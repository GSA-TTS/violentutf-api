#!/usr/bin/env python3
"""
Index Analysis and Optimization Script for Issue #123 - Phase 5 Database Monitoring.

This script provides automated index analysis for missing index detection,
unused index identification, and index optimization recommendations.

Features:
- Missing index detection based on query patterns
- Unused index identification
- Index bloat analysis
- Index optimization recommendations
- Index usage statistics collection
"""

import asyncio
import json
import os
import sys
from collections import defaultdict
from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional, Set, Tuple

# Add the app directory to the Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import argparse

from sqlalchemy import MetaData, inspect, text
from sqlalchemy.ext.asyncio import AsyncSession
from structlog.stdlib import get_logger

from app.db.base_class import Base
from app.db.session import get_db

logger = get_logger(__name__)


@dataclass
class IndexAnalysisResult:
    """Results from index analysis."""

    table_name: str
    index_name: str
    index_type: str
    columns: List[str]
    is_unique: bool
    size_mb: Optional[float] = None
    usage_count: Optional[int] = None
    last_used: Optional[datetime] = None
    effectiveness_score: Optional[float] = None
    recommendations: List[str] = field(default_factory=list)


@dataclass
class MissingIndexRecommendation:
    """Recommendation for a missing index."""

    table_name: str
    recommended_columns: List[str]
    query_patterns: List[str]
    estimated_benefit: str
    priority: str  # high, medium, low
    reasoning: str


@dataclass
class IndexOptimizationSummary:
    """Summary of index optimization analysis."""

    total_indexes: int
    unused_indexes: int
    missing_indexes: int
    bloated_indexes: int
    optimization_potential_mb: float
    recommendations: List[str]


class IndexAnalyzer:
    """
    Advanced index analyzer for database optimization.

    Provides comprehensive analysis of database indexes including usage patterns,
    missing index detection, and optimization recommendations.
    """

    def __init__(self, session: AsyncSession):
        """Initialize the index analyzer."""
        self.session = session
        self.metadata = MetaData()
        self.db_type = self._detect_database_type()

    def _detect_database_type(self) -> str:
        """
        Detect the database type for appropriate index analysis.

        Returns:
            Database type identifier
        """
        # In a real implementation, this would detect the actual database type
        # For now, assume PostgreSQL as it's commonly used
        return "postgresql"

    async def analyze_all_indexes(self) -> List[IndexAnalysisResult]:
        """
        Analyze all indexes in the database.

        Returns:
            List of index analysis results
        """
        logger.info("Starting comprehensive index analysis")

        indexes = []

        try:
            # Get all tables from SQLAlchemy models
            tables = await self._get_all_tables()

            for table_name in tables:
                table_indexes = await self._analyze_table_indexes(table_name)
                indexes.extend(table_indexes)

            logger.info("Index analysis completed", total_indexes=len(indexes))

        except Exception as e:
            logger.error("Failed to analyze indexes", error=str(e))
            raise

        return indexes

    async def _get_all_tables(self) -> List[str]:
        """
        Get all table names from the database.

        Returns:
            List of table names
        """
        # Get table names from SQLAlchemy Base registry
        table_names = []

        for model in Base.registry._class_registry.values():
            if hasattr(model, "__tablename__"):
                table_names.append(model.__tablename__)

        # Also query database for additional tables
        try:
            if self.db_type == "postgresql":
                result = await self.session.execute(
                    text(
                        """
                    SELECT tablename
                    FROM pg_tables
                    WHERE schemaname = 'public'
                """
                    )
                )
                db_tables = [row[0] for row in result.fetchall()]
                table_names.extend(db_tables)

            # Remove duplicates
            table_names = list(set(table_names))

        except Exception as e:
            logger.warning("Failed to query database tables", error=str(e))

        return table_names

    async def _analyze_table_indexes(self, table_name: str) -> List[IndexAnalysisResult]:
        """
        Analyze indexes for a specific table.

        Args:
            table_name: Name of the table to analyze

        Returns:
            List of index analysis results for the table
        """
        indexes = []

        try:
            if self.db_type == "postgresql":
                # Query PostgreSQL system catalogs for index information
                result = await self.session.execute(
                    text(
                        """
                    SELECT
                        i.indexname,
                        i.indexdef,
                        ix.indisunique,
                        array_agg(a.attname ORDER BY a.attnum) as columns,
                        pg_size_pretty(pg_relation_size(ix.indexrelid)) as size,
                        pg_relation_size(ix.indexrelid) as size_bytes
                    FROM pg_indexes i
                    JOIN pg_class ic ON ic.relname = i.indexname
                    JOIN pg_index ix ON ix.indexrelid = ic.oid
                    JOIN pg_attribute a ON a.attrelid = ix.indrelid
                        AND a.attnum = ANY(ix.indkey)
                    WHERE i.tablename = :table_name
                    GROUP BY i.indexname, i.indexdef, ix.indisunique, ix.indexrelid
                """
                    ),
                    {"table_name": table_name},
                )

                for row in result.fetchall():
                    index_name = row[0]
                    index_def = row[1]
                    is_unique = row[2]
                    columns = row[3] if row[3] else []
                    size_bytes = row[5]

                    # Convert size to MB
                    size_mb = size_bytes / (1024 * 1024) if size_bytes else None

                    # Get index usage statistics
                    usage_stats = await self._get_index_usage_stats(table_name, index_name)

                    # Determine index type
                    index_type = self._determine_index_type(index_def)

                    # Calculate effectiveness score
                    effectiveness_score = self._calculate_effectiveness_score(usage_stats, size_mb, len(columns))

                    # Generate recommendations
                    recommendations = self._generate_index_recommendations(
                        table_name, index_name, usage_stats, effectiveness_score, is_unique
                    )

                    indexes.append(
                        IndexAnalysisResult(
                            table_name=table_name,
                            index_name=index_name,
                            index_type=index_type,
                            columns=columns,
                            is_unique=is_unique,
                            size_mb=size_mb,
                            usage_count=usage_stats.get("usage_count"),
                            last_used=usage_stats.get("last_used"),
                            effectiveness_score=effectiveness_score,
                            recommendations=recommendations,
                        )
                    )

        except Exception as e:
            logger.warning("Failed to analyze table indexes", table=table_name, error=str(e))

        return indexes

    async def _get_index_usage_stats(self, table_name: str, index_name: str) -> Dict[str, Any]:
        """
        Get usage statistics for an index.

        Args:
            table_name: Table name
            index_name: Index name

        Returns:
            Dictionary with usage statistics
        """
        usage_stats = {}

        try:
            if self.db_type == "postgresql":
                # Query PostgreSQL statistics for index usage
                result = await self.session.execute(
                    text(
                        """
                    SELECT
                        idx_tup_read,
                        idx_tup_fetch,
                        idx_scan
                    FROM pg_stat_user_indexes
                    WHERE indexrelname = :index_name
                """
                    ),
                    {"index_name": index_name},
                )

                row = result.fetchone()
                if row:
                    usage_stats = {
                        "tuples_read": row[0],
                        "tuples_fetched": row[1],
                        "usage_count": row[2],
                        "last_used": None,  # PostgreSQL doesn't track last usage time by default
                    }

        except Exception as e:
            logger.warning("Failed to get index usage stats", index=index_name, error=str(e))

        return usage_stats

    def _determine_index_type(self, index_def: str) -> str:
        """
        Determine the type of index from its definition.

        Args:
            index_def: Index definition string

        Returns:
            Index type identifier
        """
        if not index_def:
            return "unknown"

        index_def_lower = index_def.lower()

        if "unique" in index_def_lower:
            return "unique"
        elif "btree" in index_def_lower:
            return "btree"
        elif "hash" in index_def_lower:
            return "hash"
        elif "gin" in index_def_lower:
            return "gin"
        elif "gist" in index_def_lower:
            return "gist"
        else:
            return "btree"  # Default assumption

    def _calculate_effectiveness_score(
        self, usage_stats: Dict[str, Any], size_mb: Optional[float], column_count: int
    ) -> float:
        """
        Calculate an effectiveness score for an index.

        Args:
            usage_stats: Index usage statistics
            size_mb: Index size in MB
            column_count: Number of columns in the index

        Returns:
            Effectiveness score (0.0 to 1.0)
        """
        score = 0.0

        # Usage-based scoring
        usage_count = usage_stats.get("usage_count", 0)
        if usage_count > 1000:
            score += 0.4
        elif usage_count > 100:
            score += 0.3
        elif usage_count > 10:
            score += 0.2
        elif usage_count > 0:
            score += 0.1

        # Size efficiency scoring
        if size_mb:
            if size_mb < 1:  # Small indexes are generally good
                score += 0.2
            elif size_mb < 10:
                score += 0.1
            # Large indexes without high usage get penalized
            elif size_mb > 100 and usage_count < 100:
                score -= 0.1

        # Column count scoring (fewer columns generally better for performance)
        if column_count == 1:
            score += 0.2
        elif column_count <= 3:
            score += 0.1
        elif column_count > 5:
            score -= 0.1

        # Ensure score is between 0 and 1
        return max(0.0, min(1.0, score))

    def _generate_index_recommendations(
        self, table_name: str, index_name: str, usage_stats: Dict[str, Any], effectiveness_score: float, is_unique: bool
    ) -> List[str]:
        """
        Generate optimization recommendations for an index.

        Args:
            table_name: Table name
            index_name: Index name
            usage_stats: Usage statistics
            effectiveness_score: Calculated effectiveness score
            is_unique: Whether the index enforces uniqueness

        Returns:
            List of recommendations
        """
        recommendations = []

        usage_count = usage_stats.get("usage_count", 0)

        # Low usage recommendations
        if usage_count == 0:
            if not is_unique and not index_name.endswith("_pkey"):
                recommendations.append("Consider dropping - index is never used")
            else:
                recommendations.append("Monitor usage - unique constraint may still be needed")
        elif usage_count < 10:
            recommendations.append("Low usage detected - verify index necessity")

        # Effectiveness recommendations
        if effectiveness_score < 0.3:
            recommendations.append("Low effectiveness score - review index design")
        elif effectiveness_score > 0.8:
            recommendations.append("High-performing index - maintain current configuration")

        # General recommendations
        if not recommendations:
            recommendations.append("Index appears to be properly utilized")

        return recommendations

    async def find_missing_indexes(self) -> List[MissingIndexRecommendation]:
        """
        Identify potentially missing indexes based on common query patterns.

        Returns:
            List of missing index recommendations
        """
        logger.info("Analyzing for missing indexes")

        recommendations = []

        try:
            # Get all tables
            tables = await self._get_all_tables()

            for table_name in tables:
                table_recommendations = await self._analyze_table_for_missing_indexes(table_name)
                recommendations.extend(table_recommendations)

        except Exception as e:
            logger.error("Failed to analyze missing indexes", error=str(e))

        return recommendations

    async def _analyze_table_for_missing_indexes(self, table_name: str) -> List[MissingIndexRecommendation]:
        """
        Analyze a table for missing indexes.

        Args:
            table_name: Table name to analyze

        Returns:
            List of missing index recommendations for the table
        """
        recommendations = []

        try:
            # Get existing indexes
            existing_indexes = await self._get_existing_index_columns(table_name)

            # Get table columns
            table_columns = await self._get_table_columns(table_name)

            # Common patterns to check for missing indexes
            missing_index_patterns = [
                # Foreign key columns
                ("Foreign key optimization", ["id"], "high"),
                ("Organization filtering", ["organization_id"], "high"),
                ("Timestamp queries", ["created_at"], "medium"),
                ("Timestamp queries", ["updated_at"], "medium"),
                ("Status filtering", ["status"], "medium"),
                ("User queries", ["user_id"], "high"),
                ("Type filtering", ["type"], "low"),
                ("Name searches", ["name"], "medium"),
                ("Email lookups", ["email"], "high"),
                ("Active record filtering", ["is_active"], "medium"),
                ("Soft delete filtering", ["is_deleted"], "medium"),
            ]

            for pattern_name, columns, priority in missing_index_patterns:
                # Check if all columns exist in the table
                if all(col in table_columns for col in columns):
                    # Check if an index already exists
                    if not self._index_exists_for_columns(existing_indexes, columns):
                        recommendations.append(
                            MissingIndexRecommendation(
                                table_name=table_name,
                                recommended_columns=columns,
                                query_patterns=[f"{table_name} queries filtering by {', '.join(columns)}"],
                                estimated_benefit=f"Improved {pattern_name.lower()} performance",
                                priority=priority,
                                reasoning=f"No index found for common {pattern_name.lower()} pattern",
                            )
                        )

            # Check for composite index opportunities
            composite_recommendations = self._analyze_composite_index_opportunities(
                table_name, table_columns, existing_indexes
            )
            recommendations.extend(composite_recommendations)

        except Exception as e:
            logger.warning("Failed to analyze table for missing indexes", table=table_name, error=str(e))

        return recommendations

    async def _get_existing_index_columns(self, table_name: str) -> List[List[str]]:
        """
        Get columns for existing indexes on a table.

        Args:
            table_name: Table name

        Returns:
            List of column lists for each index
        """
        existing_indexes = []

        try:
            if self.db_type == "postgresql":
                result = await self.session.execute(
                    text(
                        """
                    SELECT array_agg(a.attname ORDER BY a.attnum) as columns
                    FROM pg_indexes i
                    JOIN pg_class ic ON ic.relname = i.indexname
                    JOIN pg_index ix ON ix.indexrelid = ic.oid
                    JOIN pg_attribute a ON a.attrelid = ix.indrelid
                        AND a.attnum = ANY(ix.indkey)
                    WHERE i.tablename = :table_name
                    GROUP BY i.indexname
                """
                    ),
                    {"table_name": table_name},
                )

                for row in result.fetchall():
                    if row[0]:
                        existing_indexes.append(row[0])

        except Exception as e:
            logger.warning("Failed to get existing index columns", table=table_name, error=str(e))

        return existing_indexes

    async def _get_table_columns(self, table_name: str) -> List[str]:
        """
        Get all columns for a table.

        Args:
            table_name: Table name

        Returns:
            List of column names
        """
        columns = []

        try:
            if self.db_type == "postgresql":
                result = await self.session.execute(
                    text(
                        """
                    SELECT column_name
                    FROM information_schema.columns
                    WHERE table_name = :table_name
                    AND table_schema = 'public'
                """
                    ),
                    {"table_name": table_name},
                )

                columns = [row[0] for row in result.fetchall()]

        except Exception as e:
            logger.warning("Failed to get table columns", table=table_name, error=str(e))

        return columns

    def _index_exists_for_columns(self, existing_indexes: List[List[str]], columns: List[str]) -> bool:
        """
        Check if an index exists for the specified columns.

        Args:
            existing_indexes: List of existing index column combinations
            columns: Columns to check for

        Returns:
            True if an appropriate index exists
        """
        for existing_columns in existing_indexes:
            # Check if the columns are covered by an existing index
            # Either exact match or the required columns are a prefix of an existing index
            if columns == existing_columns[: len(columns)] or set(columns).issubset(set(existing_columns)):
                return True
        return False

    def _analyze_composite_index_opportunities(
        self, table_name: str, table_columns: List[str], existing_indexes: List[List[str]]
    ) -> List[MissingIndexRecommendation]:
        """
        Analyze opportunities for composite indexes.

        Args:
            table_name: Table name
            table_columns: Available table columns
            existing_indexes: Existing index configurations

        Returns:
            List of composite index recommendations
        """
        recommendations = []

        # Common composite index patterns
        composite_patterns = [
            # Filtering + sorting patterns
            (["organization_id", "created_at"], "Organization filtering with timestamp sorting"),
            (["user_id", "status"], "User-specific status filtering"),
            (["type", "created_at"], "Type filtering with timestamp sorting"),
            (["is_deleted", "updated_at"], "Active records with update time sorting"),
            (["status", "priority"], "Status and priority filtering"),
        ]

        for columns, description in composite_patterns:
            if all(col in table_columns for col in columns):
                if not self._index_exists_for_columns(existing_indexes, columns):
                    recommendations.append(
                        MissingIndexRecommendation(
                            table_name=table_name,
                            recommended_columns=columns,
                            query_patterns=[f"{table_name} queries with {description.lower()}"],
                            estimated_benefit=f"Optimized {description.lower()}",
                            priority="medium",
                            reasoning=f"Composite index opportunity for {description.lower()}",
                        )
                    )

        return recommendations

    async def generate_optimization_summary(self) -> IndexOptimizationSummary:
        """
        Generate a comprehensive index optimization summary.

        Returns:
            Index optimization summary
        """
        logger.info("Generating index optimization summary")

        # Analyze all indexes
        all_indexes = await self.analyze_all_indexes()

        # Find missing indexes
        missing_indexes = await self.find_missing_indexes()

        # Calculate metrics
        total_indexes = len(all_indexes)
        unused_indexes = len([idx for idx in all_indexes if idx.usage_count == 0])
        bloated_indexes = len([idx for idx in all_indexes if idx.size_mb and idx.size_mb > 100])

        # Calculate optimization potential
        optimization_potential_mb = (
            sum(
                idx.size_mb
                for idx in all_indexes
                if idx.size_mb is not None
                and (idx.usage_count == 0 or (idx.effectiveness_score is not None and idx.effectiveness_score < 0.3))
            )
            or 0.0
        )

        # Generate high-level recommendations
        recommendations = self._generate_optimization_recommendations(
            all_indexes, missing_indexes, unused_indexes, bloated_indexes
        )

        return IndexOptimizationSummary(
            total_indexes=total_indexes,
            unused_indexes=unused_indexes,
            missing_indexes=len(missing_indexes),
            bloated_indexes=bloated_indexes,
            optimization_potential_mb=optimization_potential_mb,
            recommendations=recommendations,
        )

    def _generate_optimization_recommendations(
        self,
        all_indexes: List[IndexAnalysisResult],
        missing_indexes: List[MissingIndexRecommendation],
        unused_count: int,
        bloated_count: int,
    ) -> List[str]:
        """
        Generate high-level optimization recommendations.

        Args:
            all_indexes: All analyzed indexes
            missing_indexes: Missing index recommendations
            unused_count: Number of unused indexes
            bloated_count: Number of bloated indexes

        Returns:
            List of optimization recommendations
        """
        recommendations = []

        if unused_count > 0:
            recommendations.append(f"Consider removing {unused_count} unused indexes to improve write performance")

        if len(missing_indexes) > 0:
            high_priority = len([idx for idx in missing_indexes if idx.priority == "high"])
            if high_priority > 0:
                recommendations.append(
                    f"Implement {high_priority} high-priority missing indexes for significant performance gains"
                )

        if bloated_count > 0:
            recommendations.append(f"Review {bloated_count} large indexes for potential optimization")

        # Overall recommendations
        recommendations.extend(
            [
                "Regularly monitor index usage statistics to identify optimization opportunities",
                "Consider implementing partial indexes for filtered queries",
                "Review composite index opportunities for multi-column filtering",
                "Monitor index maintenance overhead impact on write operations",
            ]
        )

        return recommendations

    async def generate_comprehensive_report(self, output_file: Optional[str] = None) -> Dict[str, Any]:
        """
        Generate a comprehensive index analysis report.

        Args:
            output_file: Optional file to save the report

        Returns:
            Comprehensive index analysis report
        """
        logger.info("Generating comprehensive index analysis report")

        # Perform all analyses
        all_indexes = await self.analyze_all_indexes()
        missing_indexes = await self.find_missing_indexes()
        optimization_summary = await self.generate_optimization_summary()

        report = {
            "generated_at": datetime.now().isoformat(),
            "database_type": self.db_type,
            "optimization_summary": asdict(optimization_summary),
            "index_analysis": [asdict(idx) for idx in all_indexes],
            "missing_index_recommendations": [asdict(idx) for idx in missing_indexes],
            "high_priority_actions": self._get_high_priority_actions(all_indexes, missing_indexes),
        }

        # Save to file if specified
        if output_file:
            with open(output_file, "w") as f:
                json.dump(report, f, indent=2, default=str)
            logger.info("Index analysis report saved", output_file=output_file)

        return report

    def _get_high_priority_actions(
        self, all_indexes: List[IndexAnalysisResult], missing_indexes: List[MissingIndexRecommendation]
    ) -> List[str]:
        """
        Get high-priority optimization actions.

        Args:
            all_indexes: All analyzed indexes
            missing_indexes: Missing index recommendations

        Returns:
            List of high-priority actions
        """
        actions = []

        # Unused indexes that can be dropped
        unused_indexes = [idx for idx in all_indexes if idx.usage_count == 0 and not idx.is_unique]
        if unused_indexes:
            actions.append(
                f"DROP {len(unused_indexes)} unused indexes: {', '.join([idx.index_name for idx in unused_indexes[:3]])}{'...' if len(unused_indexes) > 3 else ''}"
            )

        # High-priority missing indexes
        high_priority_missing = [idx for idx in missing_indexes if idx.priority == "high"]
        for missing in high_priority_missing[:3]:  # Top 3
            actions.append(
                f"CREATE INDEX on {missing.table_name}({', '.join(missing.recommended_columns)}) - {missing.reasoning}"
            )

        # Large ineffective indexes
        large_ineffective = [
            idx
            for idx in all_indexes
            if idx.size_mb and idx.size_mb > 50 and idx.effectiveness_score and idx.effectiveness_score < 0.3
        ]
        if large_ineffective:
            actions.append(f"Review {len(large_ineffective)} large but ineffective indexes")

        return actions


async def main() -> None:
    """Main entry point for the index analyzer script."""
    parser = argparse.ArgumentParser(description="Database Index Analyzer")
    parser.add_argument("--output", type=str, help="Output file for the report")
    parser.add_argument("--missing-only", action="store_true", help="Only analyze missing indexes")
    parser.add_argument("--usage-only", action="store_true", help="Only analyze index usage")

    args = parser.parse_args()

    logger.info("Starting index analyzer", args=vars(args))

    try:
        # Get database session
        async with get_db() as session:
            analyzer = IndexAnalyzer(session)

            if args.missing_only:
                missing_indexes = await analyzer.find_missing_indexes()
                print(f"Found {len(missing_indexes)} missing index recommendations")
                for rec in missing_indexes:
                    print(
                        f"  {rec.priority.upper()}: {rec.table_name}({', '.join(rec.recommended_columns)}) - {rec.reasoning}"
                    )

            elif args.usage_only:
                all_indexes = await analyzer.analyze_all_indexes()
                unused = [idx for idx in all_indexes if idx.usage_count == 0]
                print(f"Found {len(unused)} unused indexes")
                for idx in unused:
                    print(f"  {idx.table_name}.{idx.index_name} - Size: {idx.size_mb:.2f}MB")

            else:
                # Generate comprehensive report
                report = await analyzer.generate_comprehensive_report(args.output)

                summary = report["optimization_summary"]

                print("\n=== Index Analysis Report ===")
                print(f"Analysis completed at: {report['generated_at']}")
                print(f"Database type: {report['database_type']}")
                print(f"Total indexes analyzed: {summary['total_indexes']}")
                print(f"Unused indexes found: {summary['unused_indexes']}")
                print(f"Missing indexes identified: {summary['missing_indexes']}")
                print(f"Bloated indexes detected: {summary['bloated_indexes']}")
                print(f"Optimization potential: {summary['optimization_potential_mb']:.1f} MB")

                if report["high_priority_actions"]:
                    print("\n=== High Priority Actions ===")
                    for i, action in enumerate(report["high_priority_actions"], 1):
                        print(f"{i}. {action}")

                print("\n=== Optimization Recommendations ===")
                for i, rec in enumerate(summary["recommendations"], 1):
                    print(f"{i}. {rec}")

                if args.output:
                    print(f"\nDetailed report saved to: {args.output}")

    except Exception as e:
        logger.error("Index analyzer failed", error=str(e), exception_type=type(e).__name__)
        raise


if __name__ == "__main__":
    asyncio.run(main())
