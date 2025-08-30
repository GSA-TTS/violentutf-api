"""Add async task management models

Revision ID: async_task_models_001
Revises: 41eb10f48a60
Create Date: 2025-08-08 01:36:00.000000

"""

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

# revision identifiers, used by Alembic.
revision = "async_task_models_001"
down_revision = "41eb10f48a60"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Create task table
    op.create_table(
        "task",
        sa.Column("id", sa.String(255), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
        sa.Column("created_by", sa.String(255), server_default="system", nullable=False),
        sa.Column("updated_by", sa.String(255), server_default="system", nullable=False),
        sa.Column("version", sa.Integer(), server_default="1", nullable=False),
        sa.Column("is_deleted", sa.Boolean(), server_default="false", nullable=False),
        sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("deleted_by", sa.String(255), nullable=True),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("task_type", sa.String(100), nullable=False),
        sa.Column(
            "status",
            sa.Enum(
                "PENDING",
                "RUNNING",
                "COMPLETED",
                "FAILED",
                "CANCELLED",
                "RETRY",
                name="taskstatus",
            ),
            nullable=False,
        ),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column(
            "priority",
            sa.Enum("LOW", "NORMAL", "HIGH", "URGENT", name="taskpriority"),
            nullable=False,
            default="NORMAL",
        ),
        sa.Column("input_data", sa.JSON(), nullable=False, default={}),
        sa.Column("output_data", sa.JSON(), nullable=True),
        sa.Column("config", sa.JSON(), nullable=False, default={}),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("duration_seconds", sa.Integer(), nullable=True),
        sa.Column("progress", sa.Integer(), nullable=False, default=0),
        sa.Column("progress_message", sa.String(500), nullable=True),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column("error_details", sa.JSON(), nullable=True),
        sa.Column("retry_count", sa.Integer(), nullable=False, default=0),
        sa.Column("max_retries", sa.Integer(), nullable=False, default=3),
        sa.Column("celery_task_id", sa.String(255), nullable=True),
        sa.Column("webhook_url", sa.String(2048), nullable=True),
        sa.Column("webhook_secret", sa.String(255), nullable=True),
        sa.Column("webhook_called", sa.Boolean(), nullable=False, default=False),
        sa.PrimaryKeyConstraint("id"),
    )

    # Create task_result table
    op.create_table(
        "task_result",
        sa.Column("id", sa.String(255), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
        sa.Column("created_by", sa.String(255), server_default="system", nullable=False),
        sa.Column("updated_by", sa.String(255), server_default="system", nullable=False),
        sa.Column("version", sa.Integer(), server_default="1", nullable=False),
        sa.Column("is_deleted", sa.Boolean(), server_default="false", nullable=False),
        sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("deleted_by", sa.String(255), nullable=True),
        sa.Column("task_id", sa.String(255), nullable=False),
        sa.Column("result_type", sa.String(100), nullable=False),
        sa.Column("result_data", sa.JSON(), nullable=False, default={}),
        sa.Column("result_metadata", sa.JSON(), nullable=False, default={}),
        sa.Column("file_path", sa.String(1000), nullable=True),
        sa.Column("file_size", sa.Integer(), nullable=True),
        sa.Column("file_hash", sa.String(64), nullable=True),
        sa.Column("is_primary", sa.Boolean(), nullable=False, default=False),
        sa.ForeignKeyConstraint(["task_id"], ["task.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )

    # Create scan table
    op.create_table(
        "scan",
        sa.Column("id", sa.String(255), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
        sa.Column("created_by", sa.String(255), server_default="system", nullable=False),
        sa.Column("updated_by", sa.String(255), server_default="system", nullable=False),
        sa.Column("version", sa.Integer(), server_default="1", nullable=False),
        sa.Column("is_deleted", sa.Boolean(), server_default="false", nullable=False),
        sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("deleted_by", sa.String(255), nullable=True),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column(
            "scan_type",
            sa.Enum(
                "PYRIT_ORCHESTRATOR",
                "GARAK_PROBE",
                "CUSTOM_SCAN",
                "BENCHMARK_TEST",
                "ADVERSARIAL_TEST",
                name="scantype",
            ),
            nullable=False,
        ),
        sa.Column(
            "status",
            sa.Enum(
                "PENDING",
                "INITIALIZING",
                "RUNNING",
                "COMPLETED",
                "FAILED",
                "CANCELLED",
                "TIMEOUT",
                name="scanstatus",
            ),
            nullable=False,
            default="PENDING",
        ),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("target_config", sa.JSON(), nullable=False, default={}),
        sa.Column("scan_config", sa.JSON(), nullable=False, default={}),
        sa.Column("parameters", sa.JSON(), nullable=False, default={}),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("duration_seconds", sa.Integer(), nullable=True),
        sa.Column("progress", sa.Integer(), nullable=False, default=0),
        sa.Column("current_phase", sa.String(100), nullable=True),
        sa.Column("total_tests", sa.Integer(), nullable=False, default=0),
        sa.Column("completed_tests", sa.Integer(), nullable=False, default=0),
        sa.Column("failed_tests", sa.Integer(), nullable=False, default=0),
        sa.Column("findings_count", sa.Integer(), nullable=False, default=0),
        sa.Column("critical_findings", sa.Integer(), nullable=False, default=0),
        sa.Column("high_findings", sa.Integer(), nullable=False, default=0),
        sa.Column("medium_findings", sa.Integer(), nullable=False, default=0),
        sa.Column("low_findings", sa.Integer(), nullable=False, default=0),
        sa.Column("overall_score", sa.Float(), nullable=True),
        sa.Column("risk_score", sa.Float(), nullable=True),
        sa.Column("confidence_score", sa.Float(), nullable=True),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column("error_details", sa.JSON(), nullable=True),
        sa.Column("orchestrator_id", sa.String(255), nullable=True),
        sa.Column("task_id", sa.String(255), nullable=True),
        sa.Column("tags", sa.JSON(), nullable=False, default=[]),
        sa.ForeignKeyConstraint(["task_id"], ["task.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )

    # Create scan_finding table
    op.create_table(
        "scan_finding",
        sa.Column("id", sa.String(255), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
        sa.Column("created_by", sa.String(255), server_default="system", nullable=False),
        sa.Column("updated_by", sa.String(255), server_default="system", nullable=False),
        sa.Column("version", sa.Integer(), server_default="1", nullable=False),
        sa.Column("is_deleted", sa.Boolean(), server_default="false", nullable=False),
        sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("deleted_by", sa.String(255), nullable=True),
        sa.Column("scan_id", sa.String(255), nullable=False),
        sa.Column("title", sa.String(500), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column(
            "severity",
            sa.Enum("INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL", name="scanseverity"),
            nullable=False,
        ),
        sa.Column("category", sa.String(100), nullable=False),
        sa.Column("subcategory", sa.String(100), nullable=True),
        sa.Column("vulnerability_type", sa.String(100), nullable=False),
        sa.Column("affected_component", sa.String(255), nullable=True),
        sa.Column("attack_vector", sa.String(100), nullable=True),
        sa.Column("evidence", sa.JSON(), nullable=False, default={}),
        sa.Column("proof_of_concept", sa.Text(), nullable=True),
        sa.Column("cvss_score", sa.Float(), nullable=True),
        sa.Column("confidence_score", sa.Float(), nullable=False, default=0.0),
        sa.Column("impact_score", sa.Float(), nullable=True),
        sa.Column("exploitability_score", sa.Float(), nullable=True),
        sa.Column("remediation", sa.Text(), nullable=True),
        sa.Column("references", sa.JSON(), nullable=False, default=[]),
        sa.Column("status", sa.String(50), nullable=False, default="open"),
        sa.Column("false_positive", sa.Boolean(), nullable=False, default=False),
        sa.Column("verified", sa.Boolean(), nullable=False, default=False),
        sa.Column("source_test", sa.String(255), nullable=True),
        sa.Column("source_rule", sa.String(255), nullable=True),
        sa.Column("finding_metadata", sa.JSON(), nullable=False, default={}),
        sa.ForeignKeyConstraint(["scan_id"], ["scan.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )

    # Create scan_report table
    op.create_table(
        "scan_report",
        sa.Column("id", sa.String(255), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
        sa.Column("created_by", sa.String(255), server_default="system", nullable=False),
        sa.Column("updated_by", sa.String(255), server_default="system", nullable=False),
        sa.Column("version", sa.Integer(), server_default="1", nullable=False),
        sa.Column("is_deleted", sa.Boolean(), server_default="false", nullable=False),
        sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("deleted_by", sa.String(255), nullable=True),
        sa.Column("scan_id", sa.String(255), nullable=False),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("report_type", sa.String(100), nullable=False),
        sa.Column("format", sa.String(50), nullable=False),
        sa.Column("content", sa.JSON(), nullable=True),
        sa.Column("summary", sa.JSON(), nullable=False, default={}),
        sa.Column("file_path", sa.String(1000), nullable=True),
        sa.Column("file_size", sa.Integer(), nullable=True),
        sa.Column("file_hash", sa.String(64), nullable=True),
        sa.Column("template_name", sa.String(255), nullable=True),
        sa.Column("generated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("is_public", sa.Boolean(), nullable=False, default=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["scan_id"], ["scan.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )

    # Create indices for better performance
    op.create_index(op.f("ix_task_status"), "task", ["status"], unique=False)
    op.create_index(op.f("ix_task_task_type"), "task", ["task_type"], unique=False)
    op.create_index(op.f("ix_task_created_at"), "task", ["created_at"], unique=False)
    op.create_index(op.f("ix_task_priority"), "task", ["priority"], unique=False)
    op.create_index(op.f("ix_task_started_at"), "task", ["started_at"], unique=False)

    op.create_index(op.f("ix_scan_scan_type"), "scan", ["scan_type"], unique=False)
    op.create_index(op.f("ix_scan_status"), "scan", ["status"], unique=False)
    op.create_index(op.f("ix_scan_started_at"), "scan", ["started_at"], unique=False)
    op.create_index(op.f("ix_scan_findings_count"), "scan", ["findings_count"], unique=False)

    op.create_index(op.f("ix_scan_finding_severity"), "scan_finding", ["severity"], unique=False)
    op.create_index(op.f("ix_scan_finding_category"), "scan_finding", ["category"], unique=False)
    op.create_index(
        op.f("ix_scan_finding_vulnerability_type"),
        "scan_finding",
        ["vulnerability_type"],
        unique=False,
    )

    op.create_index(op.f("ix_scan_report_report_type"), "scan_report", ["report_type"], unique=False)
    op.create_index(
        op.f("ix_scan_report_generated_at"),
        "scan_report",
        ["generated_at"],
        unique=False,
    )


def downgrade() -> None:
    # Drop indices
    op.drop_index(op.f("ix_scan_report_generated_at"), table_name="scan_report")
    op.drop_index(op.f("ix_scan_report_report_type"), table_name="scan_report")
    op.drop_index(op.f("ix_scan_finding_vulnerability_type"), table_name="scan_finding")
    op.drop_index(op.f("ix_scan_finding_category"), table_name="scan_finding")
    op.drop_index(op.f("ix_scan_finding_severity"), table_name="scan_finding")
    op.drop_index(op.f("ix_scan_findings_count"), table_name="scan")
    op.drop_index(op.f("ix_scan_started_at"), table_name="scan")
    op.drop_index(op.f("ix_scan_status"), table_name="scan")
    op.drop_index(op.f("ix_scan_scan_type"), table_name="scan")
    op.drop_index(op.f("ix_task_started_at"), table_name="task")
    op.drop_index(op.f("ix_task_priority"), table_name="task")
    op.drop_index(op.f("ix_task_created_at"), table_name="task")
    op.drop_index(op.f("ix_task_task_type"), table_name="task")
    op.drop_index(op.f("ix_task_status"), table_name="task")

    # Drop tables
    op.drop_table("scan_report")
    op.drop_table("scan_finding")
    op.drop_table("scan")
    op.drop_table("task_result")
    op.drop_table("task")
