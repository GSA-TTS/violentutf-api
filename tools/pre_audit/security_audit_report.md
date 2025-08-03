# Security Audit Report

## Summary
- Total issues: 89
- HIGH: 4
- MEDIUM: 1
- LOW: 84


## HIGH Severity Issues

### ReDoS Risk
- **File**: /Users/tamnguyen/Documents/GitHub/violentutf-api/tools/pre_audit/git_pattern_matcher.py
- **Description**: Potential ReDoS vulnerability with pattern: (?:.*){2,}

### ReDoS Risk
- **File**: /Users/tamnguyen/Documents/GitHub/violentutf-api/tools/pre_audit/git_history_parser.py
- **Description**: Potential ReDoS vulnerability with pattern: (?:.*){2,}

### ReDoS Risk
- **File**: /Users/tamnguyen/Documents/GitHub/violentutf-api/tools/pre_audit/claude_code_auditor.py
- **Description**: Potential ReDoS vulnerability with pattern: (?:.*){2,}

### Vulnerable Dependency
- **File**: dependencies
- **Description**: gitpython 3.1.44 - CVE-2022-24439


## MEDIUM Severity Issues

### Resource Exhaustion
- **File**: /Users/tamnguyen/Documents/GitHub/violentutf-api/tools/pre_audit/claude_code_auditor.py
- **Description**: iter_commits without max_commits limit


## LOW Severity Issues

### Type Safety
- **File**: /Users/tamnguyen/Documents/GitHub/violentutf-api/tools/pre_audit/git_pattern_matcher.py
- **Description**: Function check_time_limit lacks return type annotation

### Type Safety
- **File**: /Users/tamnguyen/Documents/GitHub/violentutf-api/tools/pre_audit/git_pattern_matcher.py
- **Description**: Function check_operation_limit lacks return type annotation

### Type Safety
- **File**: /Users/tamnguyen/Documents/GitHub/violentutf-api/tools/pre_audit/git_pattern_matcher.py
- **Description**: Function regex_timeout lacks return type annotation

### Type Safety
- **File**: /Users/tamnguyen/Documents/GitHub/violentutf-api/tools/pre_audit/git_pattern_matcher.py
- **Description**: Function timeout_handler lacks return type annotation

### Resource Control
- **File**: /Users/tamnguyen/Documents/GitHub/violentutf-api/tools/pre_audit/git_pattern_matcher.py
- **Line**: 332
- **Description**: Potentially unbounded regex compilation

### Resource Control
- **File**: /Users/tamnguyen/Documents/GitHub/violentutf-api/tools/pre_audit/git_pattern_matcher.py
- **Line**: 342
- **Description**: Potentially unbounded regex compilation

### Resource Control
- **File**: /Users/tamnguyen/Documents/GitHub/violentutf-api/tools/pre_audit/git_pattern_matcher.py
- **Line**: 329
- **Description**: Potentially unbounded loop iteration

### Resource Control
- **File**: /Users/tamnguyen/Documents/GitHub/violentutf-api/tools/pre_audit/git_pattern_matcher.py
- **Line**: 365
- **Description**: Potentially unbounded loop iteration

### Resource Control
- **File**: /Users/tamnguyen/Documents/GitHub/violentutf-api/tools/pre_audit/git_pattern_matcher.py
- **Line**: 414
- **Description**: Potentially unbounded loop iteration

### Resource Control
- **File**: /Users/tamnguyen/Documents/GitHub/violentutf-api/tools/pre_audit/git_pattern_matcher.py
- **Line**: 428
- **Description**: Potentially unbounded loop iteration

### Resource Control
- **File**: /Users/tamnguyen/Documents/GitHub/violentutf-api/tools/pre_audit/git_pattern_matcher.py
- **Line**: 459
- **Description**: Potentially unbounded loop iteration

### Resource Control
- **File**: /Users/tamnguyen/Documents/GitHub/violentutf-api/tools/pre_audit/git_pattern_matcher.py
- **Line**: 465
- **Description**: Potentially unbounded loop iteration

### Resource Control
- **File**: /Users/tamnguyen/Documents/GitHub/violentutf-api/tools/pre_audit/git_pattern_matcher.py
- **Line**: 500
- **Description**: Potentially unbounded loop iteration

### Resource Control
- **File**: /Users/tamnguyen/Documents/GitHub/violentutf-api/tools/pre_audit/git_pattern_matcher.py
- **Line**: 503
- **Description**: Potentially unbounded loop iteration

### Type Safety
- **File**: /Users/tamnguyen/Documents/GitHub/violentutf-api/tools/pre_audit/git_history_parser.py
- **Description**: Function check_time_limit lacks return type annotation

### Type Safety
- **File**: /Users/tamnguyen/Documents/GitHub/violentutf-api/tools/pre_audit/git_history_parser.py
- **Description**: Function check_operation_limit lacks return type annotation

### Resource Control
- **File**: /Users/tamnguyen/Documents/GitHub/violentutf-api/tools/pre_audit/git_history_parser.py
- **Line**: 82
- **Description**: Potentially unbounded loop iteration

### Resource Control
- **File**: /Users/tamnguyen/Documents/GitHub/violentutf-api/tools/pre_audit/git_history_parser.py
- **Line**: 219
- **Description**: Potentially unbounded loop iteration

### Resource Control
- **File**: /Users/tamnguyen/Documents/GitHub/violentutf-api/tools/pre_audit/git_history_parser.py
- **Line**: 234
- **Description**: Potentially unbounded loop iteration

### Resource Control
- **File**: /Users/tamnguyen/Documents/GitHub/violentutf-api/tools/pre_audit/git_history_parser.py
- **Line**: 272
- **Description**: Potentially unbounded loop iteration

### Resource Control
- **File**: /Users/tamnguyen/Documents/GitHub/violentutf-api/tools/pre_audit/git_history_parser.py
- **Line**: 294
- **Description**: Potentially unbounded loop iteration

### Resource Control
- **File**: /Users/tamnguyen/Documents/GitHub/violentutf-api/tools/pre_audit/git_history_parser.py
- **Line**: 297
- **Description**: Potentially unbounded loop iteration

### Resource Control
- **File**: /Users/tamnguyen/Documents/GitHub/violentutf-api/tools/pre_audit/git_history_parser.py
- **Line**: 329
- **Description**: Potentially unbounded loop iteration

### Resource Control
- **File**: /Users/tamnguyen/Documents/GitHub/violentutf-api/tools/pre_audit/git_history_parser.py
- **Line**: 334
- **Description**: Potentially unbounded loop iteration

### Resource Control
- **File**: /Users/tamnguyen/Documents/GitHub/violentutf-api/tools/pre_audit/git_history_parser.py
- **Line**: 376
- **Description**: Potentially unbounded loop iteration

### Resource Control
- **File**: /Users/tamnguyen/Documents/GitHub/violentutf-api/tools/pre_audit/git_history_parser.py
- **Line**: 377
- **Description**: Potentially unbounded loop iteration

### Resource Control
- **File**: /Users/tamnguyen/Documents/GitHub/violentutf-api/tools/pre_audit/git_history_parser.py
- **Line**: 382
- **Description**: Potentially unbounded loop iteration

### Resource Control
- **File**: /Users/tamnguyen/Documents/GitHub/violentutf-api/tools/pre_audit/git_history_parser.py
- **Line**: 452
- **Description**: Potentially unbounded loop iteration

### Resource Control
- **File**: /Users/tamnguyen/Documents/GitHub/violentutf-api/tools/pre_audit/git_history_parser.py
- **Line**: 476
- **Description**: Potentially unbounded loop iteration

### Resource Control
- **File**: /Users/tamnguyen/Documents/GitHub/violentutf-api/tools/pre_audit/git_history_parser.py
- **Line**: 481
- **Description**: Potentially unbounded loop iteration

### Resource Control
- **File**: /Users/tamnguyen/Documents/GitHub/violentutf-api/tools/pre_audit/claude_code_auditor.py
- **Line**: 240
- **Description**: Potentially unbounded loop iteration

### Resource Control
- **File**: /Users/tamnguyen/Documents/GitHub/violentutf-api/tools/pre_audit/claude_code_auditor.py
- **Line**: 442
- **Description**: Potentially unbounded loop iteration

### Resource Control
- **File**: /Users/tamnguyen/Documents/GitHub/violentutf-api/tools/pre_audit/claude_code_auditor.py
- **Line**: 473
- **Description**: Potentially unbounded loop iteration

### Resource Control
- **File**: /Users/tamnguyen/Documents/GitHub/violentutf-api/tools/pre_audit/claude_code_auditor.py
- **Line**: 484
- **Description**: Potentially unbounded loop iteration

### Resource Control
- **File**: /Users/tamnguyen/Documents/GitHub/violentutf-api/tools/pre_audit/claude_code_auditor.py
- **Line**: 515
- **Description**: Potentially unbounded loop iteration

### Resource Control
- **File**: /Users/tamnguyen/Documents/GitHub/violentutf-api/tools/pre_audit/claude_code_auditor.py
- **Line**: 527
- **Description**: Potentially unbounded loop iteration

### Resource Control
- **File**: /Users/tamnguyen/Documents/GitHub/violentutf-api/tools/pre_audit/claude_code_auditor.py
- **Line**: 543
- **Description**: Potentially unbounded loop iteration

### Resource Control
- **File**: /Users/tamnguyen/Documents/GitHub/violentutf-api/tools/pre_audit/claude_code_auditor.py
- **Line**: 625
- **Description**: Potentially unbounded loop iteration

### Resource Control
- **File**: /Users/tamnguyen/Documents/GitHub/violentutf-api/tools/pre_audit/claude_code_auditor.py
- **Line**: 971
- **Description**: Potentially unbounded loop iteration

### Resource Control
- **File**: /Users/tamnguyen/Documents/GitHub/violentutf-api/tools/pre_audit/claude_code_auditor.py
- **Line**: 1027
- **Description**: Potentially unbounded loop iteration

### Resource Control
- **File**: /Users/tamnguyen/Documents/GitHub/violentutf-api/tools/pre_audit/claude_code_auditor.py
- **Line**: 1028
- **Description**: Potentially unbounded loop iteration

### Resource Control
- **File**: /Users/tamnguyen/Documents/GitHub/violentutf-api/tools/pre_audit/claude_code_auditor.py
- **Line**: 1035
- **Description**: Potentially unbounded loop iteration

### Resource Control
- **File**: /Users/tamnguyen/Documents/GitHub/violentutf-api/tools/pre_audit/claude_code_auditor.py
- **Line**: 1041
- **Description**: Potentially unbounded loop iteration

### Resource Control
- **File**: /Users/tamnguyen/Documents/GitHub/violentutf-api/tools/pre_audit/claude_code_auditor.py
- **Line**: 1045
- **Description**: Potentially unbounded loop iteration

### Resource Control
- **File**: /Users/tamnguyen/Documents/GitHub/violentutf-api/tools/pre_audit/claude_code_auditor.py
- **Line**: 1046
- **Description**: Potentially unbounded loop iteration

### Resource Control
- **File**: /Users/tamnguyen/Documents/GitHub/violentutf-api/tools/pre_audit/claude_code_auditor.py
- **Line**: 1106
- **Description**: Potentially unbounded loop iteration

### Resource Control
- **File**: /Users/tamnguyen/Documents/GitHub/violentutf-api/tools/pre_audit/claude_code_auditor.py
- **Line**: 1123
- **Description**: Potentially unbounded loop iteration

### Resource Control
- **File**: /Users/tamnguyen/Documents/GitHub/violentutf-api/tools/pre_audit/claude_code_auditor.py
- **Line**: 1136
- **Description**: Potentially unbounded loop iteration

### Resource Control
- **File**: /Users/tamnguyen/Documents/GitHub/violentutf-api/tools/pre_audit/claude_code_auditor.py
- **Line**: 1145
- **Description**: Potentially unbounded loop iteration

### Resource Control
- **File**: /Users/tamnguyen/Documents/GitHub/violentutf-api/tools/pre_audit/claude_code_auditor.py
- **Line**: 1164
- **Description**: Potentially unbounded loop iteration

### Resource Control
- **File**: /Users/tamnguyen/Documents/GitHub/violentutf-api/tools/pre_audit/claude_code_auditor.py
- **Line**: 1175
- **Description**: Potentially unbounded loop iteration

### Resource Control
- **File**: /Users/tamnguyen/Documents/GitHub/violentutf-api/tools/pre_audit/claude_code_auditor.py
- **Line**: 1187
- **Description**: Potentially unbounded loop iteration

### Resource Control
- **File**: /Users/tamnguyen/Documents/GitHub/violentutf-api/tools/pre_audit/claude_code_auditor.py
- **Line**: 1217
- **Description**: Potentially unbounded loop iteration

### Resource Control
- **File**: /Users/tamnguyen/Documents/GitHub/violentutf-api/tools/pre_audit/claude_code_auditor.py
- **Line**: 1221
- **Description**: Potentially unbounded loop iteration

### Resource Control
- **File**: /Users/tamnguyen/Documents/GitHub/violentutf-api/tools/pre_audit/claude_code_auditor.py
- **Line**: 1331
- **Description**: Potentially unbounded loop iteration

### Resource Control
- **File**: /Users/tamnguyen/Documents/GitHub/violentutf-api/tools/pre_audit/claude_code_auditor.py
- **Line**: 1336
- **Description**: Potentially unbounded loop iteration

### Resource Control
- **File**: /Users/tamnguyen/Documents/GitHub/violentutf-api/tools/pre_audit/claude_code_auditor.py
- **Line**: 1342
- **Description**: Potentially unbounded loop iteration

### Resource Control
- **File**: /Users/tamnguyen/Documents/GitHub/violentutf-api/tools/pre_audit/claude_code_auditor.py
- **Line**: 1353
- **Description**: Potentially unbounded loop iteration

### Resource Control
- **File**: /Users/tamnguyen/Documents/GitHub/violentutf-api/tools/pre_audit/claude_code_auditor.py
- **Line**: 1445
- **Description**: Potentially unbounded loop iteration

### Resource Control
- **File**: /Users/tamnguyen/Documents/GitHub/violentutf-api/tools/pre_audit/claude_code_auditor.py
- **Line**: 1459
- **Description**: Potentially unbounded loop iteration

### Resource Control
- **File**: /Users/tamnguyen/Documents/GitHub/violentutf-api/tools/pre_audit/claude_code_auditor.py
- **Line**: 1460
- **Description**: Potentially unbounded loop iteration

### Resource Control
- **File**: /Users/tamnguyen/Documents/GitHub/violentutf-api/tools/pre_audit/claude_code_auditor.py
- **Line**: 1543
- **Description**: Potentially unbounded loop iteration

### Resource Control
- **File**: /Users/tamnguyen/Documents/GitHub/violentutf-api/tools/pre_audit/claude_code_auditor.py
- **Line**: 1572
- **Description**: Potentially unbounded loop iteration

### Resource Control
- **File**: /Users/tamnguyen/Documents/GitHub/violentutf-api/tools/pre_audit/claude_code_auditor.py
- **Line**: 1641
- **Description**: Potentially unbounded loop iteration

### Resource Control
- **File**: /Users/tamnguyen/Documents/GitHub/violentutf-api/tools/pre_audit/claude_code_auditor.py
- **Line**: 1666
- **Description**: Potentially unbounded loop iteration

### Resource Control
- **File**: /Users/tamnguyen/Documents/GitHub/violentutf-api/tools/pre_audit/claude_code_auditor.py
- **Line**: 1679
- **Description**: Potentially unbounded loop iteration

### Resource Control
- **File**: /Users/tamnguyen/Documents/GitHub/violentutf-api/tools/pre_audit/claude_code_auditor.py
- **Line**: 1680
- **Description**: Potentially unbounded loop iteration

### Resource Control
- **File**: /Users/tamnguyen/Documents/GitHub/violentutf-api/tools/pre_audit/claude_code_auditor.py
- **Line**: 1703
- **Description**: Potentially unbounded loop iteration

### Resource Control
- **File**: /Users/tamnguyen/Documents/GitHub/violentutf-api/tools/pre_audit/claude_code_auditor.py
- **Line**: 1722
- **Description**: Potentially unbounded loop iteration

### Resource Control
- **File**: /Users/tamnguyen/Documents/GitHub/violentutf-api/tools/pre_audit/claude_code_auditor.py
- **Line**: 1754
- **Description**: Potentially unbounded loop iteration

### Resource Control
- **File**: /Users/tamnguyen/Documents/GitHub/violentutf-api/tools/pre_audit/claude_code_auditor.py
- **Line**: 1762
- **Description**: Potentially unbounded loop iteration

### Resource Control
- **File**: /Users/tamnguyen/Documents/GitHub/violentutf-api/tools/pre_audit/claude_code_auditor.py
- **Line**: 1766
- **Description**: Potentially unbounded loop iteration

### Resource Control
- **File**: /Users/tamnguyen/Documents/GitHub/violentutf-api/tools/pre_audit/claude_code_auditor.py
- **Line**: 1783
- **Description**: Potentially unbounded loop iteration

### Resource Control
- **File**: /Users/tamnguyen/Documents/GitHub/violentutf-api/tools/pre_audit/claude_code_auditor.py
- **Line**: 1857
- **Description**: Potentially unbounded loop iteration

### Resource Control
- **File**: /Users/tamnguyen/Documents/GitHub/violentutf-api/tools/pre_audit/claude_code_auditor.py
- **Line**: 1868
- **Description**: Potentially unbounded loop iteration

### Resource Control
- **File**: /Users/tamnguyen/Documents/GitHub/violentutf-api/tools/pre_audit/claude_code_auditor.py
- **Line**: 1904
- **Description**: Potentially unbounded loop iteration

### Resource Control
- **File**: /Users/tamnguyen/Documents/GitHub/violentutf-api/tools/pre_audit/claude_code_auditor.py
- **Line**: 1908
- **Description**: Potentially unbounded loop iteration

### Resource Control
- **File**: /Users/tamnguyen/Documents/GitHub/violentutf-api/tools/pre_audit/claude_code_auditor.py
- **Line**: 1912
- **Description**: Potentially unbounded loop iteration

### Resource Control
- **File**: /Users/tamnguyen/Documents/GitHub/violentutf-api/tools/pre_audit/claude_code_auditor.py
- **Line**: 2197
- **Description**: Potentially unbounded loop iteration

### Resource Control
- **File**: /Users/tamnguyen/Documents/GitHub/violentutf-api/tools/pre_audit/claude_code_auditor.py
- **Line**: 2407
- **Description**: Potentially unbounded loop iteration

### Resource Control
- **File**: /Users/tamnguyen/Documents/GitHub/violentutf-api/tools/pre_audit/claude_code_auditor.py
- **Line**: 2461
- **Description**: Potentially unbounded loop iteration

### Resource Control
- **File**: /Users/tamnguyen/Documents/GitHub/violentutf-api/tools/pre_audit/claude_code_auditor.py
- **Line**: 2510
- **Description**: Potentially unbounded loop iteration

### Resource Control
- **File**: /Users/tamnguyen/Documents/GitHub/violentutf-api/tools/pre_audit/claude_code_auditor.py
- **Line**: 2523
- **Description**: Potentially unbounded loop iteration

### Resource Control
- **File**: /Users/tamnguyen/Documents/GitHub/violentutf-api/tools/pre_audit/claude_code_auditor.py
- **Line**: 2612
- **Description**: Potentially unbounded loop iteration
