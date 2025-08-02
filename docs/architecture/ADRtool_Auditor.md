
Historical Architectural Auditing


The Principle of Architectural Forensics: From Log to Liability


Introduction: Beyond the git log

Traditional software architecture audits are often conducted as point-in-time assessments. They provide a valuable snapshot of the system's state but frequently miss the temporal dynamics that lead to architectural decay. A Git repository, when viewed through the lens of historical analysis, transforms from a simple version control system into a rich, forensic dataset.1 It is a longitudinal record chronicling the evolution of the codebase, the decisions and compromises made by its contributors, and the recurring patterns of instability that signal underlying architectural weaknesses.2
Leveraging Git history for an architectural audit is not merely an academic exercise; it is a strategic imperative for managing complex, long-lived software systems.3 The standard
git log command, while informative, quickly becomes overwhelming as projects scale, teams expand, and branching strategies grow more intricate.1 Visualizing and programmatically analyzing this history allows audit teams to move beyond anecdotal evidence and make data-driven decisions. This approach enables the identification of development bottlenecks, improves team collaboration, and uncovers patterns of architectural violation that are invisible in a static code review.1 By treating the commit history as a primary source of evidence, organizations can proactively identify high-risk areas, plan refactoring efforts more intelligently, and foster a culture of architectural accountability.

Architectural Drift and Erosion: The Silent Accumulation of Risk

Software architecture is not a static artifact; it is in a constant state of flux. Two key phenomena describe the degradation of architecture over time: drift and erosion. Architectural Drift is the gradual, often unintentional, divergence of the implemented system from its intended design.6 This occurs as a natural consequence of the software development lifecycle, where continuous feature additions, bug fixes, and technology updates cause the
as-built architecture to deviate from the as-designed architecture.7 While some drift is inevitable, unmanaged drift leads to increased complexity, performance bottlenecks, and a growing burden of technical debt.
A more severe form of degradation is Architectural Erosion. This occurs when development practices actively violate the prescriptive architecture's core principles and constraints.8 Erosion is characterized by the breakdown of modular boundaries, the introduction of improper dependencies, and the violation of layering principles. Over time, erosion can transform a well-structured system into a monolithic, tightly coupled entity often described as a "big ball of mud," rendering it difficult to understand, maintain, and evolve.8
Both drift and erosion are primary contributors to Technical Debt, which represents the implied cost of rework caused by choosing an easy solution now instead of using a better approach that would take longer.9 Architectural violations are a particularly insidious form of technical debt because their impact is systemic. They do not just affect a single function or class; they degrade the integrity of the entire system, hindering team velocity, increasing the cognitive load on developers, and often necessitating large-scale, expensive refactoring efforts later in the project's lifecycle.8 The purpose of a historical audit is to detect the patterns of change that signal this accumulation of architectural debt before it becomes insurmountable.

Commits as Evidence: The Narrative of Architectural Decisions

Every commit in a version control system is a record of a decision. While a single commit may be insignificant, the aggregation of thousands of commits over time tells a powerful story about the health of the architecture.1 A history of frequent, small, corrective commits concentrated in a specific file or module is strong evidence of instability, complexity, or a design flaw.11 These areas, known as "hotspots," are where architectural principles are most likely under stress and where violations are most common.1
To interpret this evidence accurately, one must understand the architectural intent. This is the role of Architecture Decision Records (ADRs). An ADR is a document that captures an important architectural decision, its context, and its consequences.13 ADRs provide the "ground truth" or the architectural "law" against which the implemented system can be judged. They document the
why behind the design, including the trade-offs considered and the principles that should be upheld.13
For a historical analysis to be effective, ADRs must be treated as first-class citizens of the project, versioned alongside the code they govern. Storing ADRs within the Git repository itself, typically in a dedicated /docs/adr directory, creates an immutable, traceable link between the architectural decision and the code that implements it.14 This practice ensures that as the code evolves, the architectural documentation evolves with it, providing a stable foundation for identifying and classifying architectural violations over time.
The analysis of commit history, therefore, is not just about finding bugs but about understanding the socio-technical dynamics of the development team. Hotspots often emerge not simply because of "bad code," but because of underlying organizational issues such as knowledge silos, communication gaps between teams, or modules that have become coordination bottlenecks.12 The output of a historical analyzer should thus be viewed as a map of organizational friction points. It provides the data needed to initiate conversations in sprint retrospectives and architectural reviews, focusing not just on
that a file is problematic, but on why the team finds it so difficult to adhere to the intended architecture in that specific area. This shifts the audit from a reactive, code-focused activity to a proactive, system-level diagnostic process.

Identifying Architectural Hotspots: The Intersection of Churn and Complexity


Defining a Hotspot: More Than Just Frequent Change

To effectively focus audit efforts, it is crucial to move beyond simple metrics of change frequency. A true architectural hotspot is a component of the codebase that is not only subject to frequent modification but is also inherently complex.12 This intersection of high
code churn (a measure of volatility) and high code complexity (a measure of cognitive load) is the most reliable indicator of risk and accumulated technical debt.16
Files that change often but are simple, such as configuration files or localization resource bundles, represent high activity but low risk. Conversely, files that are highly complex but rarely change may represent stable legacy code or a core, well-understood algorithm; while they constitute a form of technical debt, they are not an immediate priority for remediation.16 The primary targets for an architectural audit are the files that reside in the dangerous quadrant of being both difficult to understand and constantly in flux. These are the parts of the system that consume a disproportionate amount of development and maintenance effort, act as magnets for bugs, and pose the highest risk of introducing regressions when modified.11 By systematically identifying these hotspots, an audit team can prioritize its resources on the small percentage of the codebase that is responsible for the majority of the architectural pain.

Measuring Code Churn: Quantifying Volatility

Code churn is a metric that quantifies how many times a file has been modified over a specific period. It is a direct indicator of a file's volatility and can be calculated by analyzing the Git repository's history. For the purpose of this audit, a six-month window is specified, which provides a relevant view of recent development activity without being overly influenced by distant legacy changes.
The churn score for each file can be computed using a combination of git log and standard shell commands. The following command will list the files in the repository that have been changed most frequently in the last six months, along with their change counts 16:

Bash


git log --format=format: --name-only --since=6.month | egrep -v '^$' | sort | uniq -c | sort -nr


A breakdown of this command reveals its logic:
git log --format=format: --name-only --since=6.month: This retrieves the commit history for the last six months, outputting only the names of the files modified in each commit.
egrep -v '^$': This filters out any blank lines from the output.
sort: This sorts the list of file paths alphabetically, which is a necessary prerequisite for the uniq command.
uniq -c: This is the core of the churn calculation. It collapses the sorted list of file paths, counting the number of occurrences of each unique path.
sort -nr: This final step sorts the result numerically (-n) and in reverse order (-r), presenting a ranked list of the most frequently changed files at the top.
This command can be further refined to exclude irrelevant files, such as documentation, test data, or build artifacts, by adding another egrep -v pipe to filter out specific file extensions or directory patterns.16 The raw output of this command provides the "Frequency" component of the risk score.

Measuring Code Complexity: Quantifying Cognitive Load

The second axis of hotspot analysis is code complexity. A complex file is one that is difficult for a developer to understand, modify, and test safely. Several metrics exist to quantify complexity, with two of the most common being:
Cyclomatic Complexity: This metric measures the number of linearly independent paths through a program's source code.18 A higher number indicates more branching logic (e.g.,
if, while, for statements), which makes the code harder to reason about and requires more test cases to achieve full path coverage.
Cognitive Complexity: This metric, often considered a successor to Cyclomatic Complexity, measures the effort required for a human to understand the control flow of the code. It penalizes structures that break the linear flow of code, such as nesting and jumps.
To obtain these metrics, the historical analyzer should integrate with a static analysis tool. Many open-source and commercial tools can provide these measurements. For a Python-based analyzer, a lightweight library like Lizard is a good option. For a more comprehensive, multi-language solution, integrating with a platform like SonarQube is recommended.16 The analyzer script would execute the chosen static analysis tool on the current version of each source file to retrieve its complexity score, which will serve as a risk multiplier in the final hotspot calculation.

Visualizing Hotspots: The Four-Quadrant Model

The most effective way to communicate the results of the churn and complexity analysis is through a two-dimensional scatter plot, often referred to as a four-quadrant model.16 In this visualization, each file in the codebase is plotted as a point, with its code churn on the x-axis and its code complexity on the y-axis. This graph clearly delineates the risk profile of the codebase:
Bottom-Left (Low Churn, Low Complexity): This is the "safe" quadrant, containing simple, stable files that require little attention.
Top-Left (Low Churn, High Complexity): This quadrant contains complex but stable code. These files may represent core business logic or legacy components that "just work." While they carry inherent risk if they ever need to be changed, they are not an immediate priority. They are candidates for documentation and knowledge sharing.
Bottom-Right (High Churn, Low Complexity): This area typically contains files like configurations, constants, or simple data transfer objects. They change frequently as part of normal development but are easy to understand and modify, posing a low risk.
Top-Right (High Churn, High Complexity): This is the "danger" quadrant. The files located here are the hotspots. They are both difficult to work with and are constantly being modified, making them the primary source of bugs, regressions, and development friction. These files are the highest priority for the architectural audit and targeted refactoring efforts.
This visualization provides an intuitive and powerful tool for communicating risk to both technical and non-technical stakeholders, making a clear, data-driven case for where to invest architectural improvement resources. Furthermore, this analysis can reveal deeper structural issues. When multiple files that are frequently committed together (a phenomenon known as "change coupling") all appear as hotspots, it often signals a violation of modularity or an improperly defined architectural boundary.12 The historical analyzer should therefore not only identify individual hotspots but also look for clusters of co-changing hotspots, as these point to systemic architectural flaws that require a more holistic remediation strategy than simply refactoring a single file.

A Semantic Framework for Classifying Architectural Violations


The Power of Convention: Adopting Conventional Commits

Identifying the location of hotspots through churn and complexity analysis is the first step. The next, more crucial step is to understand the nature of the changes occurring in those hotspots. To achieve this programmatically, the analysis requires structured, machine-readable data within the commit messages themselves. The Conventional Commits specification provides a lightweight but powerful convention for structuring commit messages that is ideal for this purpose.20
The specification proposes a simple format for the commit header:
<type>(<scope>): <description>
Each part of this structure serves a distinct analytical purpose:
<type>: A noun that describes the category of the change. Common types include feat (a new feature), fix (a bug fix), docs, style, test, and, most importantly for this analysis, refactor and chore.22 This allows the analyzer to immediately filter for commits that are likely related to architectural maintenance and violation remediation.
<scope>: An optional noun that provides contextual information about the part of the codebase affected by the change. This is the key to linking a commit to a specific architectural component or ADR. For example, a commit message like refactor(auth): remove direct db dependency from session manager explicitly tags the change as a refactoring within the "auth" domain.24
<description>: A short, imperative summary of the change.
Adopting this convention is a foundational prerequisite for an effective historical audit. The quality of the automated analysis is directly proportional to the quality and consistency of the commit messages.1 Without a structured format, parsing commit messages becomes an exercise in unreliable natural language processing. With it, commits become structured data points that can be easily queried and categorized, enabling a direct and traceable link between a code change and an architectural principle.25
This requirement for structured commits creates a beneficial socio-technical feedback loop. For the tool to function, developers must be aware of the architecture and the relevant ADRs to select the appropriate <scope>. This act of choosing a scope during the commit process reinforces architectural thinking in the daily development workflow. The tool's output—a report on which ADRs are most frequently violated—then provides feedback to the architects on which parts of the design are confusing, poorly communicated, or difficult for developers to adhere to. In this way, the analysis tool becomes not just a passive reporter of historical violations but an active catalyst for improving the team's ongoing architectural discipline.

Designing config/violation_patterns.yml

To bridge the gap between commit messages and architectural principles, a configuration file is required. The config/violation_patterns.yml file will serve as the central repository of knowledge for the analyzer, defining the patterns that signify a fix for a specific architectural violation. This file makes the analysis logic transparent, configurable, and extensible without requiring changes to the Python source code.
This YAML file should be structured around a list of ADRs. Each ADR entry will contain metadata and a set of patterns used to identify related commits. The patterns should include both the structured scope from the Conventional Commit header and a list of less-structured keywords to be searched for in the commit message body. This dual approach provides both precision (via the scope) and broader coverage (via keywords).
The following table defines a recommended schema for this configuration file. This structure is designed to be comprehensive, providing not only the patterns for matching but also metadata for reporting and a severity weight for the risk scoring model discussed in a later section.
Field Name
Data Type
Required
Description
Example Value
adrs
List[Object]
Yes
The top-level key containing a list of all ADR definitions.


adrs.id
String
Yes
A unique identifier for the Architecture Decision Record.
ADR-004
adrs.name
String
Yes
A human-readable title for the ADR.
Authentication Service Decoupling
adrs.description
String
No
A brief explanation of the architectural principle or decision.
Violations related to direct calls to the auth DB from other services.
adrs.severity_weight
Float
Yes
A numerical weight indicating the impact of violating this ADR. Used in risk scoring.
1.5
adrs.patterns
Object
Yes
A container for the patterns used to match commits to this ADR.


adrs.patterns.conventional_commit_scope
String
No
The exact scope string to match in a Conventional Commit header.
auth
adrs.patterns.keywords
List
No
A list of case-insensitive keywords to search for in the commit message body.
["fix auth leak", "decouple user service"]

This configuration file should be treated as a living document. It embodies what is known as an "architecturally-evident coding style".13 When a new ADR is ratified, part of the definition of "done" should include adding a corresponding entry to this YAML file. Changes to this file should be subject to the same code review process as any other critical project artifact, ensuring that the rules for architectural governance are themselves governed and maintained.

Linking Commits to ADRs: The Pattern Matching Logic

With the violation_patterns.yml file defined, the core logic of the historical_analyzer.py script can be implemented. The process for classifying a single commit involves the following steps:
Parse the Commit Message: The script first needs to parse the full commit message into its constituent parts: the header, body, and footer. The header must be further parsed to extract the <type>, <scope>, and <description> according to the Conventional Commits specification. A regular expression is well-suited for this task.27
Filter by Commit Type: The analysis should primarily focus on commit types that indicate corrective action, such as fix and refactor. Commits of type feat or docs are less likely to be related to architectural violation remediation and can be filtered out to reduce noise.
Iterate Through ADR Patterns: For each commit that passes the type filter, the script will iterate through the list of ADRs defined in the parsed YAML configuration.
Apply Matching Logic: For each ADR, the script applies a two-part matching rule. A commit is considered a match for a given ADR if either of the following conditions is true:
Scope Match: The <scope> extracted from the commit header is a case-insensitive match for the conventional_commit_scope defined for the ADR in the YAML file. This is the most reliable signal.
Keyword Match: If no scope match is found, the script searches the commit message body (and optionally the description from the header) for any of the keywords defined for the ADR. This provides a fallback for commits that may not have been perfectly formatted.
If a match is found, the commit is flagged as an "architectural fix" and is associated with the corresponding ADR's ID. This creates the crucial, traceable link: Commit Hash -> Violated ADR. This link forms the basis for all subsequent analysis, including hotspot identification and risk scoring.

Implementation Blueprint for the historical_analyzer.py


Choosing the Right Tool for the Job: PyDriller vs. GitPython

The core of the audit system is the Python script responsible for analyzing the Git repository. Two primary libraries are available for this task in the Python ecosystem: GitPython and PyDriller.
GitPython is a library that provides low-level, object-oriented access to Git repositories. It allows for direct manipulation of Git objects like commits, trees, and blobs, and can execute raw Git commands.28 While powerful and flexible, it requires developers to handle much of the complexity of parsing Git output and traversing the commit graph manually.30
PyDriller is a higher-level framework built on top of GitPython, specifically designed for mining software repositories.31 It abstracts away the low-level details and provides a simple, intuitive API for iterating through commits and accessing rich information about each one, including modified files, diffs, and even pre-calculated complexity metrics.33
For the task of building the historical_analyzer.py, PyDriller is the strongly recommended choice. Its high-level abstractions significantly reduce development time and complexity. Features like built-in date filtering, easy access to modified files with parsed diffs, and integrated complexity analysis directly map to the requirements of this project, allowing the developer to focus on the analysis logic rather than the intricacies of Git plumbing.31

Step 1: Setting Up the Environment and Traversing History

The first step in the script is to set up the environment, load the configuration, and initiate the traversal of the Git history. This involves importing the necessary libraries, defining the time window for the analysis, and creating the main loop that will process each commit. PyDriller's Repository class makes it straightforward to constrain the analysis to the required six-month period using the since parameter.33
A critical consideration at this stage is the performance of the analysis. Traversing the history of a large, complex codebase can be time-consuming.33 To ensure the tool is practical for regular use, particularly within a CI/CD pipeline, performance optimizations must be considered. The analysis should ideally be run as a scheduled, asynchronous job (e.g., nightly or weekly) rather than on every single commit to avoid blocking developers. Furthermore, the script should be designed to be incremental. By storing a timestamp or the hash of the last analyzed commit, subsequent runs can use PyDriller's
from_commit parameter to process only the new commits, dramatically reducing execution time.
Code Example (PyDriller):

Python


import yaml
from datetime import datetime, timedelta
from pydriller import Repository

def load_config(config_path="config/violation_patterns.yml"):
    """Loads the violation patterns from the YAML configuration file."""
    with open(config_path, 'r') as f:
        return yaml.safe_load(f)

def main():
    """Main function to run the historical analysis."""
    config = load_config()
    repo_path = "/path/to/your/repo"

    # Define the time window for the analysis (last 6 months)
    six_months_ago = datetime.now() - timedelta(days=180)

    # Initialize data structures to hold analysis results
    # e.g., violation_counts = {}

    print(f"Analyzing commits since {six_months_ago.strftime('%Y-%m-%d')}...")

    # Traverse commits within the specified time window
    for commit in Repository(repo_path, since=six_months_ago, only_no_merge=True).traverse_commits():
        # The main analysis logic will be placed inside this loop
        process_commit(commit, config)

    # Generate the final report after processing all commits
    generate_report()

if __name__ == "__main__":
    main()


The only_no_merge=True parameter is included to filter out merge commits, focusing the analysis on the atomic changes introduced by developers, which provides a cleaner signal for architectural violations.36

Step 2: Parsing Commit Messages and Identifying Architectural Fixes

Inside the main loop, each commit message must be parsed and checked against the patterns defined in the YAML configuration. This requires a robust function that can handle the Conventional Commits format. Python's re module is suitable for this task, allowing for the extraction of the type, scope, and description from the commit header.27
The logic should be resilient to minor formatting errors but strict enough to enforce the convention. Once parsed, the commit's type, scope, and body are compared against the ADR patterns loaded from the configuration file.
Code Example (Python):

Python


import re

# Regex to parse a Conventional Commit header
CONVENTIONAL_COMMIT_REGEX = re.compile(r'^(?P<type>\w+)(?:\((?P<scope>.*)\))?:\s(?P<description>.*)$')

def find_violation_in_commit(commit_msg, config):
    """
    Parses a commit message and checks if it matches any ADR violation patterns.
    Returns the ADR ID if a match is found, otherwise None.
    """
    lines = commit_msg.split('\n')
    header = lines
    body = '\n'.join(lines[1:])

    match = CONVENTIONAL_COMMIT_REGEX.match(header)
    if not match:
        return None # Not a conventional commit

    commit_details = match.groupdict()
    commit_type = commit_details.get('type', '').lower()
    commit_scope = (commit_details.get('scope') or '').lower()

    # Only analyze commits that indicate a fix or refactoring
    if commit_type not in ['fix', 'refactor', 'chore']:
        return None

    for adr in config.get('adrs',):
        patterns = adr.get('patterns', {})

        # 1. Check for a scope match (high confidence)
        if commit_scope and commit_scope == patterns.get('conventional_commit_scope', '').lower():
            return adr['id']

        # 2. Check for keyword matches in the body (lower confidence)
        for keyword in patterns.get('keywords',):
            if keyword.lower() in body.lower() or keyword.lower() in header.lower():
                return adr['id']

    return None



Step 3: Correlating Violations with Changed Files

When a commit is identified as an architectural fix, the script must associate that violation with every file modified in that commit. PyDriller makes this straightforward through the commit.modified_files attribute, which is a list of ModifiedFile objects.34
A dictionary can be used to store the violation data, mapping each file path to a nested dictionary that tracks the total violation count and a breakdown of violations by ADR type. It is crucial to handle file renames correctly to maintain an accurate historical count. The ModifiedFile object contains both old_path and new_path attributes, which can be used to track a file's identity across renames.35 A robust implementation would maintain a mapping of old paths to their new paths to consolidate counts accurately.
Code Example (Inside the process_commit function):

Python


# Assuming violation_data is a dictionary initialized in the main scope
# violation_data = {
#     "filepath": {
#         "total_violations": 0,
#         "violations_by_adr": {"ADR-001": 0,...}
#     },...
# }

def process_commit(commit, config):
    adr_id = find_violation_in_commit(commit.msg, config)
    if adr_id:
        for modified_file in commit.modified_files:
            # Use new_path if available, otherwise fall back to old_path
            filepath = modified_file.new_path or modified_file.old_path

            # Exclude non-source files if necessary
            if not filepath or not filepath.endswith(('.py', '.java', '.js')):
                continue

            # Initialize entry for the file if it's the first time seeing it
            if filepath not in violation_data:
                violation_data[filepath] = {
                    "total_violations": 0,
                    "violations_by_adr": {}
                }

            # Increment counts
            violation_data[filepath]["total_violations"] += 1
            violation_data[filepath]["violations_by_adr"].setdefault(adr_id, 0)
            violation_data[filepath]["violations_by_adr"][adr_id] += 1



Step 4: Analyzing Diff Content for Deeper Insights (Advanced)

While the primary analysis links an entire commit to all modified files, a more sophisticated approach can analyze the diff content itself to increase precision. PyDriller provides access to the raw diff via modified_file.diff and a parsed version via modified_file.diff_parsed, which separates added and deleted lines.35
This allows for advanced filtering logic. For example, if an ADR violation pertains to a specific deprecated function, the analyzer could check if the added or deleted lines in the diff actually contain calls to that function. This can help filter out "false positives" where a file was modified in an architectural fix commit, but the changes within that file were unrelated to the violation itself (e.g., fixing a typo in a comment). Implementing this requires a much deeper, language-aware parsing of the diff content and is best considered a future enhancement to the core tool. However, acknowledging this possibility demonstrates a mature understanding of the problem's complexities.

Multi-Factor Risk Scoring and Tracking Remediation Effectiveness


Beyond Simple Counts: A Multi-Factor Risk Model

A raw count of architectural violations is a useful starting point, but it is an insufficient metric for effective prioritization. A file with ten minor naming convention violations is likely less risky than a file with two critical violations of a security boundary. To create an actionable list of high-risk files, a more nuanced, multi-factor risk scoring model is required. This model should combine multiple dimensions of risk to produce a single, comparable score for each file.37
A robust risk score formula should incorporate measures of frequency, recency, severity, and complexity. The following formula provides a configurable and comprehensive model:
RiskScore(file)=(Frequency×RecencyWeight)×SeverityWeight×ComplexityScore
Each component of this formula captures a different aspect of risk:
Frequency: This is the total count of architectural fix commits associated with the file over the analysis period. It is the raw output from the analysis in the previous section and represents the likelihood of issues in the file.
Recency Weight: This is a decay factor that gives more weight to recent violations. A problem fixed last week is a stronger indicator of current risk than a problem fixed five months ago. A simple linear decay function can be used, where a violation today has a weight of 1.0 and a violation at the start of the six-month window has a weight closer to 0.
Severity Weight: This factor represents the impact of a violation. It is sourced directly from the severity_weight field in the violation_patterns.yml file. This allows architects to encode the business and technical importance of each ADR directly into the risk calculation. For example, violations of security-related ADRs would have a higher weight than violations of stylistic ADRs.
Complexity Score: This is the static complexity metric (e.g., Cyclomatic or Cognitive Complexity) of the file. It acts as a risk multiplier, reflecting the principle that making changes to a complex file is inherently riskier and more likely to introduce new defects.10
The following table summarizes the parameters of this model, providing a clear guide for its implementation and tuning.
Parameter
Description
Data Source
Example Value/Tuning
Frequency
The total number of architectural fix commits associated with the file in the analysis window.
historical_analyzer.py output (violation counts).
A raw integer, e.g., 15.
Recency Weight
A decay function applied to each violation based on its age. Gives more weight to recent violations.
Calculated from commit timestamps.
A linear decay from 1.0 (today) to 0.1 (6 months ago). The slope can be tuned to emphasize recent activity more or less strongly.
Severity Weight
A multiplier based on the importance of the violated ADR.
severity_weight field in config/violation_patterns.yml.
Security ADR: 1.5, Performance ADR: 1.2, Naming Convention ADR: 0.8. These values should be set by the architecture team based on organizational priorities.
Complexity Score
A static analysis metric representing the cognitive load of the file. Acts as a risk multiplier.
Output from a static analysis tool (e.g., Lizard, SonarQube).
Cyclomatic Complexity value. May be normalized (e.g., log-scaled) to prevent extreme values from dominating the score.

By tracking the trend of this aggregated risk score over time, either for individual files or for the entire system, the organization gains a powerful high-level metric for its architectural health. A rising trend serves as an early warning that architectural discipline may be degrading, providing a quantitative basis for intervention long before major problems manifest.

Generating the hotspot_analysis.md Report

The final output of the analyzer is the hotspot_analysis.md report. This document should be clear, concise, and actionable, designed to be consumed by developers, technical leads, and architects during sprint planning and retrospective meetings. It should contain three primary sections:
Executive Summary: A brief overview of the analysis, including the time period covered (e.g., last 180 days), the total number of commits analyzed, and the total number of architectural fixes identified.
Top 10 High-Risk Files: A ranked table listing the files with the highest risk scores. The table should be detailed, breaking down the score into its constituent parts (e.g., Violation Count, Average Severity, Complexity) to provide context for why each file is considered high-risk. This list directly fulfills the user's requirement for a "High-risk files list generated."
Violation Analysis by ADR Type: A summary table or chart that shows the distribution of violations across all identified ADRs. This section answers the question, "Which of our architectural principles are we struggling with the most?" It provides invaluable feedback to the architecture team about which designs may be unclear, difficult to implement, or ill-suited to the team's workflow.

Tracking Remediation Effectiveness: Closing the Loop

Identifying risk is only half the battle; the ultimate goal of an audit is to drive improvement. A key requirement is to track the effectiveness of remediation efforts. This transforms the audit function from a simple reporting body into a strategic partner that can demonstrate the value of investing in technical debt repayment.39
A quantitative methodology for tracking remediation effectiveness involves a three-step process:
Establish a Baseline: Before a team begins a refactoring effort on a high-risk file or module, the historical analyzer is run to capture a baseline snapshot of its key metrics. These metrics should include its Risk Score, the frequency of architectural violation commits (churn related to fixes), and its static complexity score.
Remediate: The development team performs the targeted refactoring, with the explicit goal of addressing the architectural issues identified by the audit.
Re-measure and Analyze: After a sufficient period has passed to allow new development to occur in the refactored area (e.g., 1-3 months), the analyzer is run again. The new metrics are compared to the baseline.
Success is not defined by a reduction in complexity alone. A successful refactoring makes code easier to change correctly. Therefore, the primary indicator of effectiveness is a significant and sustained decrease in the rate of new architectural violation commits for that file or module.40 If, after refactoring, the file continues to be a source of frequent architectural fixes, the remediation was likely ineffective. This data-driven feedback loop allows teams to learn from their refactoring efforts, refine their techniques, and build a powerful business case for proactive architectural maintenance by demonstrating its positive impact on future development velocity and quality.42

Operationalizing the Analysis: Integration and Ecosystem


The Tooling Landscape: Build vs. Buy

The custom historical_analyzer.py script, as outlined, provides a powerful, tailored solution for identifying architectural hotspots based on an organization's specific ADRs. However, it is important to situate this custom tool within the broader landscape of commercial and open-source software analysis platforms.
CodeScene: This is the commercial gold standard for behavioral code analysis and the primary inspiration for the methodology described in this report. CodeScene excels at hotspot analysis, visualizing technical debt, and identifying complex socio-technical patterns like team coupling and knowledge silos.12 It provides a rich, interactive user interface that goes far beyond what a custom script can offer. The custom tool can be seen as a lightweight, open-source implementation of CodeScene's core hotspot concept, offering a high degree of customizability at zero software cost.47
SonarQube and Static Analyzers: These tools are experts at analyzing a static snapshot of the code. They are indispensable for measuring complexity, detecting code smells, and identifying security vulnerabilities.18 However, they inherently lack the temporal dimension. They can tell you
what is complex, but not what is complex and also changing frequently. The historical_analyzer.py script is not a replacement for these tools; it is a complement. It uses the output of static analyzers (the complexity score) as one of its inputs to add historical context.
The decision to build a custom tool versus buying a commercial one depends on the organization's needs and resources. The custom tool offers maximum control and direct integration with the ADR process, while a tool like CodeScene provides a more comprehensive, out-of-the-box solution with advanced visualization and analysis capabilities.
Feature
Custom Tool (historical_analyzer.py)
CodeScene
SonarQube
Historical Analysis
Core feature. Analyzes churn and commit history to find hotspots.
Core feature. Advanced analysis of hotspots, change coupling, and developer patterns.
Limited. Primarily analyzes a single snapshot of the code; historical trends are a secondary feature.
ADR/Violation Categorization
Highly customizable via violation_patterns.yml. Directly links violations to specific ADRs.
General. Can identify technical debt but does not have a native, explicit concept of ADRs.
Not supported. Categorizes issues based on its own rule sets (e.g., bug, vulnerability, code smell).
Risk Scoring
Customizable multi-factor model (Frequency, Recency, Severity, Complexity).
Provides a "Code Health" metric that combines complexity and change frequency.
Provides a "Technical Debt Ratio" and maintainability ratings based on static analysis rules.
Remediation Tracking
Can be implemented via baseline/re-measure methodology.
Provides trends and goals to track improvements in Code Health over time.
Provides a "leak period" concept to track new issues introduced since a baseline.
Cost
Development and maintenance time only.
Commercial license required.
Open-source community edition is free; paid editions offer more features.
Customizability
High. The entire logic is controlled by the organization.
Medium. Configurable analysis goals and settings.
Medium. Highly extensible through plugins and custom quality profiles.


Integration Patterns for a Seamless Workflow

For the historical analysis to have a lasting impact, its findings must be integrated directly into the development workflow. The tool should not be a siloed audit function but an active participant in the team's daily processes. Several integration patterns can be employed to achieve this 50:
CI/CD Integration (Scheduled Analysis): The most common pattern is to run the historical_analyzer.py script as a scheduled job within a CI/CD platform like GitHub Actions or Jenkins.52 A weekly run is often a good cadence. The output
hotspot_analysis.md can be automatically committed back to the repository, published to a team wiki (e.g., Confluence), or sent as a summary report to a team chat channel (e.g., Slack). This ensures the latest findings are always visible and accessible.
Issue Tracker Integration (Hub-and-Spoke): To make the findings actionable, the analyzer can act as a "spoke" that feeds data into a central "hub" like Jira or GitHub Issues.53 When the analyzer identifies a new file that has crossed a high-risk threshold, it can use the issue tracker's API to automatically create a new "Technical Debt" story or ticket in the team's backlog.18 This ticket can be pre-populated with the data from the analysis report, ensuring that the hotspot is formally tracked and can be prioritized during sprint planning.
IDE Integration (Proactive Feedback): A more advanced integration involves providing feedback directly to developers within their Integrated Development Environment (IDE). The list of high-risk files can be published as a simple JSON artifact by the CI job. A lightweight IDE plugin (e.g., for VS Code or JetBrains IDEs) could then consume this JSON file and display a subtle warning or annotation when a developer opens one of the identified high-risk files. This serves as a proactive nudge, reminding the developer to proceed with extra caution, request a peer review, or consider a small refactoring as part of their current task.

Conclusion: Fostering a Culture of Architectural Accountability

The task of identifying code areas with frequent architectural violations is more than a technical challenge; it is an opportunity to cultivate a deeper culture of architectural awareness and accountability. The framework detailed in this report provides a comprehensive blueprint for moving beyond reactive, manual audits to a proactive, data-driven system of architectural governance.
The core recommendations are to:
Establish a Foundation of Convention: Adopt the Conventional Commits specification to create a machine-readable narrative of development history.
Codify Architectural Intent: Maintain Architecture Decision Records (ADRs) within the Git repository and use the violation_patterns.yml file to create a programmatic link between these decisions and the code.
Implement the Historical Analyzer: Build the proposed Python script using PyDriller to automate the detection of hotspots based on the intersection of historical churn and static complexity.
Prioritize with Data: Utilize the multi-factor risk score to focus limited refactoring resources on the areas of the codebase with the highest potential for impact.
Measure to Improve: Track the effectiveness of remediation efforts to demonstrate the value of architectural maintenance and create a continuous feedback loop.
Integrate and Automate: Weave the tool's output into the daily development workflow through CI/CD, issue trackers, and IDEs to make architectural health a visible and shared responsibility.
Ultimately, the historical_analyzer.py tool is not just an artifact for the audit team. It is a catalyst for conversation and a mirror that reflects the team's collective development habits. By making the consequences of architectural drift and erosion visible and quantifiable, it empowers the entire organization to take shared ownership of the long-term health, stability, and maintainability of its software systems.1
Works cited
Visualizing Commit History and Analyzing Project Evolution with Git - Gitready, accessed July 31, 2025, https://gitready.com/visualizing-commit-history-and-analyzing-project-evolution-with-git/
Githru: Visual Analytics for Understanding Software Development History Through Git Metadata Analysis - ResearchGate, accessed July 31, 2025, https://www.researchgate.net/publication/344160096_Githru_Visual_Analytics_for_Understanding_Software_Development_History_Through_Git_Metadata_Analysis
[2009.03115] Githru: Visual Analytics for Understanding Software Development History Through Git Metadata Analysis - arXiv, accessed July 31, 2025, https://arxiv.org/abs/2009.03115
A Behavioral Approach to Understanding the Git Experience - ScholarSpace, accessed July 31, 2025, https://scholarspace.manoa.hawaii.edu/bitstreams/c25852a0-505f-4027-87d8-da104f4147c6/download
Full article: Implementing Version Control With Git and GitHub as a Learning Objective in Statistics and Data Science Courses - Taylor & Francis Online, accessed July 31, 2025, https://www.tandfonline.com/doi/full/10.1080/10691898.2020.1848485
Navigate application architecture drift and organizational alignment - GitLab, accessed July 31, 2025, https://about.gitlab.com/blog/navigate-application-architecture-drift-and-organizational-alignment/
From Architecture Drift to Working AI | by christian crumlish | Building Piper Morgan | Jul, 2025 | Medium, accessed July 31, 2025, https://medium.com/building-piper-morgan/from-architecture-drift-to-working-ai-201f17c5cfbf
Drift and Erosion in Software Architecture: Summary and Prevention Strategies, accessed July 31, 2025, https://www.researchgate.net/publication/339385701_Drift_and_Erosion_in_Software_Architecture_Summary_and_Prevention_Strategies
What is Technical Debt? Causes, Types & Definition Guide - Sonar, accessed July 31, 2025, https://www.sonarsource.com/learn/technical-debt/
A Method to Measure and Manage Technical Debt | Konveyor, accessed July 31, 2025, https://konveyor.io/blog/2022/measure-manage-technical-debt/
Identify hotspots in your code - ADM Help Centers, accessed July 31, 2025, https://admhelp.microfocus.com/octane/en/25.1/Online/Content/UserGuide/hotspot-files-in-code.htm
Hotspots — CodeScene 1 Documentation, accessed July 31, 2025, https://codescene.io/docs/guides/technical/hotspots.html
Architecture decision record (ADR) examples for software planning, IT leadership, and template documentation - GitHub, accessed July 31, 2025, https://github.com/joelparkerhenderson/architecture-decision-record
The Importance of Architecture Decision Records (ADRs) | by David Haylock | Medium, accessed July 31, 2025, https://medium.com/@david_haylock/the-importance-of-architecture-decision-records-adrs-9225f5dd8887
Earn future maintainers esteem by writing simple ADRs | Understand Legacy Code, accessed July 31, 2025, https://understandlegacycode.com/blog/earn-maintainers-esteem-with-adrs/
Focus refactoring on what matters with Hotspots Analysis ..., accessed July 31, 2025, https://understandlegacycode.com/blog/focus-refactoring-with-hotspots-analysis/
Finding Code Hotspots in Git Repositories | MergeStat Documentation, accessed July 31, 2025, https://docs.mergestat.com/blog/2023/01/03/finding-code-hotspots-in-git-repos
How can I quantify the amount of technical debt that exists in a project?, accessed July 31, 2025, https://softwareengineering.stackexchange.com/questions/135993/how-can-i-quantify-the-amount-of-technical-debt-that-exists-in-a-project
7 Metrics for Measuring Code Quality - Codacy | Blog, accessed July 31, 2025, https://blog.codacy.com/code-quality-metrics
Conventional Commits, accessed July 31, 2025, https://www.conventionalcommits.org/en/v1.0.0/
A specification for adding human and machine readable meaning to commit messages - Conventional Commits, accessed July 31, 2025, https://www.conventionalcommits.org/en/v1.0.0-beta.2/
docs(Conventional Commits): Feat, Fix, Refactor… which is which? | by Bruno Noriller | Medium, accessed July 31, 2025, https://medium.com/@noriller/docs-conventional-commits-feat-fix-refactor-which-is-which-531614fcb65a
Semantic Commit Messages - GitHub Gist, accessed July 31, 2025, https://gist.github.com/joshbuchea/6f47e86d2510bce28f8e7f42ae84c716
Conventional Commits. To create a useful revision history… | by Tohid haghighi | Medium, accessed July 31, 2025, https://tohidhaghighi.medium.com/conventional-commits-c55d2fc5a562
Writing Good Commit Messages. At Compass, as we continually improve… | by Ben Hoyt - Medium, accessed July 31, 2025, https://medium.com/compass-true-north/writing-good-commit-messages-fc33af9d6321
michaeljones/on-commit-messages - GitHub, accessed July 31, 2025, https://github.com/michaeljones/on-commit-messages
parse-commit-message - NPM, accessed July 31, 2025, https://www.npmjs.com/package/parse-commit-message
Overview / Install — GitPython 3.1.45 documentation, accessed July 31, 2025, https://gitpython.readthedocs.io/en/stable/intro.html
GitPython is a python library used to interact with Git repositories. - GitHub, accessed July 31, 2025, https://github.com/gitpython-developers/GitPython
Extracting Diffs from Git with Python - Libelli, accessed July 31, 2025, https://bbengfort.github.io/2016/05/git-diff-extract/
Analyzing Git Repositories with PyDriller | by Felix Gutierrez | Dev Genius, accessed July 31, 2025, https://blog.devgenius.io/analyzing-git-repositories-with-pydriller-b805f2cd9db0
ishepard/pydriller: Python Framework to analyse Git repositories - GitHub, accessed July 31, 2025, https://github.com/ishepard/pydriller
Extracting git repository data with PyDriller - Matt on ML.NET - Accessible AI, accessed July 31, 2025, https://accessibleai.dev/post/extracting-git-data-pydriller/
Getting Started — PyDriller 1.0 documentation, accessed July 31, 2025, https://pydriller.readthedocs.io/en/latest/tutorial.html
ModifiedFile — PyDriller 1.0 documentation, accessed July 31, 2025, https://pydriller.readthedocs.io/en/latest/modifiedfile.html
Configuration — PyDriller 1.0 documentation, accessed July 31, 2025, https://pydriller.readthedocs.io/en/1.0/configuration.html
Risk Score - Snyk User Docs, accessed July 31, 2025, https://docs.snyk.io/manage-risk/prioritize-issues-for-fixing/risk-score
Software Risk Manager Scoring Calculations - Black Duck Documentation Portal, accessed July 31, 2025, https://documentation.blackduck.com/bundle/srm/page/install_guide/SRMConfiguration/dashboard-scoring.html
A Case Study in Locating the Architectural Roots of Technical Debt - Ran Mo, accessed July 31, 2025, https://ranmo.github.io/papers/icse2015-Seip.pdf
Transformative Impact: Observability & Software Architecture - vFunction, accessed July 31, 2025, https://vfunction.com/blog/the-transformative-influence-of-observability-on-software-architecture/
The Power of Code Refactoring: How to Measure Refactoring Success - Stepsize AI, accessed July 31, 2025, https://www.stepsize.com/blog/how-to-measure-refactoring-success
7 Effective Strategies for CTOs to Reduce Technical Debt - Revelo, accessed July 31, 2025, https://www.revelo.com/blog/reduce-technical-debt
How to measure technical debt: a step-by-step introduction - OpsLevel, accessed July 31, 2025, https://www.opslevel.com/resources/how-to-measure-technical-debt-a-step-by-step-introduction
A Longitudinal Study of Identifying and Paying Down Architectural Debt - arXiv, accessed July 31, 2025, https://arxiv.org/pdf/1811.12904
CodeScene - Wikipedia, accessed July 31, 2025, https://en.wikipedia.org/wiki/CodeScene
How CodeScene Differs From Traditional Code Analysis Tools, accessed July 31, 2025, https://codescene.com/blog/code-analysis-tool/
20 Best Code Analysis Tools in 2025 - The CTO Club, accessed July 31, 2025, https://thectoclub.com/tools/best-code-analysis-tools/
5 Tools to Measure Technical Debt [incl. Features & Drawbacks] - Brainhub, accessed July 31, 2025, https://brainhub.eu/library/tools-to-measure-technical-debt
Configuring a Project to Exclude Certain Sonar Violations | Baeldung, accessed July 31, 2025, https://www.baeldung.com/sonar-exclude-violations
Top five data integration patterns | MuleSoft, accessed July 31, 2025, https://www.mulesoft.com/resources/esb/top-five-data-integration-patterns
Enterprise Integration Patterns: Home, accessed July 31, 2025, https://www.enterpriseintegrationpatterns.com/
Integrating Static Code Analysis Toolchains - Ferhat Erata, accessed July 31, 2025, https://ferhat.ai/publication/kern-2019-integrating/kern-2019-integrating.pdf
A comprehensive guide to integration patterns in modern business systems - Lonti, accessed July 31, 2025, https://www.lonti.com/blog/a-comprehensive-guide-to-integration-patterns-in-modern-business-systems
