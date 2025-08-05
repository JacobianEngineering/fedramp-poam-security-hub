# AWS Security Hub to FedRAMP POAM Converter

A Python utility to automatically generate FedRAMP-compliant Plan of Action and Milestones (POAM) documents from AWS Security Hub findings.

## Overview

This tool connects to the AWS Security Hub API, retrieves active compliance findings, and formats them according to FedRAMP POAM requirements. It intelligently tracks findings over time, grouping vulnerabilities by their description and managing their lifecycle (new, active, closed). This ensures that the same vulnerability affecting multiple assets is treated as a single POAM item, and that findings are automatically closed when they are no longer detected.

## Features

- Automatic retrieval of active AWS Security Hub findings.
- **Stateful tracking of findings** between runs to manage their lifecycle.
- **Groups vulnerabilities** by normalized weakness description to consolidate POAM items.
- **Combines multiple affected assets** into a single, comma-delimited list for each POAM item.
- Automatically marks findings as "Closed" when they are no longer detected.
- Mapping of AWS security controls to NIST 800-53 controls via a configurable lookup table.
- Generation of FedRAMP-compliant POAM CSV files.
- Persistent POAM ID counter to ensure continuity.
- Configurable SLA timeframes based on finding severity.
- Detailed raw findings export for reference.

## Stateful Finding Management

A key feature of this tool is its ability to track the state of findings over time. This is accomplished using a `findings_history.json` file, which is created and updated in the project root directory.

Here's how it works:

1.  **Normalization:** On each run, the script retrieves all active findings from AWS Security Hub. It normalizes the "Weakness Description" of each finding to create a consistent identifier for the underlying vulnerability.
2.  **Reconciliation:** The script compares the current findings against the records in `findings_history.json`.
    *   **New Findings:** If a vulnerability appears that is not in the history, it is marked as "Open", assigned a new sequential POAM ID, and added to the history.
    *   **Existing Findings:** If a vulnerability from the history is still present in the current findings, its asset list is updated, and its "Status Date" is set to the current date.
    *   **Closed Findings:** If a vulnerability from the history is no longer present in the current findings, its status is changed to "Closed", and it will be removed from the next POAM generation.
3.  **State Persistence:** The updated state is saved back to `findings_history.json`, and the POAM ID counter (`poam_counter.txt`) is updated, ensuring a consistent state for the next run.

## Requirements

- Python 3.6+
- AWS CLI configured with appropriate permissions
- Required Python packages:
  - boto3
  - pyyaml
  - fuzzywuzzy

## Installation

1.  Clone this repository:
    ```
    git clone https://github.com/jacobian/aws-securityhub-fedramp-poam.git
    cd aws-securityhub-fedramp-poam
    ```

2.  Install required dependencies:
    ```
    pip install -r requirements.txt
    ```

3.  Create a `config.yaml` file based on the provided sample.

## Configuration

Create a `config.yaml` file with the following structure. Be sure to add the `history_file` key.

```yaml
# Output settings
output_dir: "./poam_output"
findings_csv: "aws_security_hub_findings.csv"
poam_csv: "fedramp_poam_items.csv"
poam_counter_file: "poam_counter.txt"
history_file: "findings_history.json" # Add this line

# AWS settings
aws:
  profile: "your-aws-profile"  # Optional, use default if not specified
  region: "us-east-1"
  max_findings: 2000

# POAM settings
poam:
  point_of_contact: "DevOps Team"
  resources_required: "Staff time for DevOps team to review and implement remediation"
  id_prefix: "C-"
  start_id: 1000  # Starting ID if no counter file exists
  default_control: "UNKNOWN"  # Default value when no mapping exists
  
  # SLA timeframes for completion based on severity
  completion_sla:
    CRITICAL: 14
    HIGH: 30
    MEDIUM: 90
    LOW: 180
  
  # Mapping of AWS Security Controls to NIST 800-53 controls
  control_mappings:
    "SSM.1": "SI-2"
    "Config.1": "CM-8"
    "IAM.1": "AC-2"
    "S3.1": "SC-8"
    "EC2.1": "SC-7"
    # Add more mappings as needed
```

## Usage

Run the script with:

```
python security-hub-poam.py
```

Optional arguments:
- `--config` - Path to the configuration file (default: `config.yaml`)
- `--profile` - AWS profile to use (overrides config)
- `--region` - AWS region to use (overrides config)
- `--output-dir` - Output directory (overrides config)

## Output

The script generates two primary files in the specified `output_dir`:

1.  `aws_security_hub_findings.csv`: A raw CSV dump of all findings retrieved during the run.
2.  `fedramp_poam_items.csv`: The final, FedRAMP-formatted POAM CSV with consolidated findings.

It also creates and maintains two state files in the project root:
- `findings_history.json`: A JSON file that stores the state of all discovered vulnerabilities.
- `poam_counter.txt`: A text file that tracks the last used POAM ID to ensure continuity.

## POAM Field Mapping

| POAM Field | Source |
|------------|--------|
| POA&M ID | Persistent, sequential ID from the counter |
| Status | "Open" or "Closed", managed by the history file |
| Controls | Mapped from AWS control to NIST 800-53 via lookup table |
| Weakness Name | Finding Title |
| Weakness Description | Finding Description |
| Weakness Detector Source | Product Name |
| Weakness Source Identifier | Original Finding ID from Security Hub |
| Asset Identifier | Comma-delimited list of affected resource ARNs |
| Point of Contact | Configured value |
| Resources Required | Configured value |
| Overall Remediation Plan | Recommendation URL |
| Original Detection Date | FirstObservedAt (from the first time the finding was seen) |
| Scheduled Completion Date | FirstObservedAt + SLA days based on severity |
| Status Date | Date the script was last run |

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## Acknowledgments

- Developed by [Jacobian Engineering](https://jacobianengineering.com)
- Based on FedRAMP POAM templates and documentation