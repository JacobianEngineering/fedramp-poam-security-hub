# AWS Security Hub to FedRAMP POAM Converter

A Python utility to automatically generate FedRAMP-compliant Plan of Action and Milestones (POAM) documents from AWS Security Hub findings.

## Overview

This tool connects to AWS Security Hub, retrieves active compliance findings, and formats them according to FedRAMP POAM requirements. It maintains continuous POAM IDs between runs and supports mapping AWS security controls to NIST 800-53 controls.

## Features

- Automatic retrieval of active AWS Security Hub findings
- Mapping of AWS security controls to NIST 800-53 controls via configurable lookup table
- Generation of FedRAMP-compliant POAM CSV files
- Tracking of POAM IDs across multiple executions
- Configurable SLA timeframes based on finding severity
- Detailed raw findings export for reference

## Requirements

- Python 3.6+
- AWS CLI configured with appropriate permissions
- Required Python packages:
  - boto3
  - pyyaml

## Installation

1. Clone this repository:
   ```
   git clone https://github.com/jacobian/aws-securityhub-fedramp-poam.git
   cd aws-securityhub-fedramp-poam
   ```

2. Install required dependencies:
   ```
   pip install -r requirements.txt
   ```

3. Create a `config.yaml` file based on the provided sample

## Configuration

Create a `config.yaml` file with the following structure:

```yaml
# Output settings
output_dir: "./poam_output"
findings_csv: "aws_security_hub_findings.csv"
poam_csv: "fedramp_poam_items.csv"
poam_counter_file: "poam_counter.txt"

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
python aws_securityhub_to_poam.py
```

Optional arguments:
- `--config` - Path to the configuration file (default: `config.yaml`)
- `--profile` - AWS profile to use (overrides config)
- `--region` - AWS region to use (overrides config)
- `--output-dir` - Output directory (overrides config)

## Output

The script generates two files:

1. A raw findings CSV containing all data from Security Hub
2. A FedRAMP-formatted POAM CSV with properly mapped controls and calculations

It also maintains a counter file to ensure POAM IDs are continuous between runs.

## POAM Field Mapping

| POAM Field | Source |
|------------|--------|
| POA&M ID | Sequential ID with configurable prefix |
| Controls | Mapped from AWS control to NIST 800-53 via lookup table |
| Weakness Name | Finding Title |
| Weakness Description | Finding Description |
| Weakness Detector Source | Product Name |
| Weakness Source Identifier | Finding ID |
| Asset Identifier | Truncated Finding ID |
| Point of Contact | Configured value |
| Resources Required | Configured value |
| Overall Remediation Plan | Recommendation URL |
| Original Detection Date | FirstObservedAt |
| Scheduled Completion Date | FirstObservedAt + SLA days based on severity |
| Status Date | Date script was run |

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## Acknowledgments

- Developed by [Jacobian Engineering](https://jacobianengineering.com)
- Based on FedRAMP POAM templates and documentation
