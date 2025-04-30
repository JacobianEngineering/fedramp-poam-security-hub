import boto3
import json
import csv
import datetime
import argparse
import os
import yaml
from datetime import datetime, timedelta

# Default configuration - Can be overridden with a config file
DEFAULT_CONFIG = {
    "output_dir": ".",
    "findings_csv": "security_hub_findings.csv",
    "poam_csv": "fedramp_poam.csv",
    "aws": {
        "profile": None,
        "region": "us-east-1",
        "max_findings": 1000
    },
    "poam": {
        "point_of_contact": "Security Team",
        "resources_required": "Staff time for DevOps team to review and implement remediation",
        "completion_sla": {
            "CRITICAL": 14,
            "HIGH": 30,
            "MEDIUM": 90,
            "LOW": 180
        },
        "id_prefix": "C-"
    }
}

def parse_args():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(description='Export AWS Security Hub findings to FedRAMP POAM format')
    parser.add_argument('--config', help='Path to YAML config file', default=None)
    parser.add_argument('--profile', help='AWS profile name', default=None)
    parser.add_argument('--region', help='AWS region', default=None)
    parser.add_argument('--output-dir', help='Output directory for CSV files', default=None)
    return parser.parse_args()

def load_config(args):
    """Load configuration from file and/or command line arguments"""
    config = DEFAULT_CONFIG.copy()
    
    # Load config from file if specified
    if args.config and os.path.exists(args.config):
        try:
            with open(args.config, 'r') as config_file:
                file_config = yaml.safe_load(config_file)
                # Deep merge config
                for section in file_config:
                    if isinstance(file_config[section], dict) and section in config:
                        config[section].update(file_config[section])
                    else:
                        config[section] = file_config[section]
        except Exception as e:
            print(f"Error loading config file: {e}")
    
    # Override with command line arguments if provided
    if args.profile:
        config["aws"]["profile"] = args.profile
    if args.region:
        config["aws"]["region"] = args.region
    if args.output_dir:
        config["output_dir"] = args.output_dir
        
    return config

def get_security_hub_findings(config):
    """Query Security Hub API for active findings"""
    session = boto3.Session(
        profile_name=config["aws"]["profile"], 
        region_name=config["aws"]["region"]
    )
    securityhub = session.client('securityhub')
    
    # Filter for active findings with compliance failures
    filters = {
        'RecordState': [{'Value': 'ACTIVE', 'Comparison': 'EQUALS'}],
        'ComplianceStatus': [{'Value': 'FAILED', 'Comparison': 'EQUALS'}]
    }
    
    all_findings = []
    next_token = None
    
    # Handle pagination
    while True:
        if next_token:
            response = securityhub.get_findings(
                Filters=filters, 
                NextToken=next_token, 
                MaxResults=100
            )
        else:
            response = securityhub.get_findings(
                Filters=filters, 
                MaxResults=100
            )
        
        all_findings.extend(response['Findings'])
        
        if 'NextToken' in response and len(all_findings) < config["aws"]["max_findings"]:
            next_token = response['NextToken']
        else:
            break
            
        if len(all_findings) >= config["aws"]["max_findings"]:
            print(f"Reached maximum findings limit of {config['aws']['max_findings']}")
            break
    
    print(f"Retrieved {len(all_findings)} findings from Security Hub")
    return all_findings

def flatten_findings_to_csv(findings, output_path):
    """Flatten the findings JSON and write to CSV"""
    if not findings:
        print("No findings to export")
        return
    
    # Identify key fields to extract
    key_fields = [
        'Id', 'ProductArn', 'ProductName', 'CompanyName', 
        'Title', 'Description', 'GeneratorId', 'AwsAccountId',
        'Types', 'FirstObservedAt', 'LastObservedAt', 'CreatedAt', 'UpdatedAt',
        'RecordState'
    ]
    
    # Create flattened fieldnames
    fieldnames = key_fields.copy()
    
    # Add nested fields we want to extract
    fieldnames.extend([
        'SeverityLabel', 'SeverityProduct', 
        'ResourceId', 'ResourceType',
        'ComplianceStatus', 'SecurityControlId', 'RecommendationUrl'
    ])
    
    # Ensure output directory exists
    os.makedirs(os.path.dirname(output_path) if os.path.dirname(output_path) else '.', exist_ok=True)
    
    with open(output_path, 'w', newline='') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        
        for finding in findings:
            # Create a flattened row
            row = {}
            
            # Extract top-level fields
            for field in key_fields:
                if field in finding:
                    if isinstance(finding[field], (dict, list)):
                        row[field] = json.dumps(finding[field])
                    else:
                        row[field] = finding[field]
                else:
                    row[field] = ""
            
            # Extract nested fields
            if 'Severity' in finding:
                row['SeverityLabel'] = finding['Severity'].get('Label', '')
                row['SeverityProduct'] = finding['Severity'].get('Product', '')
                
            # Extract resource info (first resource only for CSV simplicity)
            if 'Resources' in finding and finding['Resources']:
                resource = finding['Resources'][0]
                row['ResourceId'] = resource.get('Id', '')
                row['ResourceType'] = resource.get('Type', '')
            
            # Extract compliance info
            if 'Compliance' in finding:
                row['ComplianceStatus'] = finding['Compliance'].get('Status', '')
                row['SecurityControlId'] = finding['Compliance'].get('SecurityControlId', '')
                
            # Extract remediation info
            if 'Remediation' in finding and 'Recommendation' in finding['Remediation']:
                row['RecommendationUrl'] = finding['Remediation']['Recommendation'].get('Url', '')
                
            writer.writerow(row)
    
    print(f"Exported {len(findings)} findings to {output_path}")
    return output_path

def create_poam_csv(findings, config, output_path):
    """Create a FedRAMP POAM CSV based on Security Hub findings"""
    # Define POAM columns according to FedRAMP guidance
    fieldnames = [
        "POA&M ID", "Controls", "Weakness Name", "Weakness Description", 
        "Weakness Detector Source", "Weakness Source Identifier", "Asset Identifier",
        "Point of Contact", "Resources Required", "Overall Remediation Plan",
        "Original Detection Date", "Scheduled Completion Date", "Planned Milestones",
        "Milestone Changes", "Status Date", "Vendor Dependency", "Last Vendor Check-in Date",
        "Vendor Dependent Product Name", "Original Risk Rating", "Adjusted Risk Rating",
        "Risk Adjustment", "False Positive", "Operational Requirement", "Deviation Rationale",
        "Supporting Documents", "Comments", "Auto-Approve", "Binding Operational Directive 22-01 tracking"
    ]
    
    # Current date for status date
    today = datetime.utcnow().strftime('%Y-%m-%d')
    
    # Ensure output directory exists
    os.makedirs(os.path.dirname(output_path) if os.path.dirname(output_path) else '.', exist_ok=True)
    
    with open(output_path, 'w', newline='') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        
        for idx, finding in enumerate(findings, 1):
            # Map Security Hub finding to POAM format
            row = {}
            
            # Generate ID with prefix
            row["POA&M ID"] = f"{config['poam']['id_prefix']}{idx:04d}"
            
            # Extract control from SecurityControlId if available, otherwise from Title or GeneratorId
            control = None
            if 'Compliance' in finding and finding['Compliance'].get('SecurityControlId'):
                control = finding['Compliance'].get('SecurityControlId')
            elif 'Title' in finding and finding['Title'].startswith('AWS-'):
                control = finding['Title'].split()[0]
            elif 'GeneratorId' in finding and finding['GeneratorId']:
                parts = finding['GeneratorId'].split('/')
                if len(parts) > 1:
                    control = parts[-1]
            row["Controls"] = control or ""
            
            # Extract other fields with reasonable defaults
            row["Weakness Name"] = finding.get('Title', finding.get('Id', f"SecurityHub Finding {idx}"))
            row["Weakness Description"] = finding.get('Description', "No description provided")
            row["Weakness Detector Source"] = finding.get('ProductName', "AWS Security Hub")
            row["Weakness Source Identifier"] = finding.get('Id', "")
            
            # Extract resource/asset information
            resources = finding.get('Resources', [])
            if resources:
                asset_ids = [r.get('Id', "") for r in resources]
                row["Asset Identifier"] = ", ".join(asset_ids)
            else:
                row["Asset Identifier"] = "Unknown"
                
            # Use configured values for these fields
            row["Point of Contact"] = config['poam']['point_of_contact']
            row["Resources Required"] = config['poam']['resources_required']
            
            # Extract remediation info if available
            remediation_plan = "Review and remediate the security finding"
            if 'Remediation' in finding and 'Recommendation' in finding['Remediation']:
                if 'Text' in finding['Remediation']['Recommendation']:
                    remediation_plan = finding['Remediation']['Recommendation']['Text']
                    
            row["Overall Remediation Plan"] = remediation_plan
            
            # Dates
            # Use FirstObservedAt if available, otherwise CreatedAt
            detection_date = finding.get('FirstObservedAt', finding.get('CreatedAt', datetime.utcnow().isoformat()))
            if isinstance(detection_date, str):
                detection_date = detection_date.split('T')[0]  # Extract date part only
            row["Original Detection Date"] = detection_date
            
            # Calculate completion date based on severity/priority and configured SLAs
            severity = "MEDIUM"  # Default
            if 'Severity' in finding and 'Label' in finding['Severity']:
                severity = finding['Severity']['Label']
                
            # Map Security Hub severity to SLA days - default to MEDIUM if not found
            days_to_complete = config['poam']['completion_sla'].get(
                severity, config['poam']['completion_sla'].get('MEDIUM', 90)
            )
                
            # Calculate completion date from detection date
            try:
                if isinstance(detection_date, str):
                    detection_datetime = datetime.strptime(detection_date, '%Y-%m-%d')
                else:
                    detection_datetime = detection_date
                completion_date = (detection_datetime + timedelta(days=days_to_complete)).strftime('%Y-%m-%d')
            except (ValueError, TypeError):
                # If parsing fails, use current date as base
                completion_date = (datetime.utcnow() + timedelta(days=days_to_complete)).strftime('%Y-%m-%d')
                
            row["Scheduled Completion Date"] = completion_date
            
            # Default milestone (will be filled in later)
            row["Planned Milestones"] = f"Review and remediate by {completion_date}"
            row["Milestone Changes"] = ""
            
            # Status date is today's date
            row["Status Date"] = today
            
            # Default values for remaining fields (to be filled in later)
            row["Vendor Dependency"] = "No"
            row["Last Vendor Check-in Date"] = ""
            row["Vendor Dependent Product Name"] = ""
            
            # Risk rating from severity
            if severity == 'CRITICAL':
                risk_rating = "High"
            elif severity == 'HIGH':
                risk_rating = "High"
            elif severity == 'MEDIUM':
                risk_rating = "Moderate"
            else:
                risk_rating = "Low"
                
            row["Original Risk Rating"] = risk_rating
            row["Adjusted Risk Rating"] = ""
            row["Risk Adjustment"] = "No"
            row["False Positive"] = "No"
            row["Operational Requirement"] = "No"
            row["Deviation Rationale"] = ""
            row["Supporting Documents"] = ""
            
            # Include documentation URL if available
            comments = f"Finding from AWS Security Hub: {finding.get('Id', '')}"
            if 'Remediation' in finding and 'Recommendation' in finding['Remediation'] and 'Url' in finding['Remediation']['Recommendation']:
                comments += f" | Documentation: {finding['Remediation']['Recommendation']['Url']}"
                
            row["Comments"] = comments
            row["Auto-Approve"] = ""
            row["Binding Operational Directive 22-01 tracking"] = ""
            
            writer.writerow(row)
    
    print(f"Created POAM with {len(findings)} items at {output_path}")
    return output_path

def main():
    # Parse arguments and load configuration
    args = parse_args()
    config = load_config(args)
    
    # Setup output paths
    findings_csv_path = os.path.join(config["output_dir"], config["findings_csv"])
    poam_csv_path = os.path.join(config["output_dir"], config["poam_csv"])
    
    print(f"Using AWS profile: {config['aws']['profile'] or 'default'}")
    print(f"Using AWS region: {config['aws']['region']}")
    print(f"Retrieving active Security Hub findings (max: {config['aws']['max_findings']})...")
    
    # Get findings from Security Hub
    findings = get_security_hub_findings(config)
    
    if not findings:
        print("No findings retrieved from Security Hub")
        return
    
    # Export findings to CSVs
    findings_csv = flatten_findings_to_csv(findings, findings_csv_path)
    poam_csv = create_poam_csv(findings, config, poam_csv_path)
    
    print(f"\nProcess complete. Files generated:")
    print(f"  - Raw findings: {findings_csv}")
    print(f"  - FedRAMP POAM: {poam_csv}")
    print("\nNote: You may need to manually review and fill in the following POAM fields:")
    print("  - Planned Milestones (detailed milestone plans)")
    print("  - Vendor Dependency (if applicable)")
    print("  - Risk Adjustment (if applicable)")
    print("  - Deviation Rationale (if applicable)")

if __name__ == "__main__":
    main()