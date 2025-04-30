import boto3
import json
import csv
import datetime
import argparse
import os
import yaml
import sys
from datetime import datetime, timedelta

def parse_args():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(description='Export AWS Security Hub findings to FedRAMP POAM format')
    parser.add_argument('--config', help='Path to YAML config file', default="config.yaml")
    parser.add_argument('--profile', help='AWS profile name to override config', default=None)
    parser.add_argument('--region', help='AWS region to override config', default=None)
    parser.add_argument('--output-dir', help='Output directory for CSV files to override config', default=None)
    return parser.parse_args()

def load_config(args):
    """Load configuration from file"""
    config_path = args.config
    
    # Check if config file exists
    if not os.path.exists(config_path):
        print(f"Error: Config file '{config_path}' not found.")
        print("Please create a config.yaml file with required settings.")
        sys.exit(1)
    
    # Load the config file
    try:
        with open(config_path, 'r') as config_file:
            config = yaml.safe_load(config_file)
    except Exception as e:
        print(f"Error loading config file: {e}")
        sys.exit(1)
    
    # Validate required sections
    required_sections = ['aws', 'poam', 'output_dir', 'findings_csv', 'poam_csv']
    missing_sections = [section for section in required_sections if section not in config]
    
    if missing_sections:
        print(f"Error: Missing required config sections: {', '.join(missing_sections)}")
        sys.exit(1)
    
    # Override with command line arguments if provided
    if args.profile:
        config["aws"]["profile"] = args.profile
    if args.region:
        config["aws"]["region"] = args.region
    if args.output_dir:
        config["output_dir"] = args.output_dir
        
    return config

def get_last_poam_id(config):
    """Get the last used POAM ID from the tracking file"""
    counter_file = config.get("poam_counter_file", "poam_counter.txt")
    
    try:
        with open(counter_file, 'r') as f:
            last_id = int(f.read().strip())
            return last_id
    except (FileNotFoundError, ValueError):
        # If the file doesn't exist or has invalid content, use the default
        return config["poam"].get("start_id", 1)

def save_last_poam_id(config, last_id):
    """Save the last used POAM ID to the tracking file"""
    counter_file = config.get("poam_counter_file", "poam_counter.txt")
    
    # Ensure directory exists
    os.makedirs(os.path.dirname(counter_file) if os.path.dirname(counter_file) else '.', exist_ok=True)
    
    with open(counter_file, 'w') as f:
        f.write(str(last_id))

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

def truncate_asset_id(asset_id):
    """Truncate asset identifier to security control component"""
    if not asset_id or "security-control/" not in asset_id:
        return asset_id
    
    # Find the security-control part and keep everything up to and including the control ID
    parts = asset_id.split("security-control/")
    if len(parts) > 1:
        control_parts = parts[1].split("/")
        if control_parts:
            return parts[0] + "security-control/" + control_parts[0]
    return asset_id

def map_to_nist_control(security_control, config):
    """Map AWS security control ID to NIST 800-53 control"""
    control_mappings = config["poam"].get("control_mappings", {})
    
    # Check if the control is None or empty
    if not security_control:
        return config["poam"].get("default_control", "UNKNOWN")
    
    # Normalize the control ID - strip any prefixes and ensure consistent format
    if "." in security_control:
        # Handle cases like "AWS.SSM.1" or "securityhub/v2/SSM.1" etc.
        parts = security_control.split(".")
        if len(parts) >= 2:  # At least has prefix and number
            control_base = parts[-2]  # Get the base part (like SSM)
            control_num = parts[-1]   # Get the number part (like 1)
            simple_control = f"{control_base}.{control_num}"
        else:
            simple_control = security_control
    else:
        simple_control = security_control
    
    # Print for debugging
    print(f"Mapping control: Original={security_control}, Normalized={simple_control}")
    
    # Try exact match first
    nist_control = control_mappings.get(simple_control)
    
    # If no match, try case-insensitive match
    if not nist_control:
        for control_key, nist_value in control_mappings.items():
            if control_key.upper() == simple_control.upper():
                nist_control = nist_value
                break
    
    # If still no mapping found, use the default
    if not nist_control:
        print(f"No mapping found for control: {simple_control}")
        return config["poam"].get("default_control", security_control)
    
    print(f"Found mapping: {simple_control} → {nist_control}")
    return nist_control

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

def create_poam_csv(findings, config, output_path, start_id):
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
    
    # Keep track of the highest ID used
    max_id_used = start_id
    
    with open(output_path, 'w', newline='') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        
        for idx, finding in enumerate(findings, 0):
            # Map Security Hub finding to POAM format
            row = {}
            
            # Generate ID with prefix
            current_id = start_id + idx
            if current_id > max_id_used:
                max_id_used = current_id
                
            row["POA&M ID"] = f"{config['poam']['id_prefix']}{current_id:04d}"
            
            # Extract and map control to NIST
            security_control = None
            if 'Compliance' in finding and finding['Compliance'].get('SecurityControlId'):
                security_control = finding['Compliance'].get('SecurityControlId')
            elif 'Title' in finding:
                # Try to extract control from title (formats like: "[SSM.1] Something..." or "AWS-SSM.1 Something...")
                title = finding.get('Title', '')
                if "[" in title and "]" in title:
                    possible_control = title.split('[')[1].split(']')[0]
                    if "." in possible_control:  # Likely a control ID
                        security_control = possible_control
                elif title.startswith('AWS-'):
                    parts = title.split(' ')[0].split('-')
                    if len(parts) > 1:
                        security_control = parts[1]
            elif 'GeneratorId' in finding and finding['GeneratorId']:
                parts = finding['GeneratorId'].split('/')
                if len(parts) > 1:
                    security_control = parts[-1]
                    
            # Map to NIST control
            nist_control = map_to_nist_control(security_control, config)
            row["Controls"] = nist_control or ""
            
            # Extract other fields with reasonable defaults
            row["Weakness Name"] = finding.get('Title', finding.get('Id', f"SecurityHub Finding {idx}"))
            row["Weakness Description"] = finding.get('Description', "No description provided")
            row["Weakness Detector Source"] = finding.get('ProductName', "AWS Security Hub")
            row["Weakness Source Identifier"] = finding.get('Id', "")
            
            # Extract and truncate asset identifier as specified
            asset_id = finding.get('Id', "")
            row["Asset Identifier"] = truncate_asset_id(asset_id)
                
            # Use configured values for these fields
            row["Point of Contact"] = config['poam']['point_of_contact']
            row["Resources Required"] = config['poam']['resources_required']
            
            # Use RecommendationUrl for Overall Remediation Plan
            recommendation_url = ""
            if 'Remediation' in finding and 'Recommendation' in finding['Remediation']:
                recommendation_url = finding['Remediation']['Recommendation'].get('Url', "")
                    
            row["Overall Remediation Plan"] = recommendation_url
            
            # Original Detection Date = FirstObservedAt
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
                
            # Calculate completion date from FirstObservedAt
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
            
            # Empty Planned Milestones
            row["Planned Milestones"] = ""
            row["Milestone Changes"] = ""
            
            # Status date is today's date (script run date)
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
            
            # Leave Comments field blank
            row["Comments"] = ""
            row["Auto-Approve"] = ""
            row["Binding Operational Directive 22-01 tracking"] = ""
            
            writer.writerow(row)
    
    print(f"Created POAM with {len(findings)} items at {output_path}")
    return output_path, max_id_used

def main():
    # Parse arguments and load configuration
    args = parse_args()
    config = load_config(args)
    
    # Setup output paths
    findings_csv_path = os.path.join(config["output_dir"], config["findings_csv"])
    poam_csv_path = os.path.join(config["output_dir"], config["poam_csv"])
    
    # Get last POAM ID used
    last_id = get_last_poam_id(config)
    start_id = last_id + 1
    
    print(f"Using AWS profile: {config['aws']['profile'] or 'default'}")
    print(f"Using AWS region: {config['aws']['region']}")
    print(f"Starting with POAM ID: {config['poam']['id_prefix']}{start_id:04d}")
    print(f"Retrieving active Security Hub findings (max: {config['aws']['max_findings']})...")
    
    # Get findings from Security Hub
    findings = get_security_hub_findings(config)
    
    if not findings:
        print("No findings retrieved from Security Hub")
        return
    
    # Export findings to CSVs
    findings_csv = flatten_findings_to_csv(findings, findings_csv_path)
    poam_csv, max_id_used = create_poam_csv(findings, config, poam_csv_path, start_id)
    
    # Save the last used ID
    save_last_poam_id(config, max_id_used)
    
    print(f"\nProcess complete. Files generated:")
    print(f"  - Raw findings: {findings_csv}")
    print(f"  - FedRAMP POAM: {poam_csv}")
    print(f"  - Last POAM ID used: {config['poam']['id_prefix']}{max_id_used:04d}")
    print("\nNote: You may need to manually review and fill in the following POAM fields:")
    print("  - Planned Milestones (currently empty as requested)")
    print("  - Vendor Dependency (if applicable)")
    print("  - Risk Adjustment (if applicable)")
    print("  - Deviation Rationale (if applicable)")

if __name__ == "__main__":
    main()