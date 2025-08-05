# Copyright (c) 2025 Jacobian Engineering
# Licensed under the MIT License - see LICENSE file for details

import boto3
import json
import csv
import datetime
import argparse
import os
import yaml
import sys
import re
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
    
    if not os.path.exists(config_path):
        print(f"Error: Config file '{config_path}' not found.")
        sys.exit(1)
    
    try:
        with open(config_path, 'r') as config_file:
            config = yaml.safe_load(config_file)
    except Exception as e:
        print(f"Error loading config file: {e}")
        sys.exit(1)
    
    required_sections = ['aws', 'poam', 'output_dir', 'findings_csv', 'poam_csv']
    missing_sections = [section for section in required_sections if section not in config]
    
    if missing_sections:
        print(f"Error: Missing required config sections: {', '.join(missing_sections)}")
        sys.exit(1)
    
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
            return int(f.read().strip())
    except (FileNotFoundError, ValueError):
        return config["poam"].get("start_id", 0)

def save_last_poam_id(config, last_id):
    """Save the last used POAM ID to the tracking file"""
    counter_file = config.get("poam_counter_file", "poam_counter.txt")
    os.makedirs(os.path.dirname(counter_file) if os.path.dirname(counter_file) else '.', exist_ok=True)
    with open(counter_file, 'w') as f:
        f.write(str(last_id))

def load_findings_history(config):
    """Load the findings history from the JSON file"""
    history_file = config.get("history_file", "findings_history.json")
    try:
        with open(history_file, 'r') as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}

def save_findings_history(config, history):
    """Save the updated findings history to the JSON file"""
    history_file = config.get("history_file", "findings_history.json")
    with open(history_file, 'w') as f:
        json.dump(history, f, indent=4)

def get_security_hub_findings(config):
    """Query Security Hub API for active findings"""
    session = boto3.Session(profile_name=config["aws"]["profile"], region_name=config["aws"]["region"])
    securityhub = session.client('securityhub')
    filters = {'RecordState': [{'Value': 'ACTIVE', 'Comparison': 'EQUALS'}], 'ComplianceStatus': [{'Value': 'FAILED', 'Comparison': 'EQUALS'}]}
    
    all_findings = []
    paginator = securityhub.get_paginator('get_findings')
    pages = paginator.paginate(Filters=filters)
    
    for page in pages:
        all_findings.extend(page['Findings'])
        if len(all_findings) >= config["aws"]["max_findings"]:
            print(f"Reached maximum findings limit of {config['aws']['max_findings']}")
            break
            
    print(f"Retrieved {len(all_findings)} findings from Security Hub")
    return all_findings

def normalize_description(description):
    """Normalize the weakness description by removing leading numbers like '1.14 '."""
    return re.sub(r'^\d+\.\d+\s*', '', description).strip()

def map_to_nist_control(security_control, config):
    """Map AWS security control ID to NIST 800-53 control"""
    control_mappings = config["poam"].get("control_mappings", {})
    if not security_control:
        return config["poam"].get("default_control", "UNKNOWN")
    
    # Normalize the control ID
    if "." in security_control:
        parts = security_control.split(".")
        simple_control = f"{parts[-2]}.{parts[-1]}" if len(parts) >= 2 else security_control
    else:
        simple_control = security_control
    
    # Try direct and case-insensitive match
    nist_control = control_mappings.get(simple_control)
    if not nist_control:
        for key, value in control_mappings.items():
            if key.upper() == simple_control.upper():
                nist_control = value
                break
    
    return nist_control or config["poam"].get("default_control", security_control)

def reconcile_findings(current_findings, history, poam_id_counter, config):
    """Reconcile current findings with historical data to track vulnerabilities over time."""
    today = datetime.utcnow().strftime('%Y-%m-%d')
    new_history = history.copy()
    poam_items = []
    
    grouped_current_findings = {}
    for finding in current_findings:
        norm_desc = normalize_description(finding['Description'])
        if norm_desc not in grouped_current_findings:
            grouped_current_findings[norm_desc] = {'assets': set(), 'finding_obj': finding}
        for resource in finding.get('Resources', []):
            grouped_current_findings[norm_desc]['assets'].add(resource['Id'])

    processed_historical_keys = set()

    for key, hist_item in history.items():
        processed_historical_keys.add(key)
        if key in grouped_current_findings:
            current_info = grouped_current_findings[key]
            hist_item['assets'] = sorted(list(current_info['assets']))
            hist_item['status'] = "Open"
            hist_item['status_date'] = today
            new_history[key] = hist_item
            poam_items.append(hist_item)
        else:
            if hist_item['status'] == "Open":
                hist_item['status'] = "Closed"
                hist_item['status_date'] = today
                hist_item['assets'] = []
                new_history[key] = hist_item
                poam_items.append(hist_item)

    for key, current_info in grouped_current_findings.items():
        if key not in processed_historical_keys:
            poam_id_counter += 1
            new_item = {
                'poam_id': f"{config['poam']['id_prefix']}{poam_id_counter:04d}",
                'normalized_description': key,
                'weakness_name': current_info['finding_obj']['Title'],
                'weakness_description': current_info['finding_obj']['Description'],
                'assets': sorted(list(current_info['assets'])),
                'detection_date': current_info['finding_obj'].get('FirstObservedAt', today).split('T')[0],
                'status': "Open",
                'status_date': today,
                'raw_finding': current_info['finding_obj']
            }
            new_history[key] = new_item
            poam_items.append(new_item)
            
    return poam_items, new_history, poam_id_counter

def create_poam_csv(poam_items, config, output_path):
    """Create a FedRAMP POAM CSV from reconciled findings."""
    fieldnames = [
        "POA&M ID", "Status", "Controls", "Weakness Name", "Weakness Description", 
        "Weakness Detector Source", "Weakness Source Identifier", "Asset Identifier",
        "Point of Contact", "Resources Required", "Overall Remediation Plan",
        "Original Detection Date", "Scheduled Completion Date", "Planned Milestones",
        "Milestone Changes", "Status Date", "Vendor Dependency", "Last Vendor Check-in Date",
        "Vendor Dependent Product Name", "Original Risk Rating", "Adjusted Risk Rating",
        "Risk Adjustment", "False Positive", "Operational Requirement", "Deviation Rationale",
        "Supporting Documents", "Comments", "Auto-Approve", "Binding Operational Directive 22-01 tracking"
    ]
    
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    
    with open(output_path, 'w', newline='') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        
        for item in poam_items:
            row = {}
            finding = item.get('raw_finding', {})
            
            row["POA&M ID"] = item['poam_id']
            row["Status"] = item['status']
            
            security_control_id = finding.get('Compliance', {}).get('SecurityControlId')
            row["Controls"] = map_to_nist_control(security_control_id, config)

            row["Weakness Name"] = item['weakness_name']
            row["Weakness Description"] = item['weakness_description']
            row["Weakness Detector Source"] = finding.get('ProductName', "AWS Security Hub")
            row["Weakness Source Identifier"] = finding.get('Id', "")
            row["Asset Identifier"] = ", ".join(item['assets'])
            
            row["Point of Contact"] = config['poam']['point_of_contact']
            row["Resources Required"] = config['poam']['resources_required']
            
            recommendation_url = finding.get('Remediation', {}).get('Recommendation', {}).get('Url', "")
            row["Overall Remediation Plan"] = recommendation_url
            
            row["Original Detection Date"] = item['detection_date']
            
            severity = finding.get('Severity', {}).get('Label', 'MEDIUM')
            days_to_complete = config['poam']['completion_sla'].get(severity, 90)
            detection_datetime = datetime.strptime(item['detection_date'], '%Y-%m-%d')
            row["Scheduled Completion Date"] = (detection_datetime + timedelta(days=days_to_complete)).strftime('%Y-%m-%d')
            
            row["Status Date"] = item['status_date']
            
            row["Vendor Dependency"] = "No"
            row["False Positive"] = "No"
            
            severity_map = {'CRITICAL': 'High', 'HIGH': 'High', 'MEDIUM': 'Moderate', 'LOW': 'Low'}
            row["Original Risk Rating"] = severity_map.get(severity, 'Low')
            
            for field in fieldnames:
                if field not in row:
                    row[field] = ""
            
            writer.writerow(row)
            
    print(f"Created POAM with {len(poam_items)} items at {output_path}")

def flatten_findings_to_csv(findings, output_path):
    """Flatten the findings JSON and write to CSV for archival."""
    if not findings: return
    key_fields = ['Id', 'ProductArn', 'ProductName', 'CompanyName', 'Title', 'Description', 'GeneratorId', 'AwsAccountId', 'Types', 'FirstObservedAt', 'LastObservedAt', 'CreatedAt', 'UpdatedAt', 'RecordState']
    fieldnames = key_fields + ['SeverityLabel', 'SeverityProduct', 'ResourceId', 'ResourceType', 'ComplianceStatus', 'SecurityControlId', 'RecommendationUrl']
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, 'w', newline='') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for finding in findings:
            row = {f: finding.get(f, "") for f in key_fields}
            row['SeverityLabel'] = finding.get('Severity', {}).get('Label', '')
            if finding.get('Resources'):
                row['ResourceId'] = finding['Resources'][0].get('Id', '')
                row['ResourceType'] = finding['Resources'][0].get('Type', '')
            row['ComplianceStatus'] = finding.get('Compliance', {}).get('Status', '')
            row['SecurityControlId'] = finding.get('Compliance', {}).get('SecurityControlId', '')
            row['RecommendationUrl'] = finding.get('Remediation', {}).get('Recommendation', {}).get('Url', '')
            writer.writerow(row)
    print(f"Exported {len(findings)} raw findings to {output_path}")

def main():
    args = parse_args()
    config = load_config(args)
    
    findings_csv_path = os.path.join(config["output_dir"], config["findings_csv"])
    poam_csv_path = os.path.join(config["output_dir"], config["poam_csv"])
    
    print(f"Using AWS profile: {config['aws'].get('profile', 'default')}")
    print(f"Using AWS region: {config['aws']['region']}")
    
    history = load_findings_history(config)
    last_id = get_last_poam_id(config)
    print(f"Loaded {len(history)} historical findings.")
    print(f"Last used POAM ID: {last_id}")

    current_findings = get_security_hub_findings(config)
    
    poam_items, new_history, new_last_id = reconcile_findings(current_findings, history, last_id, config)
    
    create_poam_csv(poam_items, config, poam_csv_path)
    flatten_findings_to_csv(current_findings, findings_csv_path)
    
    save_findings_history(config, new_history)
    save_last_poam_id(config, new_last_id)
    
    print(f"\nProcess complete.")
    print(f"  - Final POAM: {poam_csv_path}")
    print(f"  - Raw findings dump: {findings_csv_path}")
    print(f"  - Last POAM ID used: {new_last_id}")

if __name__ == "__main__":
    main()
