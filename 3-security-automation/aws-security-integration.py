#!/usr/bin/env python3
"""
AWS Security Integration Tool - Amazon AppSec Interview Demo
==========================================================

Demonstrates integration of security tools with AWS services for scalable security automation.
Shows how security engineers can leverage AWS services for enterprise-scale security monitoring.

Features:
- AWS Security Hub integration
- CloudWatch custom metrics and alarms
- Lambda-based security automation
- S3 security policy validation
- IAM policy analysis
- VPC security group auditing

DEFENSIVE PURPOSE ONLY - For AWS security automation and compliance monitoring
"""

import boto3
import json
import time
from datetime import datetime, timezone, timedelta
from botocore.exceptions import ClientError, NoCredentialsError
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class AWSSecurityIntegration:
    def __init__(self, region='us-east-1'):
        self.region = region
        
        try:
            # Initialize AWS clients
            self.security_hub = boto3.client('securityhub', region_name=region)
            self.cloudwatch = boto3.client('cloudwatch', region_name=region)
            self.iam = boto3.client('iam')
            self.s3 = boto3.client('s3')
            self.ec2 = boto3.client('ec2', region_name=region)
            self.lambda_client = boto3.client('lambda', region_name=region)
            self.sts = boto3.client('sts')
            
            # Get account information
            self.account_id = self.sts.get_caller_identity()['Account']
            logger.info(f"Initialized AWS security integration for account {self.account_id}")
            
        except NoCredentialsError:
            logger.error("AWS credentials not found. Please configure AWS CLI or environment variables.")
            raise
        except Exception as e:
            logger.error(f"Failed to initialize AWS clients: {e}")
            raise

    def audit_s3_security_policies(self):
        """Audit S3 bucket security configurations"""
        logger.info("Auditing S3 bucket security policies")
        findings = []
        
        try:
            # Get list of all S3 buckets
            buckets = self.s3.list_buckets()['Buckets']
            
            for bucket in buckets:
                bucket_name = bucket['Name']
                bucket_findings = self._audit_single_bucket(bucket_name)
                findings.extend(bucket_findings)
                
        except ClientError as e:
            logger.error(f"Failed to audit S3 buckets: {e}")
        
        return findings
    
    def _audit_single_bucket(self, bucket_name):
        """Audit security configuration of a single S3 bucket"""
        findings = []
        
        try:
            # Check bucket public access block
            try:
                public_access_block = self.s3.get_public_access_block(Bucket=bucket_name)
                pab_config = public_access_block['PublicAccessBlockConfiguration']
                
                if not all(pab_config.values()):
                    findings.append({
                        'type': 'S3_PUBLIC_ACCESS_BLOCK',
                        'severity': 'HIGH',
                        'resource': bucket_name,
                        'title': 'S3 Bucket Public Access Block Not Fully Enabled',
                        'description': f'Bucket {bucket_name} does not have all public access block settings enabled',
                        'remediation': 'Enable all public access block settings for the bucket'
                    })
                    
            except ClientError as e:
                if e.response['Error']['Code'] == 'NoSuchPublicAccessBlockConfiguration':
                    findings.append({
                        'type': 'S3_PUBLIC_ACCESS_BLOCK',
                        'severity': 'HIGH',
                        'resource': bucket_name,
                        'title': 'S3 Bucket Missing Public Access Block',
                        'description': f'Bucket {bucket_name} has no public access block configuration',
                        'remediation': 'Configure public access block settings for the bucket'
                    })
            
            # Check bucket encryption
            try:
                encryption = self.s3.get_bucket_encryption(Bucket=bucket_name)
                # If we get here, encryption is enabled
                logger.debug(f"Bucket {bucket_name} has encryption enabled")
                
            except ClientError as e:
                if e.response['Error']['Code'] == 'ServerSideEncryptionConfigurationNotFoundError':
                    findings.append({
                        'type': 'S3_ENCRYPTION',
                        'severity': 'MEDIUM',
                        'resource': bucket_name,
                        'title': 'S3 Bucket Encryption Not Enabled',
                        'description': f'Bucket {bucket_name} does not have server-side encryption enabled',
                        'remediation': 'Enable server-side encryption (SSE-S3, SSE-KMS, or SSE-C)'
                    })
            
            # Check bucket versioning
            try:
                versioning = self.s3.get_bucket_versioning(Bucket=bucket_name)
                if versioning.get('Status') != 'Enabled':
                    findings.append({
                        'type': 'S3_VERSIONING',
                        'severity': 'MEDIUM',
                        'resource': bucket_name,
                        'title': 'S3 Bucket Versioning Not Enabled',
                        'description': f'Bucket {bucket_name} does not have versioning enabled',
                        'remediation': 'Enable versioning to protect against accidental deletion'
                    })
                    
            except ClientError as e:
                logger.warning(f"Could not check versioning for bucket {bucket_name}: {e}")
            
            # Check for public bucket policy
            try:
                bucket_policy = self.s3.get_bucket_policy(Bucket=bucket_name)
                policy_doc = json.loads(bucket_policy['Policy'])
                
                if self._is_policy_public(policy_doc):
                    findings.append({
                        'type': 'S3_PUBLIC_POLICY',
                        'severity': 'CRITICAL',
                        'resource': bucket_name,
                        'title': 'S3 Bucket Has Public Policy',
                        'description': f'Bucket {bucket_name} has a policy that allows public access',
                        'remediation': 'Review and restrict bucket policy to prevent public access'
                    })
                    
            except ClientError as e:
                if e.response['Error']['Code'] != 'NoSuchBucketPolicy':
                    logger.warning(f"Could not check policy for bucket {bucket_name}: {e}")
                    
        except ClientError as e:
            logger.error(f"Error auditing bucket {bucket_name}: {e}")
        
        return findings
    
    def _is_policy_public(self, policy_doc):
        """Check if S3 bucket policy allows public access"""
        for statement in policy_doc.get('Statement', []):
            principal = statement.get('Principal', {})
            
            # Check for wildcard principals
            if principal == '*' or principal == {'AWS': '*'}:
                effect = statement.get('Effect', '').upper()
                if effect == 'ALLOW':
                    return True
                    
            # Check for public principals in list
            if isinstance(principal, dict):
                aws_principals = principal.get('AWS', [])
                if isinstance(aws_principals, str):
                    aws_principals = [aws_principals]
                
                if '*' in aws_principals:
                    return True
        
        return False
    
    def audit_security_groups(self):
        """Audit EC2 security group configurations"""
        logger.info("Auditing EC2 security group configurations")
        findings = []
        
        try:
            security_groups = self.ec2.describe_security_groups()['SecurityGroups']
            
            for sg in security_groups:
                sg_id = sg['GroupId']
                sg_name = sg['GroupName']
                
                # Check for overly permissive inbound rules
                for rule in sg.get('IpPermissions', []):
                    if self._is_rule_overly_permissive(rule):
                        port_info = self._get_port_info(rule)
                        
                        findings.append({
                            'type': 'SECURITY_GROUP_PERMISSIVE',
                            'severity': 'HIGH',
                            'resource': sg_id,
                            'title': f'Overly Permissive Security Group Rule',
                            'description': f'Security group {sg_name} ({sg_id}) has rule allowing {port_info} from 0.0.0.0/0',
                            'remediation': 'Restrict source IP ranges to specific networks or IP addresses'
                        })
                
                # Check for default security groups with rules
                if sg_name == 'default' and (sg.get('IpPermissions') or sg.get('IpPermissionsEgress')):
                    findings.append({
                        'type': 'DEFAULT_SECURITY_GROUP',
                        'severity': 'MEDIUM',
                        'resource': sg_id,
                        'title': 'Default Security Group Has Active Rules',
                        'description': f'Default security group {sg_id} has active rules - should be unused',
                        'remediation': 'Remove all rules from default security group and use custom groups'
                    })
                    
        except ClientError as e:
            logger.error(f"Failed to audit security groups: {e}")
        
        return findings
    
    def _is_rule_overly_permissive(self, rule):
        """Check if security group rule is overly permissive"""
        for ip_range in rule.get('IpRanges', []):
            if ip_range.get('CidrIp') == '0.0.0.0/0':
                # Check if it's a dangerous port
                from_port = rule.get('FromPort', 0)
                to_port = rule.get('ToPort', 65535)
                
                dangerous_ports = [22, 3389, 1433, 3306, 5432, 6379, 27017]
                
                if from_port in dangerous_ports or any(from_port <= port <= to_port for port in dangerous_ports):
                    return True
                    
                # Also flag if it's a wide port range open to world
                if (to_port - from_port) > 100:
                    return True
        
        return False
    
    def _get_port_info(self, rule):
        """Get human-readable port information from security group rule"""
        protocol = rule.get('IpProtocol', 'unknown')
        from_port = rule.get('FromPort')
        to_port = rule.get('ToPort')
        
        if protocol == '-1':
            return "all traffic"
        elif from_port == to_port:
            return f"port {from_port}/{protocol}"
        else:
            return f"ports {from_port}-{to_port}/{protocol}"
    
    def analyze_iam_policies(self):
        """Analyze IAM policies for security issues"""
        logger.info("Analyzing IAM policies for security issues")
        findings = []
        
        try:
            # Check for overly permissive policies
            policies = self.iam.list_policies(Scope='Local')['Policies']
            
            for policy in policies:
                policy_arn = policy['Arn']
                policy_name = policy['PolicyName']
                
                # Get policy document
                policy_version = self.iam.get_policy_version(
                    PolicyArn=policy_arn,
                    VersionId=policy['DefaultVersionId']
                )
                
                policy_doc = policy_version['PolicyVersion']['Document']
                policy_findings = self._analyze_policy_document(policy_doc, policy_name, policy_arn)
                findings.extend(policy_findings)
                
        except ClientError as e:
            logger.error(f"Failed to analyze IAM policies: {e}")
        
        return findings
    
    def _analyze_policy_document(self, policy_doc, policy_name, policy_arn):
        """Analyze individual IAM policy document for security issues"""
        findings = []
        
        for statement in policy_doc.get('Statement', []):
            if statement.get('Effect') == 'Allow':
                actions = statement.get('Action', [])
                resources = statement.get('Resource', [])
                
                # Convert to lists for consistent handling
                if isinstance(actions, str):
                    actions = [actions]
                if isinstance(resources, str):
                    resources = [resources]
                
                # Check for overly broad permissions
                if '*' in actions and '*' in resources:
                    findings.append({
                        'type': 'IAM_OVERPERMISSIVE',
                        'severity': 'CRITICAL',
                        'resource': policy_arn,
                        'title': 'IAM Policy Grants Full Administrative Access',
                        'description': f'Policy {policy_name} grants Action:* on Resource:*',
                        'remediation': 'Apply principle of least privilege - restrict to specific actions and resources'
                    })
                
                # Check for dangerous actions
                dangerous_actions = [
                    'iam:CreateRole', 'iam:CreatePolicy', 'iam:AttachRolePolicy',
                    'sts:AssumeRole', 'ec2:*', 's3:*'
                ]
                
                for action in actions:
                    if action in dangerous_actions and '*' in resources:
                        findings.append({
                            'type': 'IAM_DANGEROUS_ACTION',
                            'severity': 'HIGH',
                            'resource': policy_arn,
                            'title': f'IAM Policy Allows Dangerous Action: {action}',
                            'description': f'Policy {policy_name} allows {action} on all resources',
                            'remediation': f'Restrict {action} to specific resources only'
                        })
        
        return findings
    
    def send_findings_to_security_hub(self, findings):
        """Send security findings to AWS Security Hub"""
        logger.info(f"Sending {len(findings)} findings to Security Hub")
        
        hub_findings = []
        
        for finding in findings[:100]:  # Security Hub batch limit is 100
            hub_finding = {
                'SchemaVersion': '2018-10-08',
                'Id': f"aws-security-audit-{hash(str(finding))}",
                'ProductArn': f"arn:aws:securityhub:{self.region}:{self.account_id}:product/{self.account_id}/default",
                'GeneratorId': 'aws-security-integration-tool',
                'AwsAccountId': self.account_id,
                'CreatedAt': datetime.now(timezone.utc).isoformat(),
                'UpdatedAt': datetime.now(timezone.utc).isoformat(),
                'Severity': {
                    'Label': finding['severity']
                },
                'Title': finding['title'],
                'Description': finding['description'],
                'Types': [f"Sensitive Data Identifications/Personal Financial Information"],
                'Resources': [{
                    'Type': 'AwsAccount',
                    'Id': f"AWS::::Account:{self.account_id}",
                    'Region': self.region
                }]
            }
            
            # Add specific resource information
            if 'resource' in finding:
                if finding['type'].startswith('S3_'):
                    hub_finding['Resources'] = [{
                        'Type': 'AwsS3Bucket',
                        'Id': f"arn:aws:s3:::{finding['resource']}",
                        'Region': self.region
                    }]
                elif finding['type'].startswith('SECURITY_GROUP'):
                    hub_finding['Resources'] = [{
                        'Type': 'AwsEc2SecurityGroup',
                        'Id': f"arn:aws:ec2:{self.region}:{self.account_id}:security-group/{finding['resource']}",
                        'Region': self.region
                    }]
                elif finding['type'].startswith('IAM_'):
                    hub_finding['Resources'] = [{
                        'Type': 'AwsIamPolicy',
                        'Id': finding['resource'],
                        'Region': 'us-east-1'  # IAM is global
                    }]
            
            hub_findings.append(hub_finding)
        
        try:
            # Send findings in batches
            batch_size = 100
            for i in range(0, len(hub_findings), batch_size):
                batch = hub_findings[i:i + batch_size]
                response = self.security_hub.batch_import_findings(Findings=batch)
                
                if response['SuccessCount'] > 0:
                    logger.info(f"Successfully sent {response['SuccessCount']} findings to Security Hub")
                
                if response['FailureCount'] > 0:
                    logger.warning(f"Failed to send {response['FailureCount']} findings")
                    
        except ClientError as e:
            logger.error(f"Failed to send findings to Security Hub: {e}")
    
    def create_cloudwatch_dashboard(self, dashboard_name="SecurityDashboard"):
        """Create CloudWatch dashboard for security metrics"""
        logger.info(f"Creating CloudWatch dashboard: {dashboard_name}")
        
        dashboard_body = {
            "widgets": [
                {
                    "type": "metric",
                    "x": 0,
                    "y": 0,
                    "width": 12,
                    "height": 6,
                    "properties": {
                        "metrics": [
                            ["AWS/SecurityHub", "Findings", "ComplianceType", "CRITICAL"],
                            [".", ".", ".", "HIGH"],
                            [".", ".", ".", "MEDIUM"],
                            [".", ".", ".", "LOW"]
                        ],
                        "period": 300,
                        "stat": "Sum",
                        "region": self.region,
                        "title": "Security Hub Findings by Severity"
                    }
                },
                {
                    "type": "metric",
                    "x": 12,
                    "y": 0,
                    "width": 12,
                    "height": 6,
                    "properties": {
                        "metrics": [
                            ["AWS/GuardDuty", "FindingCount"]
                        ],
                        "period": 300,
                        "stat": "Sum",
                        "region": self.region,
                        "title": "GuardDuty Threat Detections"
                    }
                },
                {
                    "type": "log",
                    "x": 0,
                    "y": 6,
                    "width": 24,
                    "height": 6,
                    "properties": {
                        "query": f"SOURCE '/aws/lambda/security-automation' | fields @timestamp, @message\n| filter @message like /CRITICAL/\n| sort @timestamp desc\n| limit 20",
                        "region": self.region,
                        "title": "Recent Critical Security Events"
                    }
                }
            ]
        }
        
        try:
            self.cloudwatch.put_dashboard(
                DashboardName=dashboard_name,
                DashboardBody=json.dumps(dashboard_body)
            )
            
            logger.info(f"Dashboard '{dashboard_name}' created successfully")
            
        except ClientError as e:
            logger.error(f"Failed to create CloudWatch dashboard: {e}")
    
    def setup_security_alarms(self):
        """Set up CloudWatch alarms for security metrics"""
        logger.info("Setting up security CloudWatch alarms")
        
        alarms = [
            {
                'AlarmName': 'SecurityHub-CriticalFindings',
                'ComparisonOperator': 'GreaterThanThreshold',
                'EvaluationPeriods': 1,
                'MetricName': 'Findings',
                'Namespace': 'AWS/SecurityHub',
                'Period': 300,
                'Statistic': 'Sum',
                'Threshold': 0.0,
                'ActionsEnabled': True,
                'AlarmDescription': 'Alarm when critical security findings detected',
                'Dimensions': [
                    {
                        'Name': 'ComplianceType',
                        'Value': 'CRITICAL'
                    }
                ],
                'Unit': 'Count'
            },
            {
                'AlarmName': 'GuardDuty-ThreatDetection',
                'ComparisonOperator': 'GreaterThanThreshold',
                'EvaluationPeriods': 1,
                'MetricName': 'FindingCount',
                'Namespace': 'AWS/GuardDuty',
                'Period': 300,
                'Statistic': 'Sum',
                'Threshold': 0.0,
                'ActionsEnabled': True,
                'AlarmDescription': 'Alarm when GuardDuty detects threats',
                'Unit': 'Count'
            }
        ]
        
        for alarm in alarms:
            try:
                self.cloudwatch.put_metric_alarm(**alarm)
                logger.info(f"Created alarm: {alarm['AlarmName']}")
                
            except ClientError as e:
                logger.error(f"Failed to create alarm {alarm['AlarmName']}: {e}")
    
    def run_comprehensive_audit(self):
        """Run comprehensive AWS security audit"""
        logger.info("Starting comprehensive AWS security audit")
        
        all_findings = []
        
        # Run all audit checks
        s3_findings = self.audit_s3_security_policies()
        all_findings.extend(s3_findings)
        
        sg_findings = self.audit_security_groups()
        all_findings.extend(sg_findings)
        
        iam_findings = self.analyze_iam_policies()
        all_findings.extend(iam_findings)
        
        logger.info(f"Security audit completed. Found {len(all_findings)} total findings")
        
        # Send to Security Hub
        if all_findings:
            self.send_findings_to_security_hub(all_findings)
        
        # Set up monitoring
        self.create_cloudwatch_dashboard()
        self.setup_security_alarms()
        
        return all_findings


def lambda_handler(event, context):
    """AWS Lambda handler for automated security auditing"""
    try:
        # Initialize security integration
        security = AWSSecurityIntegration()
        
        # Run comprehensive audit
        findings = security.run_comprehensive_audit()
        
        # Return summary
        severity_counts = {}
        for finding in findings:
            severity = finding['severity']
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        return {
            'statusCode': 200,
            'body': json.dumps({
                'message': 'Security audit completed successfully',
                'totalFindings': len(findings),
                'severityBreakdown': severity_counts
            })
        }
        
    except Exception as e:
        logger.error(f"Lambda execution failed: {e}")
        return {
            'statusCode': 500,
            'body': json.dumps({
                'message': 'Security audit failed',
                'error': str(e)
            })
        }


def main():
    """Main execution for standalone running"""
    import argparse
    
    parser = argparse.ArgumentParser(description='AWS Security Integration Tool')
    parser.add_argument('--region', default='us-east-1', help='AWS region')
    parser.add_argument('--audit-type', choices=['s3', 'sg', 'iam', 'all'], 
                       default='all', help='Type of audit to run')
    parser.add_argument('--send-to-hub', action='store_true', 
                       help='Send findings to Security Hub')
    parser.add_argument('--setup-monitoring', action='store_true',
                       help='Set up CloudWatch monitoring')
    
    args = parser.parse_args()
    
    try:
        security = AWSSecurityIntegration(region=args.region)
        findings = []
        
        if args.audit_type in ['s3', 'all']:
            findings.extend(security.audit_s3_security_policies())
            
        if args.audit_type in ['sg', 'all']:
            findings.extend(security.audit_security_groups())
            
        if args.audit_type in ['iam', 'all']:
            findings.extend(security.analyze_iam_policies())
        
        # Display results
        print(f"\nSecurity Audit Results:")
        print(f"Total findings: {len(findings)}")
        
        severity_counts = {}
        for finding in findings:
            severity = finding['severity']
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        for severity, count in severity_counts.items():
            print(f"{severity}: {count}")
        
        # Show critical findings
        critical_findings = [f for f in findings if f['severity'] == 'CRITICAL']
        if critical_findings:
            print(f"\nCRITICAL FINDINGS:")
            for finding in critical_findings[:5]:  # Show first 5
                print(f"- {finding['title']}")
                print(f"  Resource: {finding.get('resource', 'N/A')}")
                print(f"  Description: {finding['description']}")
                print()
        
        if args.send_to_hub and findings:
            security.send_findings_to_security_hub(findings)
        
        if args.setup_monitoring:
            security.create_cloudwatch_dashboard()
            security.setup_security_alarms()
        
        return 0 if not critical_findings else 1
        
    except Exception as e:
        logger.error(f"Security audit failed: {e}")
        return 1


if __name__ == '__main__':
    exit(main())