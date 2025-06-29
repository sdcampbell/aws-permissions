import subprocess
import re
import threading
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed, TimeoutError
from tqdm import tqdm
import shutil

from colorama import Fore, init


class AWSBruteForce():

    def __init__(self, debug, region, profile, aws_services, threads):
        self.debug = debug
        self.region = region
        self.profile = profile
        self.aws_services = [a.lower() for a in aws_services]
        self.num_threads = threads
        self.found_permissions = []
        self.lock = threading.Lock()
        
        # Get account ID dynamically, but use only us-east-1 for efficiency
        self.account_id = self.get_account_id()
        self.regions = ["us-east-1"]  # Only test in us-east-1 for permission enumeration

        if shutil.which("aws") is None:
            print("AWS CLI is not installed or not in PATH. Please install the AWS CLI before running this tool.")
            exit(1)

    # Utility functions
    def get_account_id(self):
        """Dynamically retrieve the current AWS account ID"""
        try:
            result = subprocess.run(f'aws --profile {self.profile} sts get-caller-identity --query Account --output text', 
                                  shell=True, capture_output=True, timeout=10)
            if result.returncode == 0:
                account_id = result.stdout.decode().strip()
                if self.debug:
                    print(f"[DEBUG] Detected account ID: {account_id}")
                return account_id
            else:
                if self.debug:
                    print(f"[DEBUG] Failed to get account ID, using placeholder: {result.stderr.decode().strip()}")
                return "000000000000"
        except Exception as e:
            if self.debug:
                print(f"[DEBUG] Error getting account ID: {e}")
            return "000000000000"

    def get_all_regions(self):
        """Get all available AWS regions"""
        try:
            result = subprocess.run(f'aws --profile {self.profile} ec2 describe-regions --query "Regions[].RegionName" --output text', 
                                  shell=True, capture_output=True, timeout=15)
            if result.returncode == 0:
                regions = result.stdout.decode().strip().split()
                if self.debug:
                    print(f"[DEBUG] Detected {len(regions)} regions: {regions[:5]}...")  # Show first 5
                return regions
            else:
                if self.debug:
                    print(f"[DEBUG] Failed to get regions, using default: {result.stderr.decode().strip()}")
                return [self.region]
        except Exception as e:
            if self.debug:
                print(f"[DEBUG] Error getting regions: {e}")
            return [self.region]

    def transform_command(self, command):
        substitutions = [
            (r'accessanalizer', 'access-analyzer'),
            (r'amp:', 'aps:'),
            (r'apigateway:Get.*', 'apigateway:GET'),
            (r'apigatewayv2:Get.*', 'apigateway:GET'),
            (r'appintegrations:', 'app-integrations:'),
            (r'application-insights:', 'applicationinsights:'),
            (r'athena:ListApplicationDpuSizes', 'athena:ListApplicationDPUSizes'),
            (r'chime-.*:', 'chime:'),
            (r'cloudcontrol:', 'cloudformation:'),
            (r'cloudfront:ListDistributionsByWebAclId', 'cloudfront:ListDistributionsByWebACLId'),
            (r'cloudhsmv2:', 'cloudhsm:'),
            (r'codeguruprofiler:', 'codeguru-profiler:'),
            (r'comprehendmedical:ListIcd10CmInferenceJobs', 'comprehendmedical:ListICD10CMInferenceJobs'),
            (r'comprehendmedical:ListPhiDetectionJobs', 'comprehendmedical:ListPHIDetectionJobs'),
            (r'comprehendmedical:ListSnomedctInferenceJobs', 'comprehendmedical:ListSNOMEDCTInferenceJobs'),
            (r'configservice:', 'config:'),
            (r'connectcampaigns:', 'connect-campaigns:'),
            (r'connectcases:', 'cases:'),
            (r'customer-profiles:', 'profile:'),
            (r'deploy:', 'codeploy:'),
            (r'detective:ListOrganizationAdminAccounts', 'detective:ListOrganizationAdminAccount'),
            (r'docdb:', 'rds:'),
            (r'dynamodbstreams:', 'dynamodb:'),
            (r'ecr:GetLoginPassword', 'ecr:GetAuthorizationToken'),
            (r'efs:', 'elasticfilesystem:'),
            (r'elbv2', 'elasticloadbalancing:'),
            (r'elb:', 'elasticloadbalancing:'),
            (r'emr:', 'elasticmapreduce:'),
            (r'frauddetector:GetKmsEncryptionKey', 'frauddetector:GetKMSEncryptionKey'),
            (r'gamelift:DescribeEc2InstanceLimits', 'gamelift:DescribeEC2InstanceLimits'),
            (r'glue:GetMlTransforms', 'glue:GetMLTransforms'),
            (r'glue:ListMlTransforms', 'glue:ListMLTransforms'),
            (r'greengrassv2:', 'greengrass:'),
            (r'healthlake:ListFhirDatastores', 'healthlake:ListFHIRDatastores'),
            (r'iam:ListMfaDevices', 'iam:ListMFADevices'),
            (r'iam:ListOpenIdConnectProviders', 'iam:ListOpenIDConnectProviders'),
            (r'iam:ListSamlProviders', 'iam:ListSAMLProviders'),
            (r'iam:ListSshPublicKeys', 'iam:ListSSHPublicKeys'),
            (r'iam:ListVirtualMfaDevices', 'iam:ListVirtualMFADevices'),
            (r'iot:ListCaCertificates', 'iot:ListCACertificates'),
            (r'iot:ListOtaUpdates', 'iot:ListOTAUpdates'),
            (r'iot-data:', 'iot:'),
            (r'iotsecuretunneling:', 'iot:'),
            (r'ivs-realtime:', 'ivs:'),
            (r'kinesis-video-archived-media:', 'kinesisvideo:'),
            (r'kinesis-video-signaling:', 'kinesisvideo:'),
            (r'kinesisanalyticsv2:', 'kinesisanalytics:'),
            (r'lakeformation:ListLfTags', 'lakeformation:ListLFTags'),
            (r'lex-models:', 'lex:'),
            (r'lexv2-models:', 'lex:'),
            (r'lightsail:GetContainerApiMetadata', 'lightsail:GetContainerAPIMetadata'),
            (r'location:', 'geo:'),
            (r'marketplace-entitlement:', 'aws-marketplace:'),
            (r'migration-hub-refactor-spaces:', 'refactor-spaces:'),
            (r'migrationhub-config:', 'mgh:'),
            (r'migrationhuborchestrator:', 'migrationhub-orchestrator:'),
            (r'migrationhubstrategy:', 'migrationhub-strategy:'),
            (r'mwaa:', 'airflow:'),
            (r'neptune:', 'rds:'),
            (r'network-firewall:ListTlsInspectionConfigurations', 'network-firewall:ListTLSInspectionConfigurations'),
            (r'opensearch:', 'es:'),
            (r'opensearchserverless:', 'aoss:'),
            (r'organizations:ListAwsServiceAccessForOrganization', 'organizations:ListAWSServiceAccessForOrganization'),
            (r'pinpoint:', 'mobiletargeting:'),
            (r'pinpoint-email:', 'ses:'),
            (r'pinpoint-sms-voice-v2:', 'sms-voice:'),
            (r'privatenetworks:', 'private-networks:'),
            (r'Db', 'DB'),
            (r'resourcegroupstaggingapi:', 'tag:'),
            (r's3outposts:', 's3-outposts:'),
            (r'sagemaker:ListAutoMlJobs', 'sagemaker:ListAutoMLJobs'),
            (r'sagemaker:ListCandidatesForAutoMlJob', 'sagemaker:ListCandidatesForAutoMLJob'),
            (r'service-quotas:', 'servicequotas:'),
            (r'servicecatalog:GetAwsOrganizationsAccessStatus', 'servicecatalog:GetAWSOrganizationsAccessStatus'),
            (r'servicecatalog-appregistry:', 'servicecatalog:'),
            (r'sesv2:', 'ses:'),
            (r'sns:GetSmsAttributes', 'sns:GetSMSAttributes'),
            (r'sns:GetSmsSandboxAccountStatus', 'sns:GetSMSSandboxAccountStatus'),
            (r'sns:ListSmsSandboxPhoneNumbers', 'sns:ListSMSSandboxPhoneNumbers'),
            (r'sso-admin:', 'sso:'),
            (r'stepfunctions:', 'states:'),
            (r'support-app:', 'supportapp:'),
            (r'timestream-query:', 'timestream:'),
            (r'timestream-write:', 'timestream:'),
            (r'voice-id:', 'voiceid:'),
            (r'waf:ListIpSets', 'waf:ListIPSets'),
            (r'waf:ListWebAcls', 'waf:ListWebACLs'),
            (r'waf-regional:ListIpSets', 'waf-regional:ListIPSets'),
            (r'waf-regional:ListWebAcls', 'waf-regional:ListWebACLs'),
            (r'keyspaces:ListKeyspaces', 'cassandra:Select'),
            (r'keyspaces:ListTables', 'cassandra:Select'),
            (r's3api:ListBuckets', 's3:ListAllMyBuckets')
        ]

        for pattern, replacement in substitutions:
            command = re.sub(pattern, replacement, command)

        return command

    def capitalize(self, command):
        return ''.join(word.capitalize() for word in command.split('-'))

    def get_test_value_for_argument(self, service, command, arg_name, region=None):
        """Generate appropriate test values based on service, command, and argument name"""
        arg_lower = arg_name.lower()
        account_id = self.account_id
        target_region = region or self.region
        
        # ARN-based arguments
        if 'arn' in arg_lower or 'resource-arn' in arg_lower:
            if service == 'backup':
                return f"arn:aws:backup:{target_region}:{account_id}:recovery-point:test-recovery-point"
            elif service == 'iam':
                return f"arn:aws:iam::{account_id}:role/TestRole"
            elif service == 's3':
                return "arn:aws:s3:::test-bucket"
            elif service == 'lambda':
                return f"arn:aws:lambda:{target_region}:{account_id}:function:test-function"
            elif service == 'ec2':
                return f"arn:aws:ec2:{target_region}:{account_id}:instance/i-1234567890abcdef0"
            else:
                return f"arn:aws:{service}:{target_region}:{account_id}:resource/test-resource"
        
        # ID-based arguments
        elif any(x in arg_lower for x in ['id', 'identifier']):
            if service == 'bedrock':
                return "test-model-id"
            elif service == 'ec2':
                if 'instance' in arg_lower:
                    return "i-1234567890abcdef0"
                elif 'volume' in arg_lower:
                    return "vol-1234567890abcdef0"
                elif 'snapshot' in arg_lower:
                    return "snap-1234567890abcdef0"
                else:
                    return "test-resource-id"
            elif service == 'rds':
                return "test-db-instance"
            elif service == 's3':
                return "test-bucket"
            else:
                return "test-resource-id"
        
        # Name-based arguments
        elif 'name' in arg_lower:
            if service == 'iam':
                return "TestRole"
            elif service == 's3':
                return "test-bucket"
            elif service == 'lambda':
                return "test-function"
            else:
                return "test-resource-name"
        
        # Key-based arguments
        elif 'key' in arg_lower:
            if service == 's3':
                return "test-object-key"
            else:
                return "test-key"
        
        # Bucket-specific
        elif 'bucket' in arg_lower:
            return "test-bucket"
        
        # Function-specific
        elif 'function' in arg_lower:
            return "test-function"
        
        # Table-specific
        elif 'table' in arg_lower:
            return "test-table"
        
        # Region-specific
        elif 'region' in arg_lower:
            return target_region
        
        # Default fallback
        else:
            return "test-value"

    def get_alternative_test_value(self, service, command, arg_name, original_value, region=None):
        """Provide alternative test values when the first attempt fails"""
        arg_lower = arg_name.lower()
        account_id = self.account_id
        target_region = region or self.region
        
        # If original was an ARN and failed, try a simple name
        if original_value.startswith('arn:'):
            if service == 'iam':
                return "TestRole"
            elif service == 'bedrock':
                return "test-model-id"
            else:
                return "test-resource-name"
        
        # If original was a simple value, try an ARN
        elif 'arn' in arg_lower or any(x in original_value for x in ['test-', 'i-', 'vol-', 'snap-']):
            if service == 'backup':
                return f"arn:aws:backup:{target_region}:{account_id}:recovery-point:test-recovery-point"
            elif service == 'iam':
                return f"arn:aws:iam::{account_id}:role/TestRole"
            else:
                return f"arn:aws:{service}:{target_region}:{account_id}:resource/test-resource"
        
        return original_value

    def run_command(self, profile, region, service, command, extra='', cont=0):
        full_command = f'aws --cli-connect-timeout 19 --profile {profile} --region {region} {service} {command} {extra}'
        try:
            result = subprocess.run(full_command, shell=True, capture_output=True, timeout=20)
            output = result.stdout.decode() + result.stderr.decode()

            if result.returncode == 0 or re.search(r'NoSuchEntity|ResourceNotFoundException|NotFoundException', output, re.I):
                if self.debug:
                    print(f"[DEBUG] Successful or resource not found: {output.strip()}")
                perm_command = self.transform_command(f"{service}:{self.capitalize(command)}")
                print(f"{Fore.YELLOW}[+] {Fore.WHITE}You can access: {Fore.YELLOW}{service} {command} {Fore.BLUE}({full_command}) {Fore.GREEN}({perm_command}){Fore.RESET}")
                
                with self.lock:
                    self.found_permissions.append(perm_command)

            elif re.search(r'AccessDenied|ForbiddenException|UnauthorizedOperation|UnsupportedCommandException|AuthorizationException', output, re.I):
                if self.debug:
                    print(f"[DEBUG] Access denied for: {full_command}")

            elif re.search(r'ValidationException|ValidationError|InvalidArnException|InvalidRequestException|InvalidParameterValueException|InvalidARNFault|Invalid ARN|InvalidIpamScopeId.Malformed|InvalidParameterException|invalid literal for', output, re.I):
                if self.debug:
                    print(f"[DEBUG] Validation error for: {full_command}")

            elif re.search(r'Could not connect to the endpoint URL', output, re.I):
                if self.debug:
                    print(f"[DEBUG] Could not connect to endpoint: {full_command}")

            elif re.search(r'Unknown options|MissingParameter|InvalidInputException|error: argument', output, re.I):
                if self.debug:
                    print(f"[DEBUG] Option error for: {full_command}")

            elif re.search(r'arguments are required', output, re.I):
                required_arg_match = re.search(r'arguments are required: ([^\s,]+)', output)
                if required_arg_match:
                    required_arg = required_arg_match.group(1)
                    test_value = self.get_test_value_for_argument(service, command, required_arg, region)

                    test_cmd = f"aws --cli-connect-timeout 19 --profile {profile} --region {region} {service} {command} {extra} {required_arg} {test_value}"
                    test_result = subprocess.run(test_cmd, shell=True, capture_output=True, timeout=20)
                    test_output = test_result.stdout.decode() + test_result.stderr.decode()

                    # If the test value fails, try alternative formats
                    if re.search(r'ValidationException|ValidationError|InvalidArnException|InvalidRequestException|InvalidParameterValueException|InvalidARNFault|Invalid ARN|InvalidIpamScopeId.Malformed|InvalidParameterException|invalid literal for', test_output, re.I):
                        alt_value = self.get_alternative_test_value(service, command, required_arg, test_value, region)
                        if alt_value != test_value:
                            extra = f"{extra} {required_arg} {alt_value}"
                        else:
                            extra = f"{extra} {required_arg} {test_value}"
                    else:
                        extra = f"{extra} {required_arg} {test_value}"
                    
                    if cont < 3:
                        self.run_command(profile, region, service, command, extra, cont+1)
                    else:
                        if self.debug:
                            print(f"[DEBUG] Prevented eternal loop of args from: {command}\n{output.strip()}")

            else:
                if self.debug:
                    print(f"[DEBUG] Unhandled response for: {full_command}\n{output.strip()}")

        except subprocess.TimeoutExpired:
            if self.debug:
                print(f"[DEBUG] Command timed out: {full_command}")
            print(f"[-] Timeout: {full_command}")

    def get_aws_services(self):
        output = subprocess.run("aws help | col -b", shell=True, capture_output=True).stdout.decode().splitlines()
        start_string = "SERVICES"
        end_string = "SEE"
        point = "o"
        in_range = False
        services = []

        for line in output:
            line = line.strip()
            if start_string in line:
                in_range = True
            elif end_string in line:
                in_range = False

            if in_range and line and line != point and start_string not in line:
                if line.startswith("o "):
                    line = line[2:]
                services.append(line)

        return services

    def get_commands_for_service(self, service):
        output = subprocess.run(f"aws {service} help | col -b", shell=True, capture_output=True).stdout.decode().splitlines()
        start_string = "COMMANDS"
        end_string = "SEE"
        in_range = False
        commands = []

        for line in output:
            line = line.strip()
            if start_string in line:
                in_range = True
            elif end_string in line:
                in_range = False

            if in_range and line:
                if line.startswith("o "):
                    line = line[2:]
                if re.match(r'^(list|describe|get)', line):
                    commands.append(line)

        return commands

    def brute_force_permissions(self):
        commands_to_run = []
        print(f"{Fore.GREEN}Starting permission enumeration...")
        print(f"{Fore.CYAN}Using account ID: {self.account_id}")
        print(f"{Fore.CYAN}Testing in region: us-east-1 (optimized for permission enumeration)")

        services = self.get_aws_services()

        if self.aws_services:
            filterred_services = [service for service in services if service.lower() in self.aws_services ]
            if not filterred_services:
                print(f"{Fore.RED}No services found to test. Please check your input because you probably misspelled the filtering. Exiting...{Fore.RESET}")
                return
            else:
                print(f"{Fore.YELLOW}Filtered services to bf: {', '.join(filterred_services)}{Fore.RESET}")

        else:
            filterred_services = services

        with ThreadPoolExecutor(max_workers=self.num_threads) as executor:
            future_to_service = {
                executor.submit(self.get_commands_for_service, service): service 
                for service in filterred_services
            }
            pbar = tqdm(total=len(future_to_service), desc="Getting commands to test")
            for future in as_completed(future_to_service):
                pbar.update(1)
                service = future_to_service[future]
                try:
                    commands = future.result(timeout=30)
                    for command in commands:
                        # Test each command across all regions
                        for region in self.regions:
                            commands_to_run.append((self.profile, region, service, command))
                except TimeoutError:
                    if self.debug:
                        print(f"[DEBUG] Timeout getting commands for {service}")
                except Exception as e:
                    if self.debug:
                        print(f"[DEBUG] Failed to get commands for {service}: {e}")
            pbar.close()

        print(f"{Fore.CYAN}Total commands to test: {len(commands_to_run)}{Fore.RESET}")
        
        with ThreadPoolExecutor(max_workers=self.num_threads*4) as executor:
            futures = [executor.submit(self.run_command, *args) for args in commands_to_run]
            pbar = tqdm(total=len(futures), desc="Running commands")
            for future in as_completed(futures):
                pbar.update(1)
            pbar.close()

        print("\n[+] Permission enumeration completed.")
        return self.found_permissions


def main():
    init()
    
    parser = argparse.ArgumentParser(description='AWS Brute Force Permission Enumeration Tool')
    parser.add_argument('-d', '--debug', action='store_true', help='Enable debug output')
    parser.add_argument('-r', '--region', default='us-east-1', help='AWS region (default: us-east-1)')
    parser.add_argument('-p', '--profile', default='default', help='AWS profile (default: default)')
    parser.add_argument('-s', '--services', nargs='*', default=[], help='AWS services to test (default: all services)')
    parser.add_argument('-t', '--threads', type=int, default=10, help='Number of threads (default: 10)')
    
    args = parser.parse_args()
    
    brute_forcer = AWSBruteForce(
        debug=args.debug,
        region=args.region,
        profile=args.profile,
        aws_services=args.services,
        threads=args.threads
    )
    
    permissions = brute_forcer.brute_force_permissions()
    
    if permissions:
        print(f"\n{Fore.GREEN}[+] Found {len(permissions)} permissions:{Fore.RESET}")
        for perm in permissions:
            print(f"    {perm}")
    else:
        print(f"\n{Fore.YELLOW}[-] No permissions found.{Fore.RESET}")


if __name__ == '__main__':
    main()