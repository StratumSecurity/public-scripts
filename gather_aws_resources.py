#!/usr/bin/env python3

import boto3
import os
import sys
import json
import csv
import configparser
from getpass import getpass
import argparse
import re
from datetime import datetime

def get_aws_profiles():
    profiles = []
    config = configparser.ConfigParser()
    aws_credentials_file = os.path.expanduser('~/.aws/credentials')
    if os.path.exists(aws_credentials_file):
        config.read(aws_credentials_file)
        profiles = config.sections()
    return profiles

def choose_profile(profiles):
    print("Multiple AWS profiles found:")
    for idx, profile in enumerate(profiles):
        print(f"{idx + 1}: {profile}")
    while True:
        choice = input("Select a profile by number: ")
        try:
            idx = int(choice) - 1
            if 0 <= idx < len(profiles):
                return profiles[idx]
        except ValueError:
            pass
        print("Invalid selection. Please try again.")

def get_credentials():
    access_key = input("Enter your AWS Access Key ID: ")
    secret_key = getpass("Enter your AWS Secret Access Key: ")
    return access_key, secret_key

def get_default_region(profile_name):
    config = configparser.ConfigParser()
    aws_config_file = os.path.expanduser('~/.aws/config')
    if os.path.exists(aws_config_file):
        config.read(aws_config_file)
        profile_key = f'profile {profile_name}' if profile_name != 'default' else 'default'
        if profile_key in config and 'region' in config[profile_key]:
            return config[profile_key]['region']
    return 'us-east-1'  # Default region if none found

def get_all_regions(session):
    ec2 = session.client('ec2')
    regions = [region['RegionName'] for region in ec2.describe_regions()['Regions']]
    return regions

def count_global_resources(session, service_counts, verbose, exclusion_patterns):
    print("Scanning global services...")

    # IAM is global
    try:
        iam_counts = count_iam_resources(session, verbose, exclusion_patterns)
        if iam_counts:
            service_counts.append({
                'Region': 'global',
                'Service': 'iam_users',
                'ResourceCount': iam_counts['Users']
            })
            service_counts.append({
                'Region': 'global',
                'Service': 'iam_roles',
                'ResourceCount': iam_counts['Roles']
            })
            service_counts.append({
                'Region': 'global',
                'Service': 'iam_policies',
                'ResourceCount': iam_counts['Policies']
            })
            print(f"IAM resources: {iam_counts}")
    except Exception as e:
        print(f"Error scanning IAM: {str(e)}")

    # S3 Buckets
    try:
        s3_bucket_counts = count_s3_buckets(session, verbose, exclusion_patterns)
        for region, data in s3_bucket_counts.items():
            service_counts.append({
                'Region': region,
                'Service': 's3',
                'ResourceCount': data['Count']
            })
            print(f"Found {data['Count']} S3 bucket(s) in {region}")
            if verbose:
                for bucket_name in data['Buckets']:
                    print(f"  - {bucket_name}")
    except Exception as e:
        print(f"Error scanning S3 buckets: {str(e)}")

    # Route53 Hosted Zones
    try:
        route53_counts = count_route53_hosted_zones(session, verbose, exclusion_patterns)
        for zone in route53_counts:
            service_counts.append({
                'Region': 'global',
                'Service': 'route53_hosted_zone',
                'ResourceCount': 1
            })
            print(f"Found Route53 Hosted Zone: {zone['Name']}")
            if verbose:
                for record in zone['Records']:
                    print(f"  - Record: {record}")
    except Exception as e:
        print(f"Error scanning Route53 Hosted Zones: {str(e)}")

def count_resources(session, region, service_counts, verbose, exclusion_patterns):
    print(f"Scanning region: {region}")
    services = {
        'ec2': count_ec2_instances,
        'eks': count_eks_clusters,
        'ecs': count_ecs_clusters,
        'lambda': count_lambda_functions,
        'rds': count_rds_instances,
        'dynamodb': count_dynamodb_tables,
        'cloudformation': count_cf_stacks,
        # Add more services and their counting functions as needed
    }
    for service_name, count_function in services.items():
        try:
            result = count_function(session, region, verbose, exclusion_patterns)
            count = result['Count']
            if count > 0:
                service_counts.append({
                    'Region': region,
                    'Service': service_name,
                    'ResourceCount': count
                })
                print(f"Found {count} {service_name} resource(s) in {region}")
                if verbose:
                    for resource_id in result['Resources']:
                        print(f"  - {resource_id}")
        except Exception as e:
            print(f"Error scanning {service_name} in {region}: {str(e)}")

def matches_exclusion(resource_name, exclusion_patterns):
    for pattern in exclusion_patterns:
        if pattern.match(resource_name):
            return True
    return False

def count_s3_buckets(session, verbose, exclusion_patterns):
    s3 = session.client('s3')
    buckets = s3.list_buckets()
    bucket_counts = {}
    print("Determining S3 bucket regions...")
    for bucket in buckets['Buckets']:
        bucket_name = bucket['Name']
        if matches_exclusion(bucket_name, exclusion_patterns):
            continue
        try:
            bucket_location = s3.get_bucket_location(Bucket=bucket_name)['LocationConstraint']
            # Handle the case where the location is None (which means us-east-1)
            if bucket_location is None:
                bucket_location = 'us-east-1'
            elif bucket_location == 'EU':
                bucket_location = 'eu-west-1'
            if bucket_location not in bucket_counts:
                bucket_counts[bucket_location] = {'Count': 0, 'Buckets': []}
            bucket_counts[bucket_location]['Count'] += 1
            bucket_counts[bucket_location]['Buckets'].append(bucket_name)
        except Exception as e:
            print(f"Error getting location for bucket {bucket_name}: {str(e)}")
    return bucket_counts

def count_ec2_instances(session, region, verbose, exclusion_patterns):
    ec2 = session.client('ec2', region_name=region)
    paginator = ec2.get_paginator('describe_instances')
    count = 0
    resources = []
    for page in paginator.paginate():
        for reservation in page['Reservations']:
            instances = reservation['Instances']
            for instance in instances:
                instance_id = instance['InstanceId']
                if matches_exclusion(instance_id, exclusion_patterns):
                    continue
                count += 1
                if verbose:
                    resources.append(instance_id)
    return {'Count': count, 'Resources': resources}

def count_eks_clusters(session, region, verbose, exclusion_patterns):
    eks = session.client('eks', region_name=region)
    clusters = eks.list_clusters()
    filtered_clusters = [c for c in clusters['clusters'] if not matches_exclusion(c, exclusion_patterns)]
    return {'Count': len(filtered_clusters), 'Resources': filtered_clusters if verbose else []}

def count_iam_resources(session, verbose, exclusion_patterns):
    iam = session.client('iam')
    users = iam.list_users()
    roles = iam.list_roles()
    policies = iam.list_policies(Scope='Local')

    filtered_users = [u for u in users['Users'] if not matches_exclusion(u['UserName'], exclusion_patterns)]
    filtered_roles = [r for r in roles['Roles'] if not matches_exclusion(r['RoleName'], exclusion_patterns)]
    filtered_policies = [p for p in policies['Policies'] if not matches_exclusion(p['PolicyName'], exclusion_patterns)]

    if verbose:
        print("IAM Users:")
        for user in filtered_users:
            print(f"  - {user['UserName']}")
        print("IAM Roles:")
        for role in filtered_roles:
            print(f"  - {role['RoleName']}")
        print("IAM Policies:")
        for policy in filtered_policies:
            print(f"  - {policy['PolicyName']}")
    return {
        'Users': len(filtered_users),
        'Roles': len(filtered_roles),
        'Policies': len(filtered_policies)
    }

def count_ecs_clusters(session, region, verbose, exclusion_patterns):
    ecs = session.client('ecs', region_name=region)
    clusters = ecs.list_clusters()
    filtered_clusters = [arn for arn in clusters['clusterArns'] if not matches_exclusion(arn, exclusion_patterns)]
    return {'Count': len(filtered_clusters), 'Resources': filtered_clusters if verbose else []}

def count_lambda_functions(session, region, verbose, exclusion_patterns):
    lambda_client = session.client('lambda', region_name=region)
    paginator = lambda_client.get_paginator('list_functions')
    count = 0
    resources = []
    for page in paginator.paginate():
        functions = page['Functions']
        for function in functions:
            function_name = function['FunctionName']
            if matches_exclusion(function_name, exclusion_patterns):
                continue
            count += 1
            if verbose:
                resources.append(function_name)
    return {'Count': count, 'Resources': resources}

def count_rds_instances(session, region, verbose, exclusion_patterns):
    rds = session.client('rds', region_name=region)
    paginator = rds.get_paginator('describe_db_instances')
    count = 0
    resources = []
    for page in paginator.paginate():
        instances = page['DBInstances']
        for instance in instances:
            instance_id = instance['DBInstanceIdentifier']
            if matches_exclusion(instance_id, exclusion_patterns):
                continue
            count += 1
            if verbose:
                resources.append(instance_id)
    return {'Count': count, 'Resources': resources}

def count_dynamodb_tables(session, region, verbose, exclusion_patterns):
    dynamodb = session.client('dynamodb', region_name=region)
    paginator = dynamodb.get_paginator('list_tables')
    count = 0
    resources = []
    for page in paginator.paginate():
        tables = page['TableNames']
        for table_name in tables:
            if matches_exclusion(table_name, exclusion_patterns):
                continue
            count += 1
            if verbose:
                resources.append(table_name)
    return {'Count': count, 'Resources': resources}

def count_cf_stacks(session, region, verbose, exclusion_patterns):
    cf = session.client('cloudformation', region_name=region)
    paginator = cf.get_paginator('list_stacks')
    count = 0
    resources = []
    for page in paginator.paginate(StackStatusFilter=['CREATE_COMPLETE', 'UPDATE_COMPLETE']):
        stacks = page['StackSummaries']
        for stack in stacks:
            stack_name = stack['StackName']
            if matches_exclusion(stack_name, exclusion_patterns):
                continue
            count += 1
            if verbose:
                resources.append(stack_name)
    return {'Count': count, 'Resources': resources}

def count_route53_hosted_zones(session, verbose, exclusion_patterns):
    route53 = session.client('route53')
    paginator = route53.get_paginator('list_hosted_zones')
    hosted_zones = []
    for page in paginator.paginate():
        for zone in page['HostedZones']:
            zone_name = zone['Name'].rstrip('.')
            if matches_exclusion(zone_name, exclusion_patterns):
                continue
            records = list_route53_records(route53, zone['Id'], verbose, exclusion_patterns)
            hosted_zones.append({
                'Name': zone_name,
                'Records': records
            })
    return hosted_zones

def list_route53_records(route53, hosted_zone_id, verbose, exclusion_patterns):
    paginator = route53.get_paginator('list_resource_record_sets')
    records = []
    for page in paginator.paginate(HostedZoneId=hosted_zone_id):
        for record in page['ResourceRecordSets']:
            record_name = record['Name'].rstrip('.')
            if matches_exclusion(record_name, exclusion_patterns):
                continue
            records.append(record_name)
            if verbose:
                print(f"    Record: {record_name}")
    return records

def save_results(service_counts, account_id):
    # Get current date and time
    now = datetime.now()
    timestamp = now.strftime('%Y%m%d-%H%M%S')

    # Construct filename base
    filename_base = f"{account_id}-{timestamp}-stratumscope"

    # Save to CSV
    with open(f'{filename_base}.csv', 'w', newline='') as csvfile:
        fieldnames = ['Region', 'Service', 'ResourceCount']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for entry in service_counts:
            writer.writerow(entry)

    # Save to JSON
    with open(f'{filename_base}.json', 'w') as jsonfile:
        json.dump(service_counts, jsonfile, indent=4)

    # Save to TXT (tab-separated)
    with open(f'{filename_base}.txt', 'w') as txtfile:
        writer = csv.writer(txtfile, delimiter='\t')
        writer.writerow(['Region', 'Service', 'ResourceCount'])
        for entry in service_counts:
            writer.writerow([entry['Region'], entry['Service'], entry['ResourceCount']])

    print(f"Results saved to {filename_base}.[csv|json|txt]")

def save_route53_data(route53_data, account_id):
    # Get current date and time
    now = datetime.now()
    timestamp = now.strftime('%Y%m%d-%H%M%S')

    # Construct filename base
    filename_base = f"{account_id}-{timestamp}-route53"

    # Save to TXT
    with open(f'{filename_base}.txt', 'w') as txtfile:
        for zone in route53_data:
            txtfile.write(f"Hosted Zone: {zone['Name']}\n")
            for record in zone['Records']:
                txtfile.write(f"  - Record: {record}\n")
            txtfile.write("\n")  # Add a newline between zones

    print(f"Route53 data saved to {filename_base}.txt")

def main():
    parser = argparse.ArgumentParser(description='AWS Resource Scanner')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output')
    parser.add_argument('--route53', action='store_true', help='Save Route53 data to a .txt file')
    args = parser.parse_args()

    verbose = args.verbose
    save_route53 = args.route53

    # Default exclusion patterns
    default_exclusions = [
        '^StackSet-config-rules.*',
        '^StackSet-auditing-configuration.*',
        '^StackSet-guardduty-member.*',
        # Add more patterns as needed
    ]

    # Precompile regex patterns for performance
    exclusion_patterns = [re.compile(pattern) for pattern in default_exclusions]

    profiles = get_aws_profiles()
    if profiles:
        if len(profiles) > 1:
            profile_name = choose_profile(profiles)
        else:
            profile_name = profiles[0]
        default_region = get_default_region(profile_name)
        session = boto3.Session(profile_name=profile_name, region_name=default_region)
        print(f"Using profile '{profile_name}' with region '{default_region}'")
    else:
        access_key, secret_key = get_credentials()
        session = boto3.Session(
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key,
            region_name='us-east-1'  # Default region if none found
        )
        print("Using provided AWS credentials with default region 'us-east-1'")

    # Retrieve AWS account ID
    sts = session.client('sts')
    try:
        account_id = sts.get_caller_identity()['Account']
    except Exception as e:
        print(f"Error retrieving AWS account ID: {str(e)}")
        sys.exit(1)

    regions = get_all_regions(session)

    service_counts = []
    route53_data = []

    # Count global resources
    count_global_resources(session, service_counts, verbose, exclusion_patterns)

    # Collect Route53 data if --route53 is specified
    if save_route53:
        route53 = session.client('route53')
        try:
            route53_counts = count_route53_hosted_zones(session, verbose, exclusion_patterns)
            route53_data.extend(route53_counts)
        except Exception as e:
            print(f"Error collecting Route53 data: {str(e)}")

    # Count regional resources
    for region in regions:
        count_resources(session, region, service_counts, verbose, exclusion_patterns)

    save_results(service_counts, account_id)

    # Save Route53 data if --route53 flag is used
    if save_route53:
        save_route53_data(route53_data, account_id)

    print("Scanning complete.")

if __name__ == "__main__":
    main()