import boto3
import datetime
import os
import configparser
from botocore.exceptions import EndpointConnectionError, ClientError

def select_aws_profile():
    aws_config_file = os.path.expanduser('~/.aws/config')
    aws_credentials_file = os.path.expanduser('~/.aws/credentials')
    profiles = []

    config = configparser.ConfigParser()
    config.read([aws_config_file, aws_credentials_file])

    for section in config.sections():
        if section.startswith('profile '):
            profiles.append(section.split('profile ')[1])
        else:
            profiles.append(section)

    # Remove duplicates while preserving order
    seen = set()
    profiles_ordered = []
    for profile in profiles:
        if profile not in seen:
            profiles_ordered.append(profile)
            seen.add(profile)

    if not profiles_ordered:
        print("No AWS profiles found. Using default.")
        return None

    print("Available AWS profiles:")
    for idx, profile in enumerate(profiles_ordered):
        print(f"{idx + 1}: {profile}")

    while True:
        choice = input("Select the profile number to use: ")
        if choice.isdigit() and 1 <= int(choice) <= len(profiles_ordered):
            return profiles_ordered[int(choice) - 1]
        else:
            print("Invalid choice. Please try again.")

def collect_endpoints():
    # Select AWS profile
    profile_name = select_aws_profile()
    session = boto3.Session(profile_name=profile_name) if profile_name else boto3.Session()

    external_endpoints = {}
    internal_endpoints = {}

    # Get AWS Account ID
    sts_client = session.client('sts')
    account_id = sts_client.get_caller_identity()['Account']

    # Get current date and time
    current_time = datetime.datetime.now().strftime('%Y-%m-%d_%H-%M-%S')

    # Prepare filename
    filename = f"{account_id}_{current_time}_stratuminfo.txt"

    # Get all AWS regions dynamically
    ec2 = session.client('ec2', region_name='us-east-1')
    regions = [region['RegionName'] for region in ec2.describe_regions()['Regions']]

    # Initialize services list
    services_with_endpoints = [
        'ec2', 'rds', 'elb', 'elbv2', 'elasticache', 'redshift', 'workspaces',
        'apigateway', 'efs', 'opensearch', 'eks', 'lambda', 'sagemaker',
        'iot', 'cloudfront', 'route53', 's3', 'mq', 'neptune', 'glue', 'kafka',
        'dynamodb', 'elasticbeanstalk', 'codebuild', 'codepipeline', 'codedeploy',
        'batch', 'stepfunctions', 'storagegateway', 'medialive', 'mediapackage',
        'mediastore', 'transcribe', 'translate', 'elastictranscoder', 'iotanalytics',
        'iotwireless', 'kinesis', 'kinesisvideo', 'lightsail', 'transfer', 'fsx',
        'globalaccelerator', 'ecs', 'emr', 'directconnect', 'cloudhsm', 'sqs', 'sns'
    ]

    # Initialize endpoint dictionaries
    external_endpoints = {}
    internal_endpoints = {}

    for service in services_with_endpoints:
        external_endpoints[service] = []
        internal_endpoints[service] = []

    # Services that are global (do not require region specification)
    global_services = ['s3', 'cloudfront', 'route53']

    # Collect endpoints for regional services
    for region in regions:
        print(f"Processing region: {region}")
        for service in services_with_endpoints:
            if service in global_services:
                continue  # Skip global services here
            try:
                client = session.client(service, region_name=region)
                if service == 'ec2':
                    # EC2 Instances
                    instances = client.describe_instances()
                    for reservation in instances['Reservations']:
                        for instance in reservation['Instances']:
                            # Private IP
                            if 'PrivateIpAddress' in instance:
                                private_ip = instance['PrivateIpAddress']
                                internal_endpoints['ec2'].append(private_ip)
                            # Public IP
                            if 'PublicIpAddress' in instance:
                                public_ip = instance['PublicIpAddress']
                                external_endpoints['ec2'].append(public_ip)

                elif service == 'rds':
                    # RDS Instances
                    db_instances = client.describe_db_instances()
                    for db_instance in db_instances['DBInstances']:
                        endpoint = db_instance['Endpoint']['Address']
                        publicly_accessible = db_instance['PubliclyAccessible']
                        if publicly_accessible:
                            external_endpoints['rds'].append(endpoint)
                        else:
                            internal_endpoints['rds'].append(endpoint)

                elif service in ['elb', 'elbv2']:
                    # Load Balancers
                    if service == 'elb':
                        load_balancers = client.describe_load_balancers()
                        for lb in load_balancers['LoadBalancerDescriptions']:
                            dns_name = lb['DNSName']
                            scheme = lb['Scheme']
                            if scheme == 'internet-facing':
                                external_endpoints['elb'].append(dns_name)
                            else:
                                internal_endpoints['elb'].append(dns_name)
                    else:
                        load_balancers = client.describe_load_balancers()
                        for lb in load_balancers['LoadBalancers']:
                            dns_name = lb['DNSName']
                            scheme = lb['Scheme']
                            if scheme == 'internet-facing':
                                external_endpoints['elbv2'].append(dns_name)
                            else:
                                internal_endpoints['elbv2'].append(dns_name)

                elif service == 'elasticache':
                    # ElastiCache Clusters
                    clusters = client.describe_cache_clusters(ShowCacheNodeInfo=True)
                    for cluster in clusters['CacheClusters']:
                        if 'ConfigurationEndpoint' in cluster and cluster['ConfigurationEndpoint']:
                            endpoint = cluster['ConfigurationEndpoint']['Address']
                            internal_endpoints['elasticache'].append(endpoint)
                        else:
                            for node in cluster['CacheNodes']:
                                endpoint = node['Endpoint']['Address']
                                internal_endpoints['elasticache'].append(endpoint)

                elif service == 'redshift':
                    # Redshift Clusters
                    clusters = client.describe_clusters()
                    for cluster in clusters['Clusters']:
                        endpoint = cluster['Endpoint']['Address']
                        publicly_accessible = cluster['PubliclyAccessible']
                        if publicly_accessible:
                            external_endpoints['redshift'].append(endpoint)
                        else:
                            internal_endpoints['redshift'].append(endpoint)

                elif service == 'workspaces':
                    # WorkSpaces
                    try:
                        workspaces_info = client.describe_workspaces()
                        for workspace in workspaces_info['Workspaces']:
                            ip_address = workspace.get('IpAddress')
                            if ip_address:
                                internal_endpoints['workspaces'].append(ip_address)
                    except client.exceptions.UnsupportedOperation:
                        print(f"workspaces not available in region {region}. Skipping.")

                elif service == 'apigateway':
                    # API Gateways
                    rest_apis = client.get_rest_apis()
                    for api in rest_apis.get('items', []):
                        api_id = api['id']
                        endpoint = f"{api_id}.execute-api.{region}.amazonaws.com"
                        # Additional checks can be added to determine if the API is private
                        external_endpoints['apigateway'].append(endpoint)

                elif service == 'efs':
                    # EFS
                    file_systems = client.describe_file_systems()
                    for fs in file_systems['FileSystems']:
                        fs_id = fs['FileSystemId']
                        mount_targets = client.describe_mount_targets(FileSystemId=fs_id)
                        for mt in mount_targets['MountTargets']:
                            ip_address = mt['IpAddress']
                            internal_endpoints['efs'].append(ip_address)

                elif service == 'opensearch':
                    # OpenSearch Domains
                    domains = client.list_domain_names()
                    for domain_info in domains['DomainNames']:
                        domain_name = domain_info['DomainName']
                        domain_status = client.describe_domains(DomainNames=[domain_name])
                        for domain in domain_status['DomainStatusList']:
                            endpoint = domain.get('Endpoint')
                            endpoints = domain.get('Endpoints', {})
                            domain_endpoint = endpoint or list(endpoints.values())[0]
                            internal_endpoints['opensearch'].append(domain_endpoint)

                elif service == 'eks':
                    # EKS Clusters
                    clusters = client.list_clusters()
                    for cluster_name in clusters['clusters']:
                        cluster_info = client.describe_cluster(name=cluster_name)['cluster']
                        endpoint = cluster_info['endpoint']
                        if cluster_info['resourcesVpcConfig']['endpointPublicAccess']:
                            external_endpoints['eks'].append(endpoint.replace('https://', ''))
                        else:
                            internal_endpoints['eks'].append(endpoint.replace('https://', ''))

                elif service == 'lambda':
                    # Lambda Functions
                    paginator = client.get_paginator('list_functions')
                    for page in paginator.paginate():
                        for function in page['Functions']:
                            function_name = function['FunctionName']
                            vpc_config = function.get('VpcConfig')
                            if vpc_config and vpc_config.get('VpcId'):
                                internal_endpoints['lambda'].append(function_name)

                elif service == 'sagemaker':
                    # SageMaker Endpoints
                    endpoints = client.list_endpoints()
                    for endpoint in endpoints['Endpoints']:
                        endpoint_name = endpoint['EndpointName']
                        internal_endpoints['sagemaker'].append(endpoint_name)

                elif service == 'iot':
                    # IoT Endpoints
                    endpoints = client.describe_endpoint(endpointType='iot:Data-ATS')
                    endpoint_address = endpoints['endpointAddress']
                    external_endpoints['iot'].append(endpoint_address)

                elif service == 'mq':
                    # Amazon MQ Brokers
                    brokers = client.list_brokers()
                    for broker in brokers['BrokerSummaries']:
                        broker_id = broker['BrokerId']
                        broker_info = client.describe_broker(BrokerId=broker_id)
                        endpoints = broker_info.get('BrokerInstances', [])
                        for endpoint_info in endpoints:
                            endpoint = endpoint_info.get('ConsoleURL')
                            if endpoint:
                                internal_endpoints['mq'].append(endpoint)

                elif service == 'neptune':
                    # Amazon Neptune Clusters
                    clusters = client.describe_db_clusters()
                    for cluster in clusters['DBClusters']:
                        endpoint = cluster['Endpoint']
                        reader_endpoint = cluster.get('ReaderEndpoint')
                        internal_endpoints['neptune'].append(endpoint)
                        if reader_endpoint:
                            internal_endpoints['neptune'].append(reader_endpoint)

                # Add more services as needed with similar patterns

            except EndpointConnectionError:
                print(f"{service} not available in region {region}. Skipping.")
            except ClientError as e:
                code = e.response['Error']['Code']
                if code in ['UnauthorizedOperation', 'AccessDeniedException', 'UnsupportedOperation']:
                    print(f"Access denied or unsupported operation for {service} in region {region}. Skipping.")
                else:
                    print(f"Error processing {service} in region {region}: {e}")
            except Exception as e:
                print(f"Error processing {service} in region {region}: {e}")

    # Collect endpoints for global services
    print("Processing global services")
    for service in global_services:
        try:
            client = session.client(service)
            if service == 's3':
                # S3 Buckets
                buckets = client.list_buckets()
                for bucket in buckets['Buckets']:
                    bucket_name = bucket['Name']
                    endpoint = f"{bucket_name}.s3.amazonaws.com"
                    external_endpoints['s3'].append(endpoint)

            elif service == 'cloudfront':
                # CloudFront Distributions
                paginator = client.get_paginator('list_distributions')
                for page in paginator.paginate():
                    distributions = page.get('DistributionList', {}).get('Items', [])
                    for dist in distributions:
                        domain_name = dist['DomainName']
                        external_endpoints['cloudfront'].append(domain_name)

            elif service == 'route53':
                # Route53 Record Sets
                route53 = client
                hosted_zones = route53.list_hosted_zones()
                for zone in hosted_zones['HostedZones']:
                    zone_id = zone['Id']
                    zone_name = zone['Name'].rstrip('.')
                    is_private = zone['Config'].get('PrivateZone', False)
                    record_sets = []
                    paginator = route53.get_paginator('list_resource_record_sets')
                    for page in paginator.paginate(HostedZoneId=zone_id):
                        for record_set in page['ResourceRecordSets']:
                            if 'ResourceRecords' in record_set:
                                record_name = record_set['Name'].rstrip('.')
                                record_type = record_set['Type']
                                for rr in record_set['ResourceRecords']:
                                    value = rr['Value']
                                    if record_type in ['A', 'CNAME']:
                                        record_info = {
                                            'zone_name': zone_name,
                                            'record_name': record_name,
                                            'value': value,
                                            'type': record_type
                                        }
                                        record_sets.append(record_info)
                    # Classify records based on hosted zone privacy
                    if is_private:
                        internal_endpoints.setdefault('route53', []).append({'zone_name': zone_name, 'records': record_sets})
                    else:
                        external_endpoints.setdefault('route53', []).append({'zone_name': zone_name, 'records': record_sets})

        except ClientError as e:
            code = e.response['Error']['Code']
            if code in ['UnauthorizedOperation', 'AccessDeniedException', 'UnsupportedOperation']:
                print(f"Access denied or unsupported operation for {service}. Skipping.")
            else:
                print(f"Error processing {service}: {e}")
        except Exception as e:
            print(f"Error processing {service}: {e}")

    # Write results to file
    with open(filename, 'w') as file:
        # External endpoints
        for service, endpoints in external_endpoints.items():
            if service != 'route53' and endpoints:
                file.write(f"# {service} (External):\n")
                for endpoint in sorted(set(endpoints)):
                    file.write(f"{endpoint}\n")
                file.write("\n")
            elif service == 'route53' and endpoints:
                for zone in endpoints:
                    zone_name = zone['zone_name']
                    file.write(f"{zone_name} (Public Hosted Zone):\n")
                    for record in zone['records']:
                        record_name = record['record_name']
                        value = record['value']
                        file.write(f"{record_name} {value}\n")
                    file.write("\n")

        # Internal endpoints
        for service, endpoints in internal_endpoints.items():
            if service != 'route53' and endpoints:
                file.write(f"# {service} (Internal):\n")
                for endpoint in sorted(set(endpoints)):
                    file.write(f"{endpoint}\n")
                file.write("\n")
            elif service == 'route53' and endpoints:
                for zone in endpoints:
                    zone_name = zone['zone_name']
                    file.write(f"{zone_name} (Private Hosted Zone):\n")
                    for record in zone['records']:
                        record_name = record['record_name']
                        value = record['value']
                        file.write(f"{record_name} {value}\n")
                    file.write("\n")

    print(f"Endpoint information saved to {filename}")

if __name__ == "__main__":
    collect_endpoints()