"""
  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
  
  Licensed under the Apache License, Version 2.0 (the "License").
  You may not use this file except in compliance with the License.
  You may obtain a copy of the License at
  
      http://www.apache.org/licenses/LICENSE-2.0
  
  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License."""

import boto3
import pandas as pd
import datetime

# Initialize EC2 client
ec2 = boto3.client("ec2")

# Get all available regions
regions = [region["RegionName"] for region in ec2.describe_regions()["Regions"]]

# Uncomment the following two lines to specify the regions you want to analyze
# regions = ['eu-west-1', 'us-west-1']

# Function to get inbound and outbound rules for a security group
def get_rules(sg, region):
    ec2r = boto3.resource("ec2", region)
    sgs = ec2r.security_groups.filter(
        GroupIds=[
            sg,
        ]
    )
    sgs = list(sgs.pages())
    if not sgs or not sgs[0]:
        return (None, None)
    sg = sgs[0][0]
    sg_inbound = sg.ip_permissions
    sg_outbound = sg.ip_permissions_egress
    return sg_inbound, sg_outbound

# Function to get security groups for a resource
def get_sgs(resource, resource_type):
    if resource_type == "instance":
        sgs = resource.security_groups
    elif resource_type == "load_balancer":
        sgs = [{"GroupId": sg} for sg in resource["SecurityGroups"]]
    elif resource_type == "endpoint":
        sgs = [{"GroupId": sg["GroupId"]} for sg in resource["Groups"]]
    return sgs

# Function to get a resource name
def get_name(resource, resource_type):
    if resource_type == "instance" and resource.tags:
        for tag in resource.tags:
            if tag["Key"] == "Name":
                return tag["Value"]
    elif resource_type == "load_balancer":
        return resource["LoadBalancerName"]
    elif resource_type == "endpoint":
        return resource["VpcEndpointId"]
    return "None"

# Function to get security group name
def get_sg_name(sg_id, region):
    ec2r = boto3.resource("ec2", region)
    sg = ec2r.SecurityGroup(sg_id)
    return sg.group_name

# Main function
def main():
    table = []
    columns = [
        "Resource Type",
        "Region",
        "Resource Name",
        "Resource-ID",
        "SG-Name",
        "SG-ID",
        "Direction",
        "Source",
        "Destination",
        "Protocol",
        "Ports",
    ]
    df = pd.DataFrame(table, columns=columns)
    print("Collecting Security Groups information from every region....")

    for region in regions:
        ec2r = boto3.resource("ec2", region)
        elbv2 = boto3.client("elbv2", region)
        instances = list(ec2r.instances.all())
        load_balancers = elbv2.describe_load_balancers()["LoadBalancers"]
        endpoints = ec2r.meta.client.describe_vpc_endpoints()["VpcEndpoints"]

        resources = [
            {"type": "instance", "data": instances},
            {"type": "load_balancer", "data": load_balancers},
            {"type": "endpoint", "data": endpoints},
        ]

        for resource_type in resources:
            for resource_data in resource_type["data"]:
                if resource_type["type"] == "instance":
                    resource_id = resource_data.id
                    resource_name = get_name(resource_data, "instance")
                elif resource_type["type"] == "load_balancer":
                    resource_id = resource_data["LoadBalancerArn"]
                    resource_name = get_name(resource_data, "load_balancer")
                elif resource_type["type"] == "endpoint":
                    resource_id = resource_data["VpcEndpointId"]
                    resource_name = get_name(resource_data, "endpoint")

                sgs = get_sgs(resource_data, resource_type["type"])

                for sg in sgs:
                    sg_id = sg["GroupId"]
                    sg_name = get_sg_name(sg_id, region)
                    rules_inbound, rules_outbound = get_rules(sg_id, region)

                    # Process inbound rules and append to DataFrame
                    for rule in rules_inbound:
                        for ip_range in rule["IpRanges"]:
                            row = {
                                "Resource Type": resource_type["type"],
                                "Region": region,
                                "Resource Name": resource_name,
                                "Resource-ID": resource_id,
                                "SG-Name": sg_name,
                                "SG-ID": sg_id,
                                "Direction": "Inbound",
                                "Source": ip_range["CidrIp"],
                                "Destination": "",
                                "Protocol": rule["IpProtocol"],
                                "Ports": rule["FromPort"] if "FromPort" in rule else "N/A",
                            }
                            row_df = pd.DataFrame([row], columns=columns)
                            df = pd.concat([df, row_df], ignore_index=True)

                    # Process outbound rules and append to DataFrame
                    for rule in rules_outbound:
                        for ip_range in rule["IpRanges"]:
                            row = {
                                "Resource Type": resource_type["type"],
                                "Region": region,
                                "Resource Name": resource_name,
                                "Resource-ID": resource_id,
                                "SG-Name": sg_name,
                                "SG-ID": sg_id,
                                "Direction": "Outbound",
                                "Source": "",
                                "Destination": ip_range["CidrIp"],
                                "Protocol": rule["IpProtocol"],
                                "Ports": rule["FromPort"] if "FromPort" in rule else "N/A",
                            }
                            row_df = pd.DataFrame([row], columns=columns)
                            df = pd.concat([df, row_df], ignore_index=True)

    # Save DataFrame to Excel file
    time = datetime.datetime.now().strftime("%H-%M-%S_%d-%m-%Y")
    file_name = "fw_policy-report-" + time + ".xlsx"
    print(file_name + " has been created")
    df.to_excel(file_name)

if __name__ == "__main__":
    main()
