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

ec2 = boto3.client("ec2")
# run for every region
regions = [region["RegionName"] for region in ec2.describe_regions()["Regions"]]
# specify regions
# regions = ['eu-west-1','us-west-1]

# Get rules from SG


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


# Get available SGs
def get_sgs(instance):
    sgs = instance.security_groups
    return sgs


# Get instance name
def get_name(instance):
    if instance.tags:
        for tag in instance.tags:
            if tag["Key"] == "Name":
                return tag["Value"]
    else:
        return "None"


def main():
    table = []
    columns = [
        "Region",
        "Instance Name",
        "Instance-ID",
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
        for instance in ec2r.instances.all():
            inst_id = instance.id  # get instance id
            sgs = get_sgs(instance)  # gets sg from instance
            inst_name = get_name(instance)  # gets the instance name
            for sg in sgs:
                sg_id = sg["GroupId"]
                sg_name = sg["GroupName"]
                rules_inbound = get_rules(sg_id, region)[0]
                rules_outbound = get_rules(sg_id, region)[1]
                for rule in rules_inbound:
                    rule_destination = inst_id
                    from_cidr = []
                    direction = "Inbound"
                    from_port_range = rule.get("FromPort", "any")
                    to_port_range = rule.get("ToPort", "any")
                    if from_port_range == to_port_range:
                        ports = from_port_range
                    else:
                        ports = str(from_port_range) + " - " + str(to_port_range)
                    if from_port_range == -1:
                        ports = "any"
                    protocol = rule["IpProtocol"]
                    if protocol == "-1":
                        protocol = "any"
                    for cidr in rule.get("IpRanges", []):
                        from_cidr.append(cidr["CidrIp"])
                    for cidrv6 in rule.get("Ipv6Ranges", []):
                        from_cidr.append(cidrv6["CidrIpv6"])
                    for source_sg in rule.get("UserIdGroupPairs", []):
                        from_cidr.append(source_sg["GroupId"])
                    for source_sg in rule.get("PrefixListIds", []):
                        from_cidr.append(source_sg["PrefixListId"])
                    if not from_cidr:
                        from_cidr.append("0.0.0.0/0")

                    df = df.append(
                        {
                            "Region": region,
                            "Instance Name": inst_name,
                            "Instance-ID": inst_id,
                            "SG-Name": sg_name,
                            "SG-ID": sg_id,
                            "Direction": direction,
                            "Source": from_cidr,
                            "Destination": rule_destination,
                            "Protocol": protocol,
                            "Ports": ports,
                        },
                        ignore_index=True,
                    )
                for rule in rules_outbound:
                    rule_source = inst_id
                    to_cidr = []
                    direction = "Outbound"
                    protocol = rule["IpProtocol"]
                    from_port_range = rule.get("FromPort", "any")
                    to_port_range = rule.get("ToPort", "any")
                    if from_port_range == to_port_range:
                        ports = from_port_range
                    else:
                        ports = str(from_port_range) + " - " + str(to_port_range)
                    if from_port_range == -1:
                        ports = "any"
                    protocol = rule["IpProtocol"]
                    if protocol == "-1":
                        protocol = "any"
                    for cidr in rule.get("IpRanges", []):
                        to_cidr.append(cidr["CidrIp"])
                    for cidrv6 in rule.get("Ipv6Ranges", []):
                        to_cidr.append(cidrv6["CidrIpv6"])
                    for source_sg in rule.get("UserIdGroupPairs", []):
                        to_cidr.append(source_sg["GroupId"])
                    for source_sg in rule.get("PrefixListIds", []):
                        to_cidr.append(source_sg["PrefixListId"])
                    if not to_cidr:
                        to_cidr.append("0.0.0.0/0")
                    df = df.append(
                        {
                            "Region": region,
                            "Instance Name": inst_name,
                            "Instance-ID": inst_id,
                            "SG-Name": sg_name,
                            "SG-ID": sg_id,
                            "Direction": direction,
                            "Source": rule_source,
                            "Destination": to_cidr,
                            "Protocol": protocol,
                            "Ports": ports,
                        },
                        ignore_index=True,
                    )
    time = datetime.datetime.now().strftime("%H-%M-%S_%d-%m-%Y")
    file_name = "fw_policy-report-" + time + ".xlsx"
    print(file_name + " has been created")
    return df.to_excel(file_name)


if __name__ == "__main__":
    main()