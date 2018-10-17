#!/usr/bin/env python3
#@AB feel free to use it however you wish!

import boto3
import botocore
#import ysecure
import re
#from ruamel.yaml import YAML
import os,sys,yaml

#This function can be replaces with something that can load the aws configuration values in order to connect with AWS.
def assign_resource(service_name,region):
	resource = boto3.resource(
			service_name,
			region,
					aws_access_key_id= get_ykeykey_key('key_name'),
					aws_secret_access_key= get_ykeykey_key('secret_name'),
		)
	return resource

#This function can be replaces with something that can load the aws configuration values in order to connect with AWS.
def assign_client(service_name,region):
	client = boto3.client(
			service_name,
						region,
						aws_access_key_id= get_ykeykey_key('key_name'),
						aws_secret_access_key= get_ykeykey_key('secret_name'),
				)
	return client

def ec2_describe_instances(region):
	"""This uses a filter to look at the running ec2 instances in a specific region and adds the ec2 attributes into a dict.
	Parameters:
		region: This is the AWS region that the script would run against.
	Returns:
		ec2: ec2 resource passed to enable ec2 calls for other modules.
		instance_list: A dict of instances containing instance id as a key and the attributes as values.
	"""
	instance_list= {}
	ec2_list = [] 

       
	ec2 = assign_resource('ec2',region)
	#instances = ec2.instances.filter(Filters=[{'Name': 'instance-state-name', 'Values': ['running']}])
	for instance in ec2.instances.all():
                ec2_list.append(instance.id)
        

	for id in ec2_list:
		instance = ec2.Instance(id)
		security_groups = []
		instance_list[id] = {'subnet_id': instance.subnet_id,'key': instance.key_name,'image_id': instance.image_id,'security_groups': instance.security_groups, 'vpc_id': instance.vpc_id, 'instance_type': instance.instance_type, 'public_ip': instance.public_ip_address, 'ebs_volumes': instance.block_device_mappings}

	return ec2,instance_list


def volume_list(ec2,instance_list):
	"""This retrieves volumes for all the instances and stores the instance id and volume id in a dict
		Parameters:
				ec2: That is just the resource passed over from ec2_describe_instances function
				instance_list: instance_list: List of all the running ec2 instances
		Returns:
				volume_dict: A dict containing instance_id as key and volume id's as values
	"""
	volume_dict = {}
	volume_list = []

	for volume in ec2.volumes.all():
		volume_list.append(volume.id)


	for item in instance_list.keys():
		for volume in instance_list[item]['ebs_volumes']:
			if volume['Ebs']['VolumeId'] in volume_list:
				volume_dict.setdefault(item, []).append(volume['Ebs']['VolumeId'])
	return volume_list,volume_dict

def create_snapshot(ec2,volume_list,volume_dict):

	snapshot_dict = {}
	for id in volume_list:
		try:
			volume = ec2.Volume(id)
			description = 'Snapshot being created for Volume' +volume.id
			snapshot = ec2.create_snapshot(VolumeId = volume.id, Description = description)
			snapshot_dict[volume.id] = snapshot.snapshot_id
		except botocore.exceptions.ClientError as e:
			print('The snapshot operation failed due to:', e.reason)

	return snapshot_dict   


#def volume_info(ec2,volume_dict,snapshot_dict):
def volume_info(ec2,volume_dict):
	"""This takes the volume dictionary and for each volume id it collects details on each of those volumes.
		Parameters:
			ec2: ec2 resource passed to enable ec2 calls for other modules.
			volume_dict: A volume dictionary containing instance id's as keys and corresponding volume id's as values.
		Returns:
			volume_info_dict: This returns a dictionary containing volume id as a key and it's attributes as values.
			volume_info_dict_file: This passes the volume dictionary to create a corresponding yaml file.
		"""

	volume_info_dict = {}
	for key,value in volume_dict.items():
		for volume_id in value:
			try:
				volume = ec2.Volume(volume_id)
				#snapshot_id = snapshot_dict[volume_id]
				for item in volume.attachments:
					device = item['Device']
					delete_on_termination = item['DeleteOnTermination']
				#volume_info_dict[volume_id] = {'instance':key, 'device_name':device,'delete_on_termination': delete_on_termination, 'zone':volume.availability_zone, 'volume_size':volume.size, 'iops':volume.iops, 'encrypted':volume.encrypted, 'volume_type': volume.volume_type, 'snapshot': snapshot_id}
				volume_info_dict[volume_id] = {'instance':key, 'device_name':device,'delete_on_termination': delete_on_termination, 'zone':volume.availability_zone, 'volume_size':volume.size, 'iops':volume.iops, 'encrypted':volume.encrypted, 'volume_type': volume.volume_type, 'tags': volume.tags}
				if volume_info_dict[volume_id]['tags']:
					volume_info_dict = tags_dict(volume_info_dict, 'tags', volume_id)
				else:
					volume_info_dict[volume_id]['tags'] = {}
			except botocore.exceptions.ClientError as e:
				print('The volume operation failed due to:', e.reason)

	volume_info_dict_file = {'volume_dict': volume_info_dict}	
	return volume_info_dict,volume_info_dict_file

def ec2_info(ec2,region, volume_dict, volume_info_dict):
	"""For each of the running ec2 instances it retrieves the additional attributes linked to each instance such as key_name, image, instance_type etc.
	   Parameters:
	      ec2: ec2 resource passed to enable ec2 calls for other modules.
	      region: This is the AWS region that the script would run against.
	      volume_dict: A volume dictionary containing instance id's as keys and corresponding volume id's as values.
	      volume_info_dict: A dictionary containing volume id as a key and it's attributes as values.
	   Returns:
	   	   ec2_info_dict: A dictionary of the ec2 instance attributes using instance_id as the key and attributes such as key_name, image, security_group etc. as values.
	"""


	ec2_info_dict = {}
	ec2_list = []

	for instance in ec2.instances.all():
                ec2_list.append(instance.id)
 

	for id in ec2_list:
		instance = ec2.Instance(id)
		for sec_group in instance.security_groups:
			for key,value in sec_group.items():
				if key == 'GroupId':
					security_group_id = value
		
		if instance.id in volume_dict.keys():
			volume_list = volume_dict[instance.id]
			volume_info = []
			for id in volume_list:
				volume = ec2.Volume(id)
				if volume.attachments:
					print(volume.attachments)
					for item in volume.attachments:
 						volume = {'device_name': item['Device'], 'delete_on_termination': item['DeleteOnTermination'], 'encrypted': volume.encrypted, 'volume_type': volume.volume_type, 'iops': volume.iops}
					volume_info.append(volume)
			ec2_info_dict[instance.id] = {'vpc_subnet_id': instance.subnet_id, 'key_name': instance.key_name,'image': instance.image_id, 'security_group': security_group_id,'instance_type': instance.instance_type,'volumes': volume_info}
		else:
			ec2_info_dict[instance.id] = {'vpc_subnet_id': instance.subnet_id, 'key_name': instance.key_name,'image': instance.image_id, 'security_group': security_group_id,'instance_type': instance.instance_type}
	ec2_info_dict = {'ec2_dict': ec2_info_dict}
	return ec2_info_dict


def subnet_list(ec2,instance_list):
	"""This grabs all of the subnets that are linked to the running instances
		Parameters:
			ec2: That is just the resource passed over from ec2_describe_instances function
			instance_list: instance_list: List of all the running ec2 instances
		Returns:
			subnet_list: Is a list containing the subnet ids
			subnets: That is a dict containing additional information about the subnets
	"""
	subnet_info = {}
	subnet_ids = []

	for subnet in ec2.subnets.all():
		subnet_ids.append(subnet.id)

	#print(subnet_ids)

	for id in subnet_ids:
		try:
			subnet = ec2.Subnet(id)
			subnet_info[id] = {'vpc_id': subnet.vpc_id,'az': subnet.availability_zone,'cidr': subnet.cidr_block,'map_public': subnet.map_public_ip_on_launch,'resource_tags': subnet.tags}
			if subnet_info[id]['resource_tags']:
				subnet_info = tags_dict(subnet_info, 'resource_tags', id)
			else:
				subnet_info[id]['resource_tags'] = {}
		except botocore.exceptions.ClientError as e:
			print('The subnet operation failed due to:', e.reason)
	subnet_info = {'subnet_dict': subnet_info}
	return subnet_ids,subnet_info


def route_table_info(ec2, instance_list, subnet_list):
	"""This grabs all of the route tables that are linked to the running instances
		Parameters:
			ec2: That is just the resource passed over from ec2_describe_instances function
			instance_list: instance_list: List of all the running ec2 instances
			subnet_list: List of subnet_ids that are linked to the running ec2 instances
		Returns:
			subnet_route_table: Is a dict where the keys are the subnet id and value is the route table id
			routes: That is a dict containing additional information about the route tables
		"""
	#subnet_route_table = {}
	route_info = {}
	route_ids = [] 
	#nat_gateway = []

	for route in ec2.route_tables.all():
		route_ids.append(route.id)

	for id in route_ids:
		try:	
			route_table = ec2.RouteTable(id)
			subnet_ids = []
			for subnet in route_table.associations_attribute:
				if 'SubnetId' in subnet.keys():
					subnet_ids.append(subnet['SubnetId'])
			mapping = {'DestinationCidrBlock':'dest','GatewayId':'gateway_id','NatGatewayId':'gateway_id'}
			#Adding additional function to handle the re-mapping for the item.routes_attribute
			routes_attribute = remap_dict(mapping,route_table.routes_attribute)
			route_info[id] = {'vpc_id': route_table.vpc_id,'subnets': subnet_ids,'routes': routes_attribute, 'tags': route_table.tags}
			if route_info[id]['tags']:
					route_info = tags_dict(route_info, 'tags', id)
			else:
				route_info[id]['tags'] = {'Name': id}
		except botocore.exceptions.ClientError as e:
			print('The route table operation failed due to:', e.reason)
	route_info = {'route_dict': route_info}
	return route_info


def remap_dict(dict_map,orig_dict):
	"""This function is used to change the key:value mapping for a dict to match the Ansible mapping

	Parameters:
		dict_map: This is the new mapping
		orig_dict: Existing dict name that will have it's mapping changed

	Returns:
		new_list: A new list containing the new_dict is returned

	"""
	new_list = []
	for item in orig_dict:
		new_dict = {}
		for key in dict_map.keys():
			if key in item.keys():
				value = dict_map[key]
				new_dict[value] = item[key]
		new_list.append(new_dict)
	return new_list


def network_acl(ec2,subnet_list):
	'''This grabs all of the network acls that are linked to the running instances
		Parameters:
			ec2: That is just the resource passed over from ec2_describe_instances function
			subnet_list: List of subnet_ids that are linked to the running ec2 instances
		Returns:
			acl_subnet: Is a dict where the keys are the subnet id and value is the acl id
			acls: That is a dict containing additional information about the acls
	'''
	acls = {}
	acl_subnet = {}
	protocols = {'-1':'ALL','6':'TCP','17':'UDP','1':'ICMP'}
	for subnet in subnet_list:
		try:
			network_acl = ec2.network_acls.filter(Filters=[{'Name': 'association.subnet-id', 'Values': [subnet]}])
			for item in network_acl:
				subnet_ids = []
				for x in item.associations:
					subnet_ids.append(x['SubnetId'])
				acl_subnet[subnet] = item.id
				egress,ingress = nacl_info(item.entries)
				acls[item.id] = {'vpc_id': item.vpc_id, 'nacl_id': item.network_acl_id, 'egress': egress, 'ingress': ingress, 'subnets': subnet_ids, 'tags': item.tags}
				if acls[item.id]['tags']:
					acls = tags_dict(acls, 'tags', item.id)
				else:
					acls[item.id]['tags'] = {"Name": acls[item.id]['nacl_id']}
		except botocore.exceptions.ClientError as e:
			print('The acl operation failed due to:', e.reason)
	acls = {'acl_dict': acls}
	return acl_subnet,acls


def nacl_info(entries):
	ingress = []
	egress = []
	protocols = {'-1':'all','6':'tcp','17':'udp','1':'icmp'}
	for item in entries:
		protocol = item['Protocol']
		#Are we supporting ICMP if so then need to additional function for that
		if protocols[protocol] == 'all':
			from_port = None
			to_port = None
		else:
			from_port = item['PortRange']['From']
			to_port = item['PortRange']['To']
		if item['RuleNumber'] != 32767:
			e_list = [item['RuleNumber'],protocols[protocol],item['RuleAction'],item['CidrBlock'],None,None,from_port,to_port] 
		else:
			continue
		if item['Egress']:
			egress.append(e_list)
		else:
			ingress.append(e_list)
	return egress,ingress


def security_groups(ec2, region):
	'''This grabs all of the security groups related information that are linked to the running instances
			Parameters:
				ec2: That is just the resource passed over from ec2_describe_instances function
				region: The AWS region to traverse.
			Returns:
				sg_info: Returns a dictionary of dictionaries of security groups containing the id as the key and group_name, rules, vpc_id etc. as the keys inside the dictionary represented by the id.
		'''
		sg_ids = []
		sg_info = {}

		for sg in ec2.security_groups.all():
			sg_ids.append(sg.id)
		
		for id in sg_ids:
			try:
				security_group = ec2.SecurityGroup(id)
				sg_info[id] = {'group_id': security_group.group_id, 'group_name': security_group.group_name, 'rules': security_group.ip_permissions, 'rules_egress': security_group.ip_permissions_egress, 'vpc_id': security_group.vpc_id}
				sg_info = security_groups_info(sg_info,'rules',id)
				sg_info = security_groups_info(sg_info,'rules_egress',id)
			except botocore.exceptions.ClientError as e:
				print('The security_groups operation failed due to:', e.reason)
		sg_info = {'sg_dict': sg_info}
		return sg_info


def security_groups_info(sec_gr, rule_name, sec_id):
	rule = []

	if sec_gr[sec_id][rule_name]:
		for rules in sec_gr[sec_id][rule_name]:
			if rules['IpProtocol'] != '-1':
				if rules['IpRanges'] and rules['UserIdGroupPairs']:
					for entry in rules['IpRanges']:
						rule.append({'proto': rules['IpProtocol'], 'from_port': rules['FromPort'], 'to_port': rules['ToPort'], 'cidr_ip': entry['CidrIp']})
					for entry in rules['UserIdGroupPairs']:
						rule.append({'proto': rules['IpProtocol'], 'from_port': rules['FromPort'], 'to_port': rules['ToPort'], 'group_id': entry['GroupId']})
				elif rules['IpRanges'] and not rules['UserIdGroupPairs']:
					for entry in rules['IpRanges']:
						rule.append({'proto': rules['IpProtocol'], 'from_port': rules['FromPort'], 'to_port': rules['ToPort'], 'cidr_ip': entry['CidrIp']})
				elif rules['UserIdGroupPairs'] and not rules['IpRanges']:
					for entry in rules['UserIdGroupPairs']:
						rule.append({'proto': rules['IpProtocol'], 'from_port': rules['FromPort'], 'to_port': rules['ToPort'], 'group_id': entry['GroupId']})
			elif rules['IpProtocol'] == '-1':
				if rules['IpRanges'] and rules['UserIdGroupPairs']:
					for entry in rules['IpRanges']:
						rule.append({'proto': 'all', 'cidr_ip': entry['CidrIp'], 'from_port': 'all', 'to_port': 'all'})
					for entry in rules['UserIdGroupPairs']:
						rule.append({'proto': rules['IpProtocol'], 'from_port': rules['FromPort'], 'to_port': rules['ToPort'], 'group_id': entry['GroupId']})
				elif rules['IpRanges'] and not rules['UserIdGroupPairs']:
					for entry in rules['IpRanges']:
						rule.append({'proto': 'all', 'cidr_ip': entry['CidrIp'], 'from_port': 'all', 'to_port': 'all'})
				elif rules['UserIdGroupPairs'] and not rules['IpRanges']:
					for entry in rules['UserIdGroupPairs']:
						rule.append({'proto': rules['IpProtocol'], 'from_port': rules['FromPort'], 'to_port': rules['ToPort'], 'group_id': entry['GroupId']})
			sec_gr[sec_id][rule_name]= rule
	return sec_gr

	



def vpc_list(ec2,instance_list):
	"""This grabs all of the VPC that are linked to the running instances
		Parameters:
			ec2: That is just the resource passed over from ec2_describe_instances function
			instance_list: List of all the running ec2 instances
		Returns:
			vpc_list: A list of vpc_id that are linked to those running instances
			vpcs: A dict output of all the various vpc attributes linked to the various vpc instances
	"""
	vpc_info = {}
	vpc_ids = []

	for vpc in ec2.vpcs.all():
		vpc_ids.append(vpc.id)

	for id in vpc_ids:
		try:
			vpc = ec2.Vpc(id)
			vpc_info[id] = {'vpc_id': vpc.vpc_id,'dhcp_opts_id': vpc.dhcp_options_id,'cidr_block': vpc.cidr_block, 'resource_tags': vpc.tags}
			if vpc_info[id]['resource_tags']:
				vpc_info = tags_dict(vpc_info, 'resource_tags', id)
				vpc_info[id]['name'] = vpc_info[id]['resource_tags']['Name']
			else:
				vpc_info[id]['name'] = vpc_info[id]['vpc_id']
				vpc_info[id]['resource_tags'] = {}
			
		except botocore.exceptions.ClientError as e:
			print('The vpc operation failed due to:', e.reason)
	vpc_info = {'vpc_dict': vpc_info}
	return vpc_ids,vpc_info

def nat_list(vpc_ids):
	nat_gw = {}

	ec2 = assign_client('ec2', region)
	for vpc in vpc_ids:
		result = ec2.describe_nat_gateways(Filter=[{'Name':'vpc-id','Values':[vpc]}])
		for item in result['NatGateways']:
			subnet_id = item['SubnetId']
			nat = item['NatGatewayId']
			print(item)
			for x in item['NatGatewayAddresses']:
				print(x)
				alloc_id = x['AllocationId']
				eip = x['PublicIp']
			nat_gw[nat] = {'nat_gateway_id': nat, 'subnet_id': subnet_id}
	nat_gw = {'nat_dict': nat_gw}
	return nat_gw


def igw_list(ec2, vpc_ids):
	igw_info = {}
	igw_ids = {}

	for id in vpc_ids:
		vpc = ec2.Vpc(id)
		for igw in vpc.internet_gateways.all():
			igw_ids[id] = igw.id

	for vpc,igw_id in igw_ids.items():
		internet_gateway = ec2.InternetGateway(igw_id)
		igw_info[igw_id] = {'vpc_id': vpc, 'tags': internet_gateway.tags}
		if igw_info[igw_id]['tags']:
			igw_info = tags_dict(igw_info, 'tags', igw_id)
		else:
                        igw_info[igw_id]['tags'] = {}
	igw_info = {'igw_dict': igw_info}
	return igw_info

def tags_dict(dict_name,tag_name,key):
	"""This function converts a list of tags containing a dict into a dict so yaml does not complain about it
		Parameters:
			dict_name: A dictionary that needs to be edited
			tag_name: The tag name which would be the key in that dict
		Returns:
			dict_name: Returns the modified dict containing a dict instead of a list of dicts
	"""
	old_value = dict_name[key][tag_name]
	del(dict_name[key][tag_name])
	new_tags = {}
	for item in old_value:
		new_key = item['Key']
		new_value = item['Value']
		new_tags[new_key] = new_value
	dict_name[key][tag_name] = new_tags
	return dict_name

def elb_info():
	#Module currently not supported by Ansible
	regex = 'NLB'
	elb = assign_client('elbv2','us-west-1')
	lbs = elb.describe_load_balancers()
	lb_names = [lb[key] for lb in lbs['LoadBalancers'] for key in lb.keys() if key == 'LoadBalancerArn']
	for item in lb_names:
		if re.search(regex, item):
			res = elb.describe_target_groups(LoadBalancerArn=item)
			print(res)

def yaml_file(content,file,item):
	filename = os.path.split(file)[1]
	try:
		with open(file, 'w') as yaml_file:
			indent_len = len(item)+4
			yaml.dump(content,sys.stdout,default_flow_style=False,explicit_start=True,indent=indent_len,line_break=True)
			yaml.dump(content,yaml_file,default_flow_style=False,explicit_start=True,indent=indent_len)
			return filename
	except IOError:
		print('Could not write to the file: ',filename) 

#Define a different method to obtain the key and the secret for the AWS account
def get_ykeykey_key(key):
	try:
		key_value = ysecure.get_key(key)
		return key_value
	except RuntimeError:
		print('Could not execute the call to ysecure')


if __name__ == '__main__':
	subnet_file = './subnets.yaml'
	vpc_file = './vpc.yaml'
	sg_file = './sg.yaml'
	acl_file = './acl.yaml'
	route_file = './route.yaml'
	volume_file = './volume.yaml'
	ec2_file = './ec2.yaml'
	nat_file = './nat.yaml'
	igw_file = './igw.yaml'
	region = 'us-east-2'
 
	#key = get_ykeykey_key('aws_ansible_ghe')
	#print(key)
	#value = get_ykeykey_key('aws_ansible_ghe_secret')
	#print(value)
	
	ec2,instance_list = ec2_describe_instances(region)
	print(instance_list)
	volume_list,volume_dict = volume_list(ec2,instance_list)
	print(volume_list)
	#snapshot_dict = create_snapshot(ec2,volume_list,volume_dict)
	#print("snapshot info is:", snapshot_dict)
	#volume_info_dict = volume_info(ec2,volume_dict,snapshot_dict)
	volume_info_dict,volume_info_dict_file = volume_info(ec2,volume_dict)
	print(volume_info_dict)
	yaml_file(volume_info_dict_file,volume_file,'volume_dict')
	ec2_dict = ec2_info(ec2,region, volume_dict, volume_info_dict)
	yaml_file(ec2_dict,ec2_file,'ec2_dict')
	print(ec2_dict)

	subnet_list,subnets = subnet_list(ec2,instance_list)
	print(subnet_list,subnets)
	yaml_file(subnets,subnet_file,'subnet_dict')
	routes = route_table_info(ec2, instance_list, subnet_list)
	print(routes)
	yaml_file(routes,route_file,'route_dict')
	acl_info,acls = network_acl(ec2,subnet_list)
	print(acl_info,acls)
	yaml_file(acls,acl_file,'acl_dict')
	sg_info = security_groups(ec2, instance_list)
	print(sg_info)
	yaml_file(sg_info,sg_file,'sg_dict')
	vpc_list,vpcs = vpc_list(ec2,instance_list)
	print(vpcs,vpc_list)
	yaml_file(vpcs,vpc_file,'vpc_dict')
	nat_gw = nat_list(vpc_list)
	yaml_file(nat_gw, nat_file, 'nat_dict')
	print(nat_gw)
	igw_info = igw_list(ec2,vpc_list)
	yaml_file(igw_info,igw_file,'igw_dict')
	print(igw_info)
	elb_info()
