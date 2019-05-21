#!/usr/bin/env python3
#@AB feel free to use it however you wish!

import boto3
import botocore
import yahoo.ysecure
import re
import ipaddress
import math
#from ruamel.yaml import YAML
import os,sys,yaml
from collections import defaultdict

class CustomException(Exception): pass

def assign_resource(service_name,region,type):
	if type == 'source':
		resource = boto3.resource(
			service_name,
			region,
			aws_access_key_id= get_ykeykey_key('xxxxxxxxxx'),
			aws_secret_access_key= get_ykeykey_key('xxxxxxxxxxxx'),
		)
	elif type == 'destination':
		resource = boto3.resource(
			service_name,
			region,
			aws_access_key_id=get_ykeykey_key('xxxxxxxxxxxx'),
			aws_secret_access_key=get_ykeykey_key('xxxxxxxxxxxx'),
		)
	return resource

def assign_client(service_name,region,type):
	if type == 'source':
		client = boto3.client(
			service_name,
			region,
			aws_access_key_id= get_ykeykey_key('xxxxxxxxxxx'),
			aws_secret_access_key= get_ykeykey_key('xxxxxxxxxxx'),
				)
	elif type == 'destination':
		client = boto3.client(
			service_name,
			region,
			aws_access_key_id=get_ykeykey_key('xxxxxxxxxxx'),
			aws_secret_access_key=get_ykeykey_key('xxxxxxxxxxx'),
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

	ec2 = assign_resource('ec2',region, 'source')
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


def create_route_tables(info, owner_id, ec2_dest, vpc_id, count=0):
		route_tables = []
		x = 0
		#vpc_id = info['VpcId']
		while x <= count:
			route_table = ec2_dest.create_route_table(VpcId=vpc_id)
			route_tables.append(route_table['RouteTable']['RouteTableId'])
			x += 1
		return route_tables


def check_routes(vpc_id,ec2_dest_client):
	"""This just gets a count of all the existing route tables under the new vpc
	Parameters:
		vpc_id: The id of the vpc being checked
		ec2_dest_client: The ec2 client parameter for the destination

	Returns:
		rt_count: It returns the route table count
	"""
	route_tables = []
	rt = ec2_dest_client.describe_route_tables(Filters=[{'Name': 'vpc-id', 'Values': [vpc_id]}])

	rt_count = 0

	if rt['RouteTables']:
		for item in rt['RouteTables']:
			if item['RouteTableId']:
				rt_count += 1
				route_tables.append(item['RouteTableId'])
	return rt_count, route_tables

def check_route_table_routes(route_table_id, cidr):
	found = ''
	routes = ec2_dest_client.describe_route_tables(Filters=[{'Name': 'route-table-id', 'Values': [route_table_id]}])
	for item in routes['RouteTables']:
		for route in item['Routes']:
			print(cidr)
			if route['DestinationCidrBlock'] == cidr:
				found = True
				break
	if found:
		return True
	else:
		return False




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
			e_list = [item['RuleNumber'], protocols[protocol], item['RuleAction'], item['CidrBlock'], None, None, from_port, to_port]
		else:
			continue
		if item['Egress']:
			egress.append(e_list)
		else:
			ingress.append(e_list)
	return egress,ingress

def nacl_copy(type, vpc_id, nacl_id, dest_vpc, count=0):
	ec2_client = assign_client('ec2', region, 'source')
	ec2_dest_client = assign_client('ec2', region, 'destination')

	if type == 'source_to_source':
		ec2_1 = ec2_client
		ec2_2 = ec2_client
	elif type == 'source_to_dest':
		ec2_1 = ec2_client
		ec2_2 = ec2_dest_client

	x = 0
	nacl_entries = []
	nacl_ids = []
	empty_nacl_dict = {}
	nacl_tag = ''

	nacls = ec2_1.describe_network_acls(Filters=[{ 'Name': 'vpc-id', 'Values': [vpc_id]}])
	for nacl in nacls['NetworkAcls']:
		if nacl['NetworkAclId'] == nacl_id:
			nacl_tag = nacl['Tags']
			nacl_entries.append(nacl['Entries'])


	if count:
		while x < count:
			new_nacl = ec2_2.create_network_acl(VpcId = dest_vpc)
			ec2_2.create_tags(Resources=[new_nacl['NetworkAcl']['NetworkAclId']],Tags=nacl_tag)
			for entry in nacl_entries:
				for rule in entry:
					if rule['RuleNumber'] != 32767:
						if 'PortRange' in rule.keys():
							if 'CidrBlock' in rule.keys():
								ec2_2.create_network_acl_entry(CidrBlock=rule['CidrBlock'], Egress=rule['Egress'], Protocol=rule['Protocol'], RuleAction=rule['RuleAction'], RuleNumber=rule['RuleNumber'], PortRange=rule['PortRange'], NetworkAclId=new_nacl['NetworkAcl']['NetworkAclId'])
							else:
								ec2_2.create_network_acl_entry(Ipv6CidrBlock=rule['Ipv6CidrBlock'], Egress=rule['Egress'], Protocol=rule['Protocol'], RuleAction=rule['RuleAction'], RuleNumber=rule['RuleNumber'], PortRange=rule['PortRange'], NetworkAclId=new_nacl['NetworkAcl']['NetworkAclId'])
						else:
							if 'CidrBlock' in rule.keys():
								ec2_2.create_network_acl_entry(CidrBlock=rule['CidrBlock'], Egress=rule['Egress'], Protocol=rule['Protocol'], RuleAction=rule['RuleAction'], RuleNumber=rule['RuleNumber'], NetworkAclId=new_nacl['NetworkAcl']['NetworkAclId'])
							else:
								ec2_2.create_network_acl_entry(Ipv6CidrBlock=rule['Ipv6CidrBlock'], Egress=rule['Egress'], Protocol=rule['Protocol'], RuleAction=rule['RuleAction'], RuleNumber=rule['RuleNumber'], NetworkAclId=new_nacl['NetworkAcl']['NetworkAclId'])

			nacl_ids.append(new_nacl['NetworkAcl']['NetworkAclId'])
			x += 1

	return nacl_ids





def vpc_list(ec2):
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
			vpc_info[id] = {'vpc_id': vpc.vpc_id,'dhcp_opts_id': vpc.dhcp_options_id, 'cidr_block': vpc.cidr_block, 'resource_tags': vpc.tags, 'instance_tenancy':vpc.instance_tenancy}
		except botocore.exceptions.ClientError as e:
			print('The vpc operation failed due to:', e.reason)
	#vpc_info = {'vpc_dict': vpc_info}
	return vpc_ids,vpc_info

def create_vpc(ec2,id,itemt):
	"""This will create a new VPC in the location specified by itemt using a source VPC id provided by id
		Parameters:
			ec2: This is the ec2 resource that is either linked to the source or the destination
			id: This is the vpc id that needs to be replicated
			itemt: Presents either a source or destination as the desired location of this new VPC.
		Returns:
			new_vpcs: A dictionary of the new VPC

	"""
	new_vpcs = {}
	try:
		vpc_source = ec2.Vpc(id)
		ec2_dest = assign_resource('ec2',region,itemt)
		vpc = ec2_dest.create_vpc(CidrBlock=vpc_source.cidr_block,InstanceTenancy=vpc_source.instance_tenancy)
		vpc_dest = ec2_dest.Vpc(vpc.vpc_id)
		for item in vpc_source.tags:
			if item['Key'] == 'Name':
				vpc_dest.create_tags(Tags=[{'Key':item['Key'],'Value':item['Value']}])
				new_vpcs[vpc_dest.vpc_id] = {'vpc_id': vpc_dest.vpc_id,'dhcp_opts_id': vpc_dest.dhcp_options_id,'cidr_block': vpc_dest.cidr_block, 'resource_tags': vpc_dest.tags, 'instance_tenancy':vpc_dest.instance_tenancy}
	except botocore.exceptions.ClientError as e:
		print('The vpc operation failed due to:', e.reason)
	return new_vpcs

def check_vpc(vpc_id):
	try:
		val = ''
		ec2 = assign_resource('ec2',region,'source')
		vpc = ec2.Vpc(vpc_id)
		for tag in vpc.tags:
			if tag['Key'] == 'Name':
					vpc_name = tag['Value']
		ec2_dest = assign_resource('ec2', region, 'destination')
		vpclist,vpc_dict = vpc_list(ec2_dest)
		for id,params in vpc_dict.items():
			if params['resource_tags']:
				for item in params['resource_tags']:
					if item['Key'] == 'Name':
						if item['Value'] == vpc_name:
							val = 'exists'
		if val:
			return False
		else:
			return True
	except botocore.exceptions.ClientError as e:
		print('The vpc operation failed due to:', e.reason)

def vpc_grep(vpc_val,itemt,source):
	if source == 'id':
		ec2 = assign_resource('ec2',region,itemt)
		vpc_ret = ec2.Vpc(vpc_val)
		for item in vpc_ret.tags:
			if item['Key'] == 'Name':
				return item['Value']
	elif source == 'name':
		ec2 = assign_resource('ec2', region, itemt)
		for vpc in ec2.vpcs.all():
			for item in vpc.tags:
				if item['Key'] == 'Name':
					if item['Value'] == vpc_val:
						return vpc.vpc_id

def check_vpc_peering(source_vpcs):
	source_peering = {}
	ec2 = assign_client('ec2', region, 'source')


	for vpcid, params in source_vpcs.items():
		peering = ec2.describe_vpc_peering_connections(Filters=[{ 'Name': 'requester-vpc-info.vpc-id', 'Values': [vpcid]}])
		if peering['VpcPeeringConnections']:
			for peers in peering['VpcPeeringConnections']:
				for key,value in peers.items():
					peering_id = peers['VpcPeeringConnectionId']
					source_peering[peering_id] = []
					source_vpc_id = peers['AccepterVpcInfo']['VpcId']
					source_name = vpc_grep(source_vpc_id, 'source', 'id')
					dest_vpc_id = peers['RequesterVpcInfo']['VpcId']
					dest_name = vpc_grep(dest_vpc_id, 'source', 'id')
					source_peering[peering_id] = {'source': source_name, 'dest': dest_name}

	return source_peering


def create_vpc_peering(source_peering, dest_vpcs, ownerid, region):
	dest_peering = {}
	ec2_dest = assign_resource('ec2', region, 'destination')

	for id, value in source_peering.items():
		source_name = value['source']
		dest_name = value['dest']
		source_id = vpc_grep(source_name, 'destination', 'name')
		dest_id = vpc_grep(dest_name, 'destination', 'name')
		dest_peer = ec2_dest.create_vpc_peering_connection(PeerOwnerId= ownerid, PeerVpcId= dest_id, VpcId= source_id, PeerRegion= region)
		dest_peering[dest_peer.id] = {'source': source_name, 'dest': dest_name}

	return dest_peering



def subnet_list(ec2):
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
	#subnet_info = {'subnet_dict': subnet_info}
	return subnet_ids,subnet_info

def calculate_subnets(vpc_id,no_of_subnets):
	"""This will take a vpc_id and subnet count and creates the corresponding subnnet ranges
			Parameters:
				vpc_id: The id of the vpc whose cidr block will be used to create the subnets
				no_of_subnets: The total number of subnets required
			Returns:
				subnet_list: Is a list of all the subnets created
		"""
	ec2_dest = assign_resource('ec2', region, 'destination')
	vpc = ec2_dest.Vpc(vpc_id)
	cidr = vpc.cidr_block
	addr = ipaddress.ip_network(cidr)
	if addr.version == 4 or addr.version == 6:
		net = ipaddress.ip_network(cidr)
		no_of_hosts = net.num_addresses
		no_of_subnet_hosts = math.modf(no_of_hosts / no_of_subnets)
		subnet_bits = 32 - math.ceil(math.log(no_of_subnet_hosts[1], 2))
		newnet = ipaddress.ip_network(cidr)
		newsubnets = newnet.subnets(new_prefix=subnet_bits)
	return newsubnets

def create_subnets(vpc_id, newsubnets, environments, instances, az_id):
	new_subnets = {}
	subnet_names = []
	ec2_dest = assign_resource('ec2', region, 'destination')
	try:
			for env in environments:
				for instance in instances:
					for azone, azone_id in az_id.items():
						if instance.upper() == 'JIRA':
							subnet_name = instance+'-'+env+'-'+'internal'+'-'+azone
							subnet_names.append(subnet_name)
						elif instance.upper() == 'ELB' or instance.upper() == 'NLB' or instance.upper() == 'NGINX':
							subnet_name = instance+'-'+env+'-'+'external'+'-'+azone
							subnet_names.append(subnet_name)
						else:
							raise CustomException()
			for subnet, subnet_name in zip(newsubnets, subnet_names):
				if 'us-west-2b' in subnet_name:
					azone = 'us-west-2b'
				elif 'us-west-2a' in subnet_name:
					azone = 'us-west-2a'
				newsubnet = ec2_dest.create_subnet(AvailabilityZone=azone, CidrBlock=subnet, VpcId=vpc_id)
				subnet_dest = ec2_dest.Subnet(newsubnet.id)
				subnet_dest.create_tags(Tags=[{ 'Key' : 'Name', 'Value' : subnet_name}])
				if newsubnet.id not in new_subnets.keys():
					new_subnets[newsubnet.id] = {'vpc_id': subnet_dest.vpc_id,'az': subnet_dest.availability_zone,'cidr': subnet_dest.cidr_block,'map_public': subnet_dest.map_public_ip_on_launch,'resource_tags': subnet_dest.tags}
	except CustomException:
		err = "The instance was not valid."
	return new_subnets

def check_subnet(subnet_cidr):
	try:
		val = ''
		ec2_dest = assign_resource('ec2', region, 'destination')
		subnetlist, subnet_dict = subnet_list(ec2_dest)
		for id, params in subnet_dict.items():
			if params['cidr'] == subnet_cidr:
				val = 'exists'
		if val:
			return False
		else:
			return True
	except botocore.exceptions.ClientError as e:
		print('The vpc operation failed due to:', e.reason)

def subnet_nacl(ec2, new_subnets, dest_nacls, nacl_assoc_id, dest_vpc_id, nats, igw):
	"""This function links the new nacls and route tables with the new subnets
	Parameters:
		ec2: This is the ec2 client parameter
		new_subnets: The subnet dictionary containing info on the new subnets
		dest_nacls: The nacl name and it's id
		nacl_assoc_id: The nacl association id and the corresponding subnet
		dest_vpc_id: The destination vpc id
		nats: The nat id's
		igw: Internet gateway id
	"""
	subnets = {}
	routes = {}

	for id, params in new_subnets.items():
		subnets[params['resource_tags']['Name']] = id

	rt_info = ec2.describe_route_tables(Filters=[{'Name': 'vpc-id', 'Values': [dest_vpc_id]}])
	for item in rt_info['RouteTables']:
		if item['Associations']:
			for info in item['Associations']:
				rt_assoc_id = info['RouteTableAssociationId']


	for key1 in dest_nacls.keys():
		for key2 in subnets.keys():
			if key1.lower() in key2.lower():
				subnet_id = subnets[key2]
				new_nacl = dest_nacls[key1]
				if nacl_assoc_id.get(subnet_id):
					nacl = nacl_assoc_id[subnet_id]
					ec2.replace_network_acl_association(AssociationId=nacl, NetworkAclId=new_nacl)

	for key in subnets.keys():
		pattern1 = re.compile('NLB|ELB|Nginx')
		pattern2 = re.compile('Jira')
		if pattern1.match(key):
			ec2.associate_route_table(RouteTableId=igw, SubnetId=subnets[key])
		elif pattern2.match(key):
			if key.endswith('2a'):
				ec2.associate_route_table(RouteTableId=nats[0], SubnetId=subnets[key])
			elif key.endswith('2b'):
				ec2.associate_route_table(RouteTableId=nats[1], SubnetId=subnets[key])






def check_addresses(az_id):
	eip_allocation = []
	ec2_dest = assign_client('ec2', region, 'destination')
	addresses = ec2_dest.describe_addresses(Filters=[{'Name': 'domain', 'Values': ['vpc']}])

	available_count = 0
	if len(addresses["Addresses"]):
		for ip in addresses["Addresses"]:
			if 'AssociationId' not in ip.keys():
				#eip = ip["PublicIp"]
				allocation_id = ip["AllocationId"]
				eip_allocation.append(allocation_id)
				available_count += 1

	while available_count < len(az_id):
		addr = ec2_dest.allocate_address(Domain='vpc')
		#eip = addr['PublicIp'])
		allocation_id = addr["AllocationId"]
		eip_allocation.append(allocation_id)

	return eip_allocation


def security_groups(type):
	"""This grabs all of the security groups related information that are linked to the running instances
			Parameters:
				ec2: That is just the resource passed over from ec2_describe_instances function
				region: The AWS region to traverse.
			Returns:
				sg_info: Returns a dictionary of dictionaries of security groups containing the id as the key and group_name, rules, vpc_id etc. as the keys inside the dictionary represented by the id.
	"""
	sg_ids = []
	sg_info = {}
	global sg_ingress
	global sg_egress

	ec2 = assign_resource('ec2', region, type)

	for sg in ec2.security_groups.all():
		sg_ids.append(sg.id)



	for id in sg_ids:
		try:
			security_group = ec2.SecurityGroup(id)
			if security_group.group_name != 'default':
				sg_info[id] = {'group_id': security_group.group_id, 'group_name': security_group.group_name, 'rules': security_group.ip_permissions, 'rules_egress': security_group.ip_permissions_egress, 'vpc_id': security_group.vpc_id, 'description': security_group.description, 'tags': security_group.tags}
				if type == 'source':
					sg_ingress, sg_egress, updated_ingress, updated_egress = sg_check_references(security_group.group_name,security_group.ip_permissions,security_group.ip_permissions_egress, sg_ingress, sg_egress)
					sg_info[id]['rules'] = updated_ingress
					sg_info[id]['rules_egress'] = updated_egress
		except botocore.exceptions.ClientError as e:
			print('The security_groups operation failed due to:', e.reason)
	#print(sg_egress,sg_ingress)
	return sg_info

def recursively_default_dict():
	return defaultdict(recursively_default_dict)

def sg_check_references(sg,ingress,egress,sg_ingress,sg_egress):
	updated_ingress = []
	updated_egress = []

	for item in ingress:
		if item.get('UserIdGroupPairs') and len(item.get('UserIdGroupPairs')):
			ingress_rule = item.get('UserIdGroupPairs')
			for group in ingress_rule:
				g_name = get_referenced_sg_name(group['GroupId'])
				#g_name = sg_grep('name', ec2, group['GroupId'])
				group['GroupId'] = g_name
			if sg not in sg_ingress.keys():
				sg_list = []
				sg_list.append(item)
				sg_ingress[sg] = sg_list
			else:
				sg_ingress[sg].append(item)
		else:
			updated_ingress.append(item)

	for item in egress:
		if item.get('UserIdGroupPairs') and len(item.get('UserIdGroupPairs')):
			egress_rule = item.get('UserIdGroupPairs')
			for group in egress_rule:
				g_name = get_referenced_sg_name(group['GroupId'])
				#g_name = sg_grep('name', itemt, group['GroupId'])
				group['GroupId'] = g_name
			if sg not in sg_egress.keys():
				sg_list = []
				sg_list.append(item)
				sg_egress[sg] = item
			else:
				sg_egress[sg].append(item)
		else:
			updated_egress.append(item)

	return sg_ingress,sg_egress,updated_ingress,updated_egress


def sg_check(id):
	try:
		sg_name = ''
		sg_group_name = ''
		val = ''
		ec2 = assign_resource('ec2', region, 'source')
		sg = ec2.SecurityGroup(id)
		if sg.group_name != 'default':
			if sg.tags:
				for tag in sg.tags:
					if tag['Key'] == 'Name':
						sg_name = tag['Value']
			else:
				sg_group_name = sg.group_name
			sg_dest = security_groups('destination')
			for id,params in sg_dest.items():
				if sg_name:
					if params['tags']:
						for item in params['tags']:
							if item['Key'] == 'Name':
								if item['Value'] == sg_name:
									val = 'exists'
				elif sg_group_name:
					if params['group_name'] == sg_group_name:
						val = 'exists'
			if val:
				return False
			else:
				return True
		# Skip creating default security groups
		elif sg.group_name == 'default':
			return False

	except botocore.exceptions.ClientError as e:
		print('The security group operation failed due to:', e.reason)




def sg_create(ec2,id,sg_info):
	try:
		security_group = ec2.SecurityGroup(id)
		vpc_name = vpc_grep(security_group.vpc_id,'source','id')
		vpc_dest_id = vpc_grep(vpc_name,'destination','name')
		ec2_dest = assign_resource('ec2',region,'destination')
		sg = ec2_dest.create_security_group(Description=security_group.description,GroupName=security_group.group_name,VpcId=vpc_dest_id)
		sg_dest = ec2_dest.SecurityGroup(sg.group_id)
		if security_group.tags:
			for item in security_group.tags:
				if item['Key'] == 'Name':
					sg_dest.create_tags(Tags=[{'Key':item['Key'],'Value':item['Value']}])
		vpc_dest = ec2_dest.Vpc(vpc_dest_id)
		print(vpc_dest.cidr_block,sg_dest.group_id,sg_info)
		if not len(sg_dest.ip_permissions_egress) and sg_info['rules_egress']:
			sg_dest.authorize_egress(IpPermissions=sg_info['rules_egress'])
		if not len(sg_dest.ip_permissions) and sg_info['rules']:
			sg_dest.authorize_ingress(GroupId  = sg_dest.group_id,IpPermissions = sg_info['rules'])
	except botocore.exceptions.ClientError as e:
		print('The security group creation failed due to:', e.reason)



def sg_grep(ec2, source, value, type):
	if source == 'id':
		#ec2 = assign_resource('ec2',region,itemt)
		security_group = ec2.SecurityGroup(value)
		if security_group.tags:
			for item in security_group.tags:
				if item['Key'] == 'Name':
					g_name = item['Value']
		else:
			g_name = security_group.group_name
		return g_name
	elif source == 'name':
		#ec2 = assign_resource('ec2', region, itemt)
		sg_info = security_groups(type)

		for id, params in sg_info.items():
			if params['group_name'] and value == params['group_name']:
						g_id = id
						break
			else:
				if params['tags']:
					for item in params['tags']:
						if item['Key'] == 'Name' and (item['Value'] == value):
							g_id = id
							break
		return g_id


def get_referenced_sg_name(g_id):
	security_group = ec2.SecurityGroup(g_id)
	if security_group.tags:
		for item in security_group.tags:
			if item['Key'] == 'Name':
				g_name = item['Value']
	else:
		g_name = security_group.group_name
	return g_name

def sg_ingress_egress_add(ec2, type, dest_peering, userid):
	'''This function takes a list of all the security group rules that reference other security groups and modifies them.
	Parameters:
		ec2: The ec2 parameter indicates source or destination
		type: Also indicates source or destination but it is referenced by the sg_grep function
		dest_peering: This has the destination peering id used to replace the current id
		userid: The new account user id
	Returns:
	'''
	global sg_ingress
	global sg_egress

	for sg_name in sg_ingress.keys():
		if isinstance(sg_name, str):
			sg_id = sg_grep(ec2, 'name', sg_name, type)
			for rules in sg_ingress[sg_name]:
				for item in rules['UserIdGroupPairs']:
					sg_rule_id = sg_grep(ec2, 'name', item['GroupId'], type)
					item['GroupId'] = sg_rule_id
					item['UserId'] = userid
					if item.get('VpcId'):
						vpc_name = vpc_grep(item['VpcId'], 'source', 'id')
						dest_vpc_id = vpc_grep(vpc_name, 'destination', 'name')
						item['VpcId'] = dest_vpc_id
						item['VpcPeeringConnectionId'] = dest_peering
				print(rules)
				sg_dest = ec2_dest.SecurityGroup(sg_id)
				sg_dest.authorize_ingress(GroupId=sg_dest.group_id, IpPermissions=[rules])


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



def get_ykeykey_key(key):
	try:
		key_value = yahoo.ysecure.get_key(key)
		if key_value:
			return key_value
		else:
			return -1
	except RuntimeError:
		print('Could not execute the call to ysecure')


if __name__ == '__main__':
	region = 'us-west-2'
	az_id = {'us-west-2a': 'usw2-az1', 'us-west-2b': 'usw2-az2'}
	sg_ingress = {}
	sg_egress = {}
	no_of_subnets = 32
	environments = ['prod', 'stage', 'archive', 'sandbox']
	instances =['Jira', 'NLB', 'ELB', 'Nginx']
	ownerid = 'xxxxxxxxxx'
	source_jira_prod_vpc = 'xxxxxxxxxxx'
	new_vpcs = {}
	vpcs_dest = {}
	new_subnets = []
	subnet_val = ''
	dest_nacls = {}

	print(sg_ingress, sg_egress)
	ec2, instance_list = ec2_describe_instances(region)
	ec2 = assign_resource('ec2', region, 'source')
	ec2_dest = assign_resource('ec2', region, 'destination')

	ec2_client = assign_client('ec2', region, 'source')
	ec2_dest_client = assign_client('ec2', region, 'destination')

	print(instance_list)
	vpclist, vpcs = vpc_list(ec2)
	print(type(vpcs), vpclist)

	for item in vpclist:
		if check_vpc(item):
			print("Creating VPC")
			new_vpcs = create_vpc(ec2, item, 'destination')
		else:
			print("Found VPC")

			vpclist_dest, vpcs_dest = vpc_list(ec2_dest)


	sg_info = security_groups('source')
	for item in sg_info.keys():
		if sg_check(item):
			print("Creating Security Groups")
			sg_create(ec2_dest,item,sg_info[item])
		else:
			print("Found Security Group")
	sg_dest_info = security_groups('destination')

	#for key, value in sg_ingress.items():
	#	print(key, value)


	if new_vpcs:
		vpcs_dest = new_vpcs
	elif vpcs_dest:
		vpcs_dest = vpcs_dest

	peering = check_vpc_peering(vpcs)
	dest_peer = check_vpc_peering(vpcs_dest)
	if dest_peer:
		for key, value in dest_peer.items():
			dest_peer = key

	if not len(dest_peer):
		dest_peering = create_vpc_peering(peering, vpcs_dest, ownerid, region)

		for key, value in dest_peering.items():
			dest_peering_id = key
		print(dest_peering)

	for vpc_id, vpc_params in vpcs_dest.items():
		if vpc_params['resource_tags']:
			for item in vpc_params['resource_tags']:
				for key,value in item.items():
					if value == 'jira-prod':
						dest_prod_vpc = vpc_id
						subnets_to_create = calculate_subnets(vpc_id, no_of_subnets)
						for item in subnets_to_create:
							new_subnets.append(str(item))
						for subnet_cidr in new_subnets:
							if not check_subnet(subnet_cidr):
								print("Found subnet for ", subnet_cidr," please delete all existing subnets first!!")
								subnet_val = 'Found'

						subnet_ids = []
						if not subnet_val:
							new_subnets = create_subnets(vpc_id, new_subnets, environments, instances, az_id)
							for id, params in new_subnets.items():
								for key,value in params["resource_tags"]:
									if "NLB-prod-external" in value:
										subnet_ids.append(id)
						else:
							new_subnets_list, new_subnets = subnet_list(ec2_dest)
							for id, params in new_subnets.items():
								for key, value in params["resource_tags"].items():
									if "NLB-prod-external" in value:
										subnet_ids.append(id)

						eip_allocation = check_addresses(az_id)
						igw = ec2_dest_client.describe_internet_gateways(Filters=[{'Name': 'attachment.vpc-id', 'Values': [vpc_id]}])
						nat = ec2_dest_client.describe_nat_gateways(Filters=[{'Name': 'vpc-id', 'Values': [vpc_id]}])

						az_ids = []
						for key in az_id.keys():
							az_ids.append(key)

						for nt in nat['NatGateways']:
							if not nt['NatGatewayId']:
								for subnet_id, allocation_id, az_id in zip(subnet_ids, eip_allocation, az_ids):
									token = allocation_id+az_id
									nat = ec2_dest_client.create_nat_gateway(AllocationId=allocation_id, SubnetId=subnet_id, ClientToken=token)

						igw = ec2_dest_client.describe_internet_gateways(Filters=[{'Name': 'attachment.vpc-id', 'Values': [vpc_id]}])
						nat = ec2_dest_client.describe_nat_gateways(Filters=[{'Name': 'vpc-id', 'Values': [vpc_id]}])

						print(igw, nat)


						rt_count, route_tables = check_routes(vpc_id, ec2_dest_client)
						info = {'VpcId': vpc_id}
						if rt_count < 3:
							route_tables = create_route_tables(info, ownerid, ec2_dest_client, vpc_id, count=(3 - rt_count))
						print(route_tables)

						'''
						nacls = ec2_client.describe_network_acls(Filters=[{'Name': 'vpc-id', 'Values': [source_jira_prod_vpc]}])
						for nacl in nacls['NetworkAcls']:
							nacl_ids = nacl_copy('source_to_dest', source_jira_prod_vpc, nacl['NetworkAclId'], vpc_id, 4)
						print(nacl_ids)
						'''
						dest_nacl_assoc_id = {}
						nacls = ec2_dest_client.describe_network_acls(Filters=[{'Name': 'vpc-id', 'Values': [dest_prod_vpc]}])
						for nacl in nacls['NetworkAcls']:
							for tag in nacl['Tags']:
								if tag['Key'] == 'Name':
									nacl_name = tag['Value']
							dest_nacls[nacl_name] = nacl['NetworkAclId']
							if nacl['Associations']:
								for item in nacl['Associations']:
									subnet = item['SubnetId']
									assoc_id = item['NetworkAclAssociationId']
									dest_nacl_assoc_id[subnet]= assoc_id


						#This igw and nat create_route code needs to be translated into an independent function!!

						if len(route_tables) >= 3:
							for id,nt in zip(route_tables[0:2], nat['NatGateways']) :
								try:
									cidr = '0.0.0.0/0'
									if not check_route_table_routes(id, cidr):
										ec2_dest_client.create_route(DestinationCidrBlock=cidr, NatGatewayId=nt['NatGatewayId'], RouteTableId=id)
								except botocore.exceptions.ClientError as e:
									print('The route tables operation failed due to:', e.reason)


							for key, value in dest_peering.items():
								peer_id = key
								peer_vpc_id = vpc_grep(value['dest'], 'destination', 'name')
								peer_cidr = vpcs_dest[peer_vpc_id]['cidr_block']
								try:
									if not check_route_table_routes(id, peer_cidr):
										ec2_dest_client.create_route(DestinationCidrBlock=peer_cidr, VpcPeeringConnectionId=peer_id, RouteTableId=id)
								except botocore.exceptions.ClientError as e:
									print('The route tables operation failed due to:', e.reason)


							vpc_cidr = vpcs_dest[vpc_id]['cidr_block']


							for ig in igw['InternetGateways']:
								if ig['InternetGatewayId']:
									cidr = '0.0.0.0/0'
									if not check_route_table_routes(route_tables[2], cidr):
										ec2_dest_client.create_route(DestinationCidrBlock=cidr, GatewayId=ig['InternetGatewayId'], RouteTableId=route_tables[2])
									if not check_route_table_routes(route_tables[2], peer_cidr):
										ec2_dest_client.create_route(DestinationCidrBlock=peer_cidr, VpcPeeringConnectionId=peer_id, RouteTableId=route_tables[2])
									if not check_route_table_routes(route_tables[2], vpc_cidr):
										ec2_dest_client.create_route(DestinationCidrBlock=vpc_cidr, TransitGatewayId='local', RouteTableId=route_tables[2])

						#print("sg_inress and sg_egress are:", sg_egress, sg_ingress)
						#sg_ingress_egress_add(ec2_dest, 'destination', dest_peering_id, ownerid)

						#Already setup for the new Jira account
						#subnet_nacl(ec2_dest_client, new_subnets, dest_nacls,  dest_nacl_assoc_id, dest_prod_vpc, nats=route_tables[0:2], igw=route_tables[2])
















	'''
	#print(sg_info)
	#yaml_file(sg_info, sg_file, 'sg_dict')
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
	'''

