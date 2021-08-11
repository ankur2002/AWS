#!/usr/bin/env python3
#@AB feel free to use it however you wish!

import boto3
import botocore
import re
import time
#from ruamel.yaml import YAML
import os,sys,yaml
from collections import defaultdict

class CustomException(Exception): pass

def assign_resource(service_name,type):
	if type == 'source':
		session = boto3.Session(profile_name=profile)
		resource = session.resource(service_name, source_region)
	elif type == 'destination':
		session = boto3.Session(profile_name=profile)
		resource = session.resource(service_name, dest_region)
	return resource

def assign_client(service_name,type):
	if type == 'source':
		session = boto3.Session(profile_name=profile)
		client= session.client(service_name, source_region)
	elif type == 'destination':
		session = boto3.Session(profile_name=profile)
		client = session.client(service_name, dest_region)
	return client

def ec2_describe_instances(region):
	"""
	This uses a filter to look at the running ec2 instances in a specific region and adds the ec2 attributes into a dict.
	Parameters:
		region: This is the AWS region that the script would run against.
	Returns:
		ec2: ec2 resource passed to enable ec2 calls for other modules.
		instance_list: A dict of instances containing instance id as a key and the attributes as values.
	"""
	instance_dict= {}
	instance_list = []

	ec2 = assign_resource('ec2','source')
	#If the non-running instances need to be taken into account then an additional value of stopped etc. needs to be added here.
	instances = ec2.instances.filter(Filters=[{'Name': 'instance-state-name', 'Values': ['running']}])
	for instance in instances:
	#This is assuming that your instance tags exist if not please do add them else it will make this next task virtually impossible!!
		if not check_ec2_ignore(instance):
			instance_list.append(instance.id)


	for id in instance_list:
		instance = ec2.Instance(id)
		security_groups = []
		instance_dict[id] = {'subnet_id': instance.subnet_id,'key': instance.key_name,'image_id': instance.image_id,'security_groups': instance.security_groups, 'vpc_id': instance.vpc_id, 'instance_type': instance.instance_type, 'public_ip': instance.public_ip_address, 'ebs_volumes': instance.block_device_mappings, 'tags': instance.tags}

	return instance_list,instance_dict


def volume_list(ec2,instance_dict):
	"""
	This retrieves volumes for all the instances and stores the instance id and volume id in a dict
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


	for item in instance_dict.keys():
		for volume in instance_dict[item]['ebs_volumes']:
			if volume['Ebs']['VolumeId'] in volume_list:
				volume_dict.setdefault(item, []).append(volume['Ebs']['VolumeId'])
	return volume_list,volume_dict

def create_snapshot(ec2,volume_dict):
	"""
	This function creates snapshots for all EBS volumes that are listed in the volume dict
	Parameters:
		ec2: This is the source ec2 client
		volume_dict: It uses instance id's as keys and their respective volume id's as values
	Returns:
		snapshot_dict: It returns a snapshot dict of volume_id's and their corresponding snapshot id's
	"""

	snapshot_dict = {}
	for item in volume_dict.values():
		for id in item:
			print("Creating snapshot for:", id)
			try:
				volume = ec2.Volume(id)
				description = 'Snapshot being created for Volume' +id
				snapshot = ec2.create_snapshot(VolumeId=volume.id, Description=description)

				snapshot.wait_until_completed(Filters=[{'Name': 'volume-id', 'Values': [volume.id]}])

				snapshot_dict[volume.id] = snapshot.snapshot_id
			except botocore.exceptions.ClientError as e:
				print('The snapshot operation failed due to:', e.reason)

	return snapshot_dict   



def volume_info(ec2,volume_dict):
	"""
	This takes the volume dictionary and for each volume id it collects details on each of those volumes.
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
				for item in volume.attachments:
					device = item['Device']
					delete_on_termination = item['DeleteOnTermination']
				volume_info_dict[volume_id] = {'instance':key, 'DeviceName':device,'DeleteOnTermination': delete_on_termination, 'KmsKeyId':volume.kms_key_id, 'VolumeSize':volume.size, 'Iops':volume.iops, 'Encrypted':volume.encrypted, 'VolumeType': volume.volume_type, 'tags': volume.tags}
				if volume_info_dict[volume_id]['tags']:
					volume_info_dict = tags_dict(volume_info_dict, 'tags', volume_id)
				else:
					volume_info_dict[volume_id]['tags'] = {}
			except botocore.exceptions.ClientError as e:
				print('The volume operation failed due to:', e.reason)

	return volume_info_dict

def ec2_info(ec2,region, volume_dict, volume_info_dict):
	"""
	For each running ec2 instance it retrieves the additional attributes such as key_name etc.
	Parameters:
		ec2: ec2 resource passed to enable ec2 calls for other modules.
		region: This is the AWS region that the script would run against.
		volume_dict: A volume dictionary containing instance id's as keys and corresponding volume id's as values.
		volume_info_dict: A dictionary containing volume id as a key and it's attributes as values.
	Returns:
		ec2_info_dict: A dictionary of the ec2 instance attributes using instance_id as the key.
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
			ec2_info_dict[instance.id] = {'vpc_subnet_id': instance.subnet_id, 'key_name': instance.key_name,'image': instance.image_id, 'security_group': security_group_id,'instance_type': instance.instance_type, 'tags': instance.tags}
			if ec2_info_dict[id]['tags']:
					ec2_info_dict = tags_dict(ec2_info_dict, 'tags', id)
			else:
				ec2_info_dict[id]['tags'] = {'Name': id}
	ec2_info_dict = {'ec2_dict': ec2_info_dict}
	return ec2_info_dict

def ec2_create_copy_image(ec2,ec2_dest_client,id,source_instance_dict,source_volume_info_dict):
	"""
	This function creates an AMI for the instance and copies it to the dest region
	Parameters:
		ec2: This is the ec2 source client
		ec2_dest: The ec2_dest client
		id: Instance id for which the AMI is to be created
		source_instance_dict: This is the instance dict that contains information about the instance id
		source_volume_info_dict: This contains information on each volume
		source_snapshot_dict: A dict of snapshot id's and the corresponding volume id
	Returns:
	dest_image_id: The image_id of the destination image
	ami_dict: A dict containing the image name and it's id
	"""

	instance = ec2.Instance(id)
	if not check_ec2_ignore(instance):
		block_device_mappings = []
		for tag in source_instance_dict[id]['tags']:
			if tag['Key'] == 'Name':
				instance_name = tag['Value']
		#for key,value in source_volume_info_dict.items():
		#	if value['instance'] == id:
		#		block_device_mappings.append(create_blockdevice_mappings(source_snapshot_dict, source_volume_info_dict, key))

		tags = source_instance_dict[id]['tags']
		print("Creating image for instance:", instance_name)

		image = instance.create_image(
			NoReboot=True,
			Name=instance_name,
			Description='This is an image for '+ instance_name,
			InstanceId=id
		)

		image.wait_until_exists(Filters=[{'Name': 'name', 'Values': [instance_name]}])

		return instance_name, image.id

def ec2_dest_copy(ec2_dest_client, name, id):
	"""
	This function simply copies the newly created AMI's to the destination region
	Parameters:
		ec2_dest_client: This is the just the ec2 client parameter for the destination
		name: The source instance name
		id: The source ami id
	Returns:
		dest_name The destination instance name
		dest_image_id: The destination ami id
	"""

	dest_image = ec2_dest_client.copy_image(SourceImageId=id, Name=name, SourceRegion=source_region)
	dest_image_id = dest_image['ImageId']
	dest_image = ec2_dest.Image(dest_image_id)

	dest_image.wait_until_exists()

	return name, dest_image_id



def check_ec2_ignore(instance):
	"""
	This function is to check if the ec2 instance is part of the ignore list
	Parameters:
		instance: This is the instance retrieved from the instance iterator
	Returns:
		True or False: This returns a boolean based on if or not the instance matches the ignore list
	"""

	try:
		val = ''
		for tag in instance.tags:
			if tag['Key'] == 'Name':
				instance_name = tag['Value']

		for item in ignore_list:
			if re.search(item,instance_name):
				val = 'ignore'

		if val:
			return True
		else:
			return False
	except botocore.exceptions.ClientError as e:
		print('The vpc operation failed due to:', e.reason)



def create_instance(source_instance_info,instance_name,ami_dest_dict):
	source_security_group_name = []
	destination_security_group_id = []
	print("Instance name is:",instance_name)
	source_instance_id = instance_grep(instance_name,'source','name')
	print("Instance id is:",source_instance_id)
	source_subnet_id = source_instance_info[source_instance_id]['subnet_id']
	source_security_groups = source_instance_info[source_instance_id]['security_groups']
	source_subnet_name = subnet_grep(source_subnet_id,'source','id')
	source_instance_type = source_instance_info[source_instance_id]['instance_type']

	tags = source_instance_info[source_instance_id]['tags']
	for item in source_security_groups:
		source_security_group_name.append(item['GroupName'])
	for source_sg in source_security_group_name:
		dest_sg_id = sg_grep(source_sg,'destination','name')
		if dest_sg_id not in destination_security_group_id:
			destination_security_group_id.append(dest_sg_id)

	dest_subnet_id = subnet_grep(source_subnet_name,'destination','name')
	ami_id = ami_dest_dict[instance_name]
	image = ec2_dest.Image(ami_id)
	print(source_instance_id, source_subnet_name, ami_id, tags)
	create_image_pause(image,ami_id)
	if image.state == 'available':
		print("Destination AMI is now available, creating instance:", instance_name)
		ec2_dest.create_instances(MaxCount=1,MinCount=1,SecurityGroupIds=destination_security_group_id,SubnetId=dest_subnet_id,TagSpecifications=[{ 'ResourceType':'instance', 'Tags':tags}], ImageId=ami_id, InstanceType=source_instance_type)


def create_image_pause(image,ami_id):
	count = 1
	while image.state == 'pending':
		time.sleep(180)
		image = ec2_dest.Image(ami_id)
		print(image.id,"is",image.state,"for",count,"times")
		count += 1
		if image.state == 'available':
			break
		else:
			continue
	print(ami_id,"has been copied over to the destination region")






def create_blockdevice_mappings(source_snapshot_dict, source_volume_info_dict, volume_id):
	"""
	This function creates the BlockDeviceMappings list of dict for creating the AMI
	Parameters:
		source_snapshot_dict: Is a dict of snapshot id and the corresponding volume id
		source_volume_info_dict: It is a volume dict containing the info for that volume including the instance id
		volume_id: The volume id that would reveal the block device mapping details along with the instance id
	Returns:
		block_device_info: The list of dicts of BlockDeviceMappings
	"""

	block_device_info = {
							'DeviceName': source_volume_info_dict[volume_id]['DeviceName'],
							'Ebs': {
								'DeleteOnTermination': source_volume_info_dict[volume_id]['DeleteOnTermination'],
								'Iops': source_volume_info_dict[volume_id]['Iops'],
								'SnapshotId': source_snapshot_dict[volume_id],
								'VolumeSize': source_volume_info_dict[volume_id]['VolumeSize'],
								'VolumeType': source_volume_info_dict[volume_id]['VolumeType'],
								'Encrypted': source_volume_info_dict[volume_id]['Encrypted'],
								'KmsKeyId': source_volume_info_dict[volume_id]['KmsKeyId']
							}
						}
	return block_device_info




def route_table_info(ec2):
	"""
	This grabs all of the route tables that are linked to the running instances
	Parameters:
		ec2: That is just the resource passed over from ec2_describe_instances function
		instance_list: instance_list: List of all the running ec2 instances
		subnet_list: List of subnet_ids that are linked to the running ec2 instances
	Returns:
		subnet_route_table: Is a dict where the keys are the subnet id and value is the route table id
		routes: That is a dict containing additional information about the route tables
		"""
	#subnet_route_table = {}
	route_table_info = {}
	route_table_ids = []
	#nat_gateway = []

	for route_table in ec2.route_tables.all():
		route_table_ids.append(route_table.id)

	print(route_table_ids)

	for id in route_table_ids:
		try:	
			route_table = ec2.RouteTable(id)
			subnet_ids = []
			for subnet in route_table.associations_attribute:
				if 'SubnetId' in subnet.keys():
					subnet_ids.append(subnet['SubnetId'])
			mapping = {'DestinationCidrBlock':'dest','GatewayId':'gateway_id','NatGatewayId':'gateway_id'}
			#Adding additional function to handle the re-mapping for the item.routes_attribute
			routes_attribute = remap_dict(mapping,route_table.routes_attribute)
			print(id, routes_attribute)
			route_table_info[id] = {'vpc_id': route_table.vpc_id,'subnets': subnet_ids,'routes': routes_attribute, 'tags': route_table.tags}
			if route_table_info[id]['tags']:
					route_table_info = tags_dict(route_table_info, 'tags', id)
			else:
				route_table_info[id]['tags'] = {'Name': id}
		except botocore.exceptions.ClientError as e:
			print('The route table operation failed due to:', e.reason)
	route_table_info = {'route_dict': route_table_info}
	return route_table_info,route_table_ids


def create_route_tables(ec2_dest, vpc_id, count=0):
		route_tables = []
		x = 0
		#vpc_id = info['VpcId']
		while x <= count:
			route_table = ec2_dest.create_route_table(VpcId=vpc_id)
			print(route_table['RouteTable']['RouteTableId'])
			route_tables.append(route_table['RouteTable']['RouteTableId'])
			x += 1
		return route_tables


def check_routes(vpc_id,itemt):
	"""This just gets a count of all the existing route tables under the new vpc
	Parameters:
		vpc_id: The id of the vpc being checked
		ec2: The ec2 client parameter for the destination

	Returns:
		rt_count: It returns the route table count
	"""

	route_tables = []
	ec2 = assign_client('ec2', itemt)
	rt = ec2.describe_route_tables(Filters=[{'Name': 'vpc-id', 'Values': [vpc_id]}])

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


def nacl_copy(vpc_id, nacl_id, dest_vpc):
	"""
	This function is used to copy/create nacls from a source vpc to a dest vpc
	Parameters:
		vpc_id: The source vpc id
		nacl_id: A nacl id from the source vpc that needs to be copied/created
		dest_vpc: The corresponding dest vpc id
	Returns:
		nacl_ids: A list of nacl id's that were created in the dest vpc
	"""

	ec2_client = assign_client('ec2', 'source')
	ec2_dest_client = assign_client('ec2', 'destination')

	ec2_1 = ec2_client
	ec2_2 = ec2_dest_client

	x = 0
	nacl_entries = []
	nacl_ids = []
	empty_nacl_dict = {}
	nacl_tag = ''

	nacls = ec2_1.describe_network_acls(Filters=[{ 'Name': 'vpc-id', 'Values': [vpc_id]}])
	for nacl in nacls['NetworkAcls']:
		print(nacl)
		if nacl['NetworkAclId'] == nacl_id:
			if nacl['Tags']:
				nacl_tag = nacl['Tags']
			else:
				nacl_tag = []
			nacl_entries.append(nacl['Entries'])



	new_nacl = ec2_2.create_network_acl(VpcId = dest_vpc)
	if nacl_tag:
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


	return nacl_ids


def check_nacls(source_nacls, dest_vpc_id):
	dest_nacls = ec2_dest_client.describe_network_acls(Filters=[{'Name': 'vpc-id', 'Values': [dest_vpc_id]}])
	if dest_nacls:
		return True
	else:
		return False


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

def create_vpc(ec2,id):
	"""
	This will create a new VPC in the location specified by itemt using a source VPC id provided by id
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
		ec2_dest = assign_resource('ec2', 'destination')
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
	"""
	This function checks to see if the source vpc_id already exists in the destination
	Parameters:
		vpc_id: The source vpc_id that the check is performed for
	Returns:
		True or False: It simply returns a boolean based on the vpc search result
	"""

	try:
		val = ''
		ec2 = assign_resource('ec2','source')
		vpc = ec2.Vpc(vpc_id)
		for tag in vpc.tags:
			if tag['Key'] == 'Name':
					vpc_name = tag['Value']

		ec2_dest = assign_resource('ec2', 'destination')
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

def check_vpc_ignore(vpc_id):
	"""
	This function checks to see if the source vpc name is part of the list of ignored vpc's in the destination
	Parameters:
		vpc_id: It is the source vpc_id that is used for the match
	Returns:
	True or False: It simply returns a boolean corresponding to the ignore list match results
	"""

	try:
		val = ''
		ec2 = assign_resource('ec2','source')
		vpc = ec2.Vpc(vpc_id)

		for tag in vpc.tags:
			if tag['Key'] == 'Name':
					vpc_name = tag['Value']
		for item in ignore_list:
			if re.search(item,vpc_name):
				val = 'ignore'

		if val:
			return True
		else:
			return False
	except botocore.exceptions.ClientError as e:
		print('The vpc operation failed due to:', e.reason)

def vpc_grep(vpc_val,itemt,source):
	"""
	This function takes a vpc id or name and returns a name or the corresponding vpc id
	Parameters:
		vpc_val: This is the vpc value provided to the function
		itemt: This identifies it being either the source vpc or the destination vpc
		source: It helps distinguish between vpc name and vpc id
	Returns:
		vpc id or name: Based on what was provided it returns it's converse (id for name and name for id)
	"""

	if source == 'id':
		ec2 = assign_resource('ec2',itemt)
		vpc_ret = ec2.Vpc(vpc_val)
		for item in vpc_ret.tags:
			if item['Key'] == 'Name':
				return item['Value']
	elif source == 'name':
		ec2 = assign_resource('ec2', itemt)
		for vpc in ec2.vpcs.all():
			for item in vpc.tags:
				if item['Key'] == 'Name':
					if item['Value'] == vpc_val:
						return vpc.vpc_id


def instance_grep(instance_val,itemt,source):
	if source == 'id':
		ec2 = assign_resource('ec2',itemt)
		instance_ret = ec2.Vpc(instance_val)
		for item in instance_ret.tags:
			if item['Key'] == 'Name':
				return item['Value']
	elif source == 'name':
		ec2 = assign_resource('ec2', itemt)
		for instance in ec2.instances.filter(Filters=[{'Name':'instance-state-name','Values':['running']}]):
			for item in instance.tags:
				if item['Key'] == 'Name':
					if item['Value'] == instance_val:
						return instance.id


def subnet_grep(subnet_val,itemt,source):
	"""
	This function takes a subnet id or name and returns a name or the corresponding subnet id
	Parameters:
		vpc_val: This is the subnet value provided to the function
		itemt: This identifies the value as being either the source or the destination
		source: It helps identify the subnet value as a name or an id
	Returns:
		subnet id or name: Based on what was provided it returns it's converse (id for name and name for id)
	"""

	if source == 'id':
		ec2 = assign_resource('ec2',itemt)
		subnet_ret = ec2.Subnet(subnet_val)
		for item in subnet_ret.tags:
			if item['Key'] == 'Name':
				return item['Value']
	elif source == 'name':
		ec2 = assign_resource('ec2', itemt)
		for subnet in ec2.subnets.all():
			for item in subnet.tags:
				if item['Key'] == 'Name':
					if item['Value'] == subnet_val:
						return subnet.subnet_id


#Removed all the peering functions for now since we only need to address intra region connections and the peering is between bastion and app which is created by bastion

def get_subnet_ids(vpc_id, itemt):
	subnet_ids = []
	ec2 = assign_resource('ec2', itemt)
	vpc = ec2.Vpc(vpc_id)
	for subnet in vpc.subnets.all():
		subnet_ids.append(subnet.id)
	return subnet_ids

def subnet_list(vpc_id, itemt):
	'''
	This grabs all of the subnets that are linked to the running instances
	Parameters:
		vpc_id: That is just the vpc_id used as the source vpc
		itemt: This identifies it as being either the source or the destination
	Returns:
		subnet_ids: Is a list containing the subnet ids
		subnet_info: That is a dict containing additional information about the subnets
	'''
	subnet_info = {}
	subnet_ids = []
	ec2 = assign_resource('ec2', itemt)

	subnet_ids = get_subnet_ids(vpc_id, itemt)
	#for subnet in ec2.subnets.all():
	#	subnet_ids.append(subnet.id)


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


def subnet_create(ec2,source_vpc,id,subnet_info,az_mapping):
	'''
	This function creates a corresponding subnet for the destination based on the source vpc and subnet
	Parameters:
		ec2: This is the ec2 resource that is either linked to the source or the destination
		source_vpc: The source vpc id
		id: The subnet id that needs to be created in the destination
		subnet_info: The dictionary of the existing subnets in the source vpc
		az_mapping: The source to destination az mapping dictionary
	Returns:
	'''
	try:
		subnet = ec2.Subnet(id)
		vpc_name = vpc_grep(source_vpc, 'source', 'id')
		vpc_dest_id = vpc_grep(vpc_name, 'destination', 'name')
		ec2_dest = assign_resource('ec2', 'destination')
		new_az = az_mapping[subnet.availability_zone]
		newsubnet = ec2_dest.create_subnet(AvailabilityZone=new_az, CidrBlock=subnet.cidr_block, VpcId=vpc_dest_id)
		subnet_dest = ec2_dest.Subnet(newsubnet.subnet_id)
		if subnet.tags:
			for item in subnet.tags:
				if item['Key'] == 'Name':
					subnet_dest.create_tags(Tags=[{'Key':item['Key'],'Value':item['Value']}])
		vpc_dest = ec2_dest.Vpc(vpc_dest_id)
		print(subnet_dest.cidr_block, subnet_dest.id)
	except CustomException:
		err = "The instance was not valid."

def subnet_check(vpc_id,id):
	try:
		val = ''
		ec2 = assign_resource('ec2', 'source')

		subnet = ec2.Subnet(id)

		if subnet.tags:
			for tag in subnet.tags:
				if tag['Key'] == 'Name':
					subnet_name = tag['Value']
		if subnet_name:
			for item in ignore_list:
				if re.search(item, subnet_name):
					val = 'ignore'

		ec2 = assign_resource('ec2', 'destination')
		vpc_name = vpc_grep(vpc_id, 'source', 'id')
		vpc_dest_id = vpc_grep(vpc_name, 'destination', 'name')
		dest_subnetlist, dest_subnet_dict = subnet_list(vpc_dest_id, 'destination')
		print(dest_subnet_dict)
		for id, params in dest_subnet_dict.items():
			if params['resource_tags']:
				if params['resource_tags']['Name'] == subnet_name:
					val = 'exists'
		if val:
			return False
		else:
			return True
	except botocore.exceptions.ClientError as e:
		print('The vpc operation failed due to:', e.reason)

def subnet_nacl(ec2, new_subnets, dest_nacls, nacl_assoc_id, dest_vpc_id, nats, igw):
	"""
	This function links the new nacls and route tables with the new subnets
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
	ec2_dest = assign_client('ec2', 'destination')
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


def security_groups(itemt):
	"""
	This grabs all of the security groups related information that are linked to the running instances
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

	ec2 = assign_resource('ec2', itemt)

	for sg in ec2.security_groups.all():
		sg_ids.append(sg.id)



	for id in sg_ids:
		try:
			security_group = ec2.SecurityGroup(id)
			if security_group.group_name != 'default':
				sg_info[id] = {'group_id': security_group.group_id, 'group_name': security_group.group_name, 'rules': security_group.ip_permissions, 'rules_egress': security_group.ip_permissions_egress, 'vpc_id': security_group.vpc_id, 'description': security_group.description, 'tags': security_group.tags}
				if itemt == 'source':
					sg_ingress, sg_egress, updated_ingress, updated_egress = sg_check_references(security_group.group_name,security_group.ip_permissions,security_group.ip_permissions_egress, sg_ingress, sg_egress,itemt)
					sg_info[id]['rules'] = updated_ingress
					sg_info[id]['rules_egress'] = updated_egress
		except botocore.exceptions.ClientError as e:
			print('The security_groups operation failed due to:', e.reason)
	#print(sg_egress,sg_ingress)
	return sg_info

def recursively_default_dict():
	return defaultdict(recursively_default_dict)

def sg_check_references(sg,ingress,egress,sg_ingress,sg_egress,itemt):
	updated_ingress = []
	updated_egress = []

	for item in ingress:
		if item.get('UserIdGroupPairs') and len(item.get('UserIdGroupPairs')):
			ingress_rule = item.get('UserIdGroupPairs')
			for group in ingress_rule:
				g_name = sg_grep(group['GroupId'],itemt,'id')
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
				g_name = sg_grep(group['GroupId'],itemt,'id')
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
	'''
	This function checks to see if the source sg is in the ignore list or if it already exists in the destination
	Parameters:
		id: This is just the source security group id
	Returns:
		True or False: It returns a bool based on if the source sg is found in the ignore list or if it already exists in the destination
	'''
	try:
		sg_name = ''
		sg_group_name = ''
		val = ''
		ec2 = assign_resource('ec2', 'source')
		sg = ec2.SecurityGroup(id)

		if sg.group_name != 'default':
			if sg.tags:
				for tag in sg.tags:
					if tag['Key'] == 'Name':
						sg_name = tag['Value']
			else:
				sg_group_name = sg.group_name
			if sg_name:
				for item in ignore_list:
					if re.search(item, sg_name):
						val = 'ignore'
			elif sg_group_name:
				for item in ignore_list:
					if re.search(item, sg_name):
						val = 'ignore'

			sg_dest = security_groups('destination')
			for id,params in sg_dest.items():
				if params['tags']:
					for item in params['tags']:
						if item['Key'] == 'Name':
							if item['Value'] == sg_name:
								val = 'exists'
				else:
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
		print("Found vpc ", vpc_name)
		vpc_dest_id = vpc_grep(vpc_name,'destination','name')
		sg = ec2_dest.create_security_group(Description=security_group.description,GroupName=security_group.group_name,VpcId=vpc_dest_id)
		sg_dest = ec2_dest.SecurityGroup(sg.group_id)
		if security_group.tags:
			for item in security_group.tags:
				if item['Key'] == 'Name':
					sg_dest.create_tags(Tags=[{'Key':item['Key'],'Value':item['Value']}])
		vpc_dest = ec2_dest.Vpc(vpc_dest_id)
		print(vpc_dest.cidr_block,sg_dest.group_id,sg_info)
		if not len(sg_dest.ip_permissions_egress) and sg_info['rules_egress']:
			sg_check_references(sg_info, ingress, egress, sg_ingress, sg_egress, itemt)
			sg_dest.authorize_egress(IpPermissions=sg_info['rules_egress'])
		if not len(sg_dest.ip_permissions) and sg_info['rules']:
			sg_dest.authorize_ingress(GroupId=sg_dest.group_id, IpPermissions=sg_info['rules'])
	except botocore.exceptions.ClientError as e:
		print('The security group creation failed due to:', e.reason)



def sg_grep(sg_value,itemt,source):
	if source == 'id':
		ec2 = assign_resource('ec2',itemt)
		security_group = ec2.SecurityGroup(sg_value)
		if security_group.tags:
			for item in security_group.tags:
				if item['Key'] == 'Name':
					g_name = item['Value']
		else:
			g_name = security_group.group_name
		return g_name
	elif source == 'name':
		ec2 = assign_resource('ec2', itemt)
		sg_info = security_groups(itemt)

		for id, params in sg_info.items():
			if params['group_name'] and sg_value == params['group_name']:
						g_id = id
						break
			else:
				if params['tags']:
					for item in params['tags']:
						if item['Key'] == 'Name' and (item['Value'] == sg_value):
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
	"""
	This function takes a list of all the security group rules that reference other security groups and modifies them.
	Parameters:
		ec2: The ec2 parameter indicates source or destination
		type: Also indicates source or destination but it is referenced by the sg_grep function
		dest_peering: This has the destination peering id used to replace the current id
		userid: The new account user id
	Returns:
	"""

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


def nat_list(ec2,vpc_id):
	"""
	This function takes vpc_id and returns a dictionary of the assoicated nat gateways
	Parameters:
		ec2: ec2 parameter
		vpc_id: The source vpc id that is used to retrieve the nat gateways.
	Returns:
		nat_gw: It returns a dictionary of nat gateways
	"""

	nat_gw = {}

	result = ec2.describe_nat_gateways(Filter=[{'Name':'vpc-id','Values':[vpc_id]}])
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

def check_nats(source_nats, dest_vpc_id):
	"""
	This function checks the number of souce nats to compare them against the dest nats
	Parameters:
		source_nats:
		dest_vpc_id:
	Returns:
		True or False: Returns a boolean i.e. True if the number of source nats > number of dest nats and False if not
	"""

	try:
		dest_nats = []
		result = ec2_dest_client.describe_nat_gateways(Filter=[{'Name':'vpc-id','Values':[dest_vpc_id]}])
		for nt in result['NatGateways']:
			if nt['NatGatewayId'] not in dest_nats:
				dest_nats.append(nt['NatGatewayId'])
		print("dest nats is:",dest_nats,"source nats is:",source_nats)
	except botocore.exceptions.ClientError as e:
		print('The nat creation check failed due to:', e.reason)
	print("dest nats length is:", len(dest_nats), "source nats length is:", len(source_nats))
	if len(source_nats) > len(dest_nats):
		return True
	else:
		return False

def igw_list(ec2, vpc_ids):
	"""
	It takes a list of vpc_ids and returns a dictionary of the corresponding internet gateways
	Parameters:
		ec2: ec2 parameter
		vpc_ids: A list of vpc id's that is used to retrieve the internet gateways.
	Returns:
		igw_info: It returns a dictionary of internet gateways
	"""

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

def check_igw(source_tags,dest_vpc_id):
	"""
	This function checks to see if the internet gateway already exists for the dest vpc
	Parameters:
		source_tags: The source igw tags
		dest_vpc_id: The destination vpc id
	Returns:
		True or False: Returns a boolean based on whether or not it finds the internet gateway in the destination vpc
	"""

	try:
		for item in source_tags:
			tag = item['Value']
		print(tag,dest_vpc_id)
		igw = ec2_dest_client.describe_internet_gateways(Filters=[{'Name':'attachment.vpc-id', 'Values':[dest_vpc_id]},{'Name':'tag:Name','Values':[tag]}])
	except botocore.exceptions.ClientError as e:
		print('The igw check failed due to:', e.reason)

	if igw['InternetGateways']:
		for item in igw['InternetGateways']:
			if item['InternetGatewayId']:
				return True
			else:
				return False
	else:
		return False

def create_igw(source_tags,dest_vpc_id):
	try:
		dest_igw = ec2_dest_client.create_internet_gateway()
		dest_igw_id = dest_igw['InternetGateway']['InternetGatewayId']
		dest_igw = ec2_dest.InternetGateway(dest_igw_id)
		dest_igw.create_tags(Tags=source_tags)
		ec2_dest_client.attach_internet_gateway(InternetGatewayId=dest_igw_id, VpcId=dest_vpc_id)
	except botocore.exceptions.ClientError as e:
		print('The igw check failed due to:', e.reason)
	return dest_igw_id


def tags_dict(dict_name,tag_name,key):
	"""
	This function converts a list of tags containing a dict into a dict so yaml does not complain about it
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
	profile = 'datacoe'
	source_region = 'us-east-1'
	dest_region = 'us-west-1'
	ignore_list = ['bastion', 'gacco']
	#This az_mapping will provide the source to destination mapping for the availability-zones
	az_mapping = {'us-east-1a': 'us-west-1b', 'us-east-1b': 'us-west-1c'}
	az_id = {'us-west-1b': 'usw1-az3', 'us-west-1c': 'usw1-az1'}
	sg_ingress = {}
	sg_egress = {}
	new_vpcs = {}
	vpcs_dest = {}
	new_subnets = []
	subnet_val = ''
	dest_nacls = {}
	dest_igws = []
	dest_ami = []

	ec2 = assign_resource('ec2', 'source')
	ec2_dest = assign_resource('ec2', 'destination')

	ec2_client = assign_client('ec2', 'source')
	ec2_dest_client = assign_client('ec2', 'destination')

	source_instance_list, source_instance_dict = ec2_describe_instances(source_region)
	print("Here is the source instance dict:", source_instance_dict)
	source_volume_list, source_volume_dict = volume_list(ec2,source_instance_dict)
	print("This is the source volume dictionary:",source_volume_dict)
	#print("Now creating snapshots of all the source volumes")
	#source_snapshot_dict = create_snapshot(ec2, source_volume_dict)
	#print("All snapshots have been created")
	source_volume_info_dict = volume_info(ec2, source_volume_dict)
	#print("Here are the snapshot and volume info dicts:",source_snapshot_dict,source_volume_info_dict)

	ami_dict = {}
	for id in source_instance_dict.keys():
		instance_name, image_id = ec2_create_copy_image(ec2, ec2_dest_client, id, source_instance_dict, source_volume_info_dict)
		if instance_name not in ami_dict.keys():
			ami_dict[instance_name] = image_id
	print("Finished creating all of the source AMI's")

	print("Starting to copy those source AMI's to the destination region")
	ami_dest_dict = {}
	for name, id in ami_dict.items():
		dest_name, dest_image_id = ec2_dest_copy(ec2_dest_client, name, id)
		if dest_name not in ami_dest_dict.keys():
			ami_dest_dict[dest_name] = dest_image_id
	print(ami_dest_dict)



	source_route_table_info, source_route_table_list = route_table_info(ec2)



	vpclist, vpcs = vpc_list(ec2)


	#for key, value in sg_ingress.items():
	#	print(key, value)




#Skipped over peering for now since this is bound to only copy resources between regions

	for source_vpc in vpclist:
		if not check_vpc_ignore(source_vpc):
			if check_vpc(source_vpc):
				print("Creating VPC")
				new_vpcs = create_vpc(ec2, source_vpc)
			else:
				print("Found VPC")

			vpclist_dest, vpcs_dest = vpc_list(ec2_dest)

		sg_info = security_groups('source')

		for item in sg_info.keys():
			print("Looking for ", item)
			if sg_check(item):
				print("Creating Security Group")
				sg_create(ec2, item, sg_info[item])
			else:
				print("Found Security Group")
		sg_dest_info = security_groups('destination')

		if not check_vpc_ignore(source_vpc):
			subnet_ids, subnet_info = subnet_list(source_vpc, 'source')
			for item in subnet_info.keys():
				if subnet_check(source_vpc, item):
					print("Creating subnet")
					subnet_create(ec2,source_vpc, item, subnet_info[item], az_mapping)
				else:
					print("Found subnet")

		if not check_vpc_ignore(source_vpc):
			source_nacl_list = []
			nacls = ec2_client.describe_network_acls(Filters=[{'Name': 'vpc-id', 'Values': [source_vpc]}])
			for item in nacls['NetworkAcls']:
				print(item['NetworkAclId'])
			vpc_name = vpc_grep(source_vpc, 'source', 'id')
			dest_vpc_id = vpc_grep(vpc_name, 'destination', 'name')
			if not check_nacls(nacls,dest_vpc_id):
				for nacl in nacls['NetworkAcls']:
					nacl_ids = nacl_copy(source_vpc, nacl['NetworkAclId'], dest_vpc_id)
					print(nacl_ids)

			source_igw = ec2_client.describe_internet_gateways(Filters=[{'Name': 'attachment.vpc-id', 'Values': [source_vpc]}])
			source_nat = ec2_client.describe_nat_gateways(Filters=[{'Name': 'vpc-id', 'Values': [source_vpc]}])
			eip_allocation = check_addresses(az_id)

			for igw in source_igw['InternetGateways']:
				source_tags = igw['Tags']
				print(dest_vpc_id)
				if not check_igw(source_tags,dest_vpc_id):
					dest_igw_id = create_igw(source_tags,dest_vpc_id)
					if dest_igw_id not in dest_igws:
						dest_igws.append(dest_igw_id)
				else:
					print('Found internet gateway')

			source_nats = []
			for nt in source_nat['NatGateways']:
				id = nt['NatGatewayId']
				if id not in source_nats:
					source_nats.append(id)
				print("For source vpc",source_vpc,"found",source_nats)
				subnet = ec2.Subnet(nt['SubnetId'])
				source_az = subnet.availability_zone
				subnet_name = subnet_grep(nt['SubnetId'], 'source', 'id')
				dest_subnet_id = subnet_grep(subnet_name, 'destination', 'name')
				dest_az = az_mapping[source_az]
				allocation_id = eip_allocation.pop()
				token = allocation_id + dest_az + source_vpc
				if check_nats(source_nats,dest_vpc_id):
					print("Need more nat gateways")
					nat = ec2_dest_client.create_nat_gateway(AllocationId=allocation_id, SubnetId=dest_subnet_id, ClientToken=token)
				else:
					print('Found nat gateways for vpc')


			source_rt_count, source_route_tables = check_routes(source_vpc, 'source')
		#source_route_table_info,source_route_table_list = route_table_info(ec2)


	for vpc_id, vpc_params in vpcs_dest.items():

						dest_igw = ec2_dest_client.describe_internet_gateways(Filters=[{'Name': 'attachment.vpc-id', 'Values': [vpc_id]}])
						dest_nat = ec2_dest_client.describe_nat_gateways(Filters=[{'Name': 'vpc-id', 'Values': [vpc_id]}])

						print(dest_igw, dest_nat)

						dest_rt_count, dest_route_tables = check_routes(vpc_id, 'destination')
						print('source_rt_count is:',source_rt_count,"dest_rt_count is:",dest_rt_count)
						if source_rt_count > dest_rt_count:
							dest_route_tables = create_route_tables(ec2_dest_client, vpc_id, count=(source_rt_count - dest_rt_count))
							print(dest_route_tables)
						else:
							print("Found destination route tables")

						dest_nacl_assoc_id = {}
						dest_nacls = ec2_dest_client.describe_network_acls(Filters=[{'Name': 'vpc-id', 'Values': [vpc_id]}])
						for dest_nacl in dest_nacls['NetworkAcls']:
							for tag in dest_nacl['Tags']:
								if tag['Key'] == 'Name':
									nacl_name = tag['Value']
									dest_nacls[nacl_name] = dest_nacl['NetworkAclId']
							if dest_nacl['Associations']:
								for item in dest_nacl['Associations']:
									subnet = item['SubnetId']
									assoc_id = item['NetworkAclAssociationId']
									dest_nacl_assoc_id[subnet]= assoc_id


						#This igw and nat create_route code needs to be translated into an independent function!!

						if len(dest_route_tables) >= 3:
							for id,nt in zip(dest_route_tables[0:2], dest_nat['NatGateways']) :
								try:
									cidr = '0.0.0.0/0'
									if not check_route_table_routes(id, cidr):
										ec2_dest_client.create_route(DestinationCidrBlock=cidr, NatGatewayId=nt['NatGatewayId'], RouteTableId=id)
								except botocore.exceptions.ClientError as e:
									print('The route tables operation failed due to:', e.reason)

						

							vpc_cidr = vpcs_dest[vpc_id]['cidr_block']


							for dest_ig in dest_igw['InternetGateways']:
								if dest_ig['InternetGatewayId']:
									cidr = '0.0.0.0/0'
									if not check_route_table_routes(dest_route_tables[2], cidr):
										ec2_dest_client.create_route(DestinationCidrBlock=cidr, GatewayId=dest_ig['InternetGatewayId'], RouteTableId=dest_route_tables[2])
									#if not check_route_table_routes(dest_route_tables[2], peer_cidr):
									#	ec2_dest_client.create_route(DestinationCidrBlock=peer_cidr, VpcPeeringConnectionId=peer_id, RouteTableId=dest_route_tables[2])
									if not check_route_table_routes(dest_route_tables[2], vpc_cidr):
										ec2_dest_client.create_route(DestinationCidrBlock=vpc_cidr, TransitGatewayId='local', RouteTableId=dest_route_tables[2])


						for instance_name in ami_dest_dict.keys():
							print("Creating instance for:", instance_name)
							create_instance(source_instance_dict,instance_name,ami_dest_dict)
						#print("sg_inress and sg_egress are:", sg_egress, sg_ingress)
						#sg_ingress_egress_add(ec2_dest, 'destination', dest_peering_id, ownerid)

						#Already setup for the new Jira account
						#subnet_nacl(ec2_dest_client, new_subnets, dest_nacls,  dest_nacl_assoc_id, dest_prod_vpc, nats=route_tables[0:2], igw=route_tables[2])



	


