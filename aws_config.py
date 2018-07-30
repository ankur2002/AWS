#!/usr/bin/env python3
#@AB feel free to use it however you wish!

import boto3
import botocore
import yahoo.ysecure
import re
#from ruamel.yaml import YAML
import os,sys,yaml

def assign_resource(service_name,region):
	resource = boto3.resource(
			service_name,
			region,
                	aws_access_key_id= get_ykeykey_key('aws_ansible_ghe'),
                	aws_secret_access_key= get_ykeykey_key('aws_ansible_ghe_secret'),
		)
	return resource

def assign_client(service_name,region):
	client = boto3.client(
			service_name,
                        region,
                        aws_access_key_id= get_ykeykey_key('aws_ansible_ghe'),
                        aws_secret_access_key= get_ykeykey_key('aws_ansible_ghe_secret'),
                )
	return client

def ec2_describe_instances(region):
	'''This uses a filter to look at the running ec2 instances in a specific region and adds the ec2 attributes into a dict.
	Parameters:
		region: This is the AWS region that the script would run against.
	Returns:
		ec2: ec2 resource passed to enable ec2 calls for other modules.
		instance_list: A dict of instances containing instance id as a key and the attributes as values.
	'''
	instance_list= {}
	ec2 = assign_resource('ec2',region)
	instances = ec2.instances.filter(Filters=[{'Name': 'instance-state-name', 'Values': ['running']}])
	
	for instance in instances:
		security_groups = []
		instance_list[instance.id] = {'subnet_id': instance.subnet_id,'key': instance.key_name,'image_id': instance.image_id,'security_groups': instance.security_groups, 'vpc_id': instance.vpc_id, 'instance_type': instance.instance_type, 'public_ip': instance.public_ip_address, 'ebs_volumes': instance.block_device_mappings}

	return ec2,instance_list


def volume_list(ec2,instance_list):
	'''This retrieves volumes for all the instances and stores the instance id and volume id in a dict
        Parameters:
                ec2: That is just the resource passed over from ec2_describe_instances function
                instance_list: instance_list: List of all the running ec2 instances
        Returns:
                volume_dict: A dict containing instance_id as key and volume id's as values
        '''
	volume_dict = {}
	volume_list = set()
	for item in instance_list.keys():
		for volume in instance_list[item]['ebs_volumes']:
			for key in volume.keys():
				volume_dict.setdefault(item, set()).add(volume['Ebs']['VolumeId'])
				volume_list.add(volume['Ebs']['VolumeId'])
	return volume_list,volume_dict

def create_snapshot(ec2,volume_list,volume_dict):

	snapshot_dict = {}
	for id in volume_list:
		try:
			volume = ec2.Volume(id)
			description = 'Snapshot being created for Volume' +volume.id
			snapshot = ec2.create_snapshot(VolumeId = volume.id, Description = description)
			#snapshot = volume.create_snapshot(Description)
			snapshot_dict[volume.id] = snapshot.snapshot_id
		except botocore.exceptions.ClientError as e:
			print('The snapshot operation failed due to:', e.reason)

	return snapshot_dict   

def volume_info(ec2,volume_dict,snapshot_dict):
	#Need to add the snapshot attribute once the create_snapshot function is enabled!!

	volume_info_dict = {}
	for key,value in volume_dict.items():
		for volume_id in value:
			try:
				volume = ec2.Volume(volume_id)
				snapshot_id = snapshot_dict[volume_id]
				for item in volume.attachments:
					device = item['Device']
					delete_on_termination = item['DeleteOnTermination']
				volume_info_dict[volume_id] = {'instance':key, 'device_name':device,'delete_on_termination': delete_on_termination, 'zone':volume.availability_zone, 'volume_size':volume.size, 'iops':volume.iops, 'encrypted':volume.encrypted, 'volume_type': volume.volume_type, 'snapshot': snapshot_id}
			except botocore.exceptions.ClientError as e:
				print('The volume operation failed due to:', e.reason)

	volume_info_dict = {'volume_dict': volume_info_dict}	
	return volume_info_dict

def ec2_info(ec2,region, volume_dict, volume_info_dict):


	ec2_info_dict = {}
	ec2 = assign_resource('ec2', region)
	instances = ec2.instances.filter(Filters=[{'Name': 'instance-state-name', 'Values': ['running']}])

	for instance in instances:
		for sec_group in instance.security_groups:
			for key,value in sec_group.items():
                                if key == 'GroupId':
                                        security_group_id = value
		print("instance and volume info is:",instance.id, volume_dict[instance.id])
		'''if instance.id in volume_dict.keys():
			volume = {'device_name': instance['device_name'], 'delete_on_termination': instance['delete_on_termination'], 'encrypted': instance['encrypted'], 'volume_type': instance['volume_type'], 'iops': instance['iops'], 'snapshot': instance['snapshot']}
			ec2_info_dict[instance.id] = {'vpc_subnet_id': instance.subnet_id, 'key_name': instance.key_name,'image': instance.image_id, 'group_id': security_group_id,'private_ip': instance.private_ip_address,'instance_type': instance.instance_type,'public_ip': instance.public_ip_address,'volumes': volume}
		else:
			ec2_info_dict[instance.id] = {'vpc_subnet_id': instance.subnet_id, 'key_name': instance.key_name,'image': instance.image_id, 'group_id': security_group_id,'private_ip': instance.private_ip_address,'instance_type': instance.instance_type,'public_ip': instance.public_ip_address}
	ec2_info_dict = {'ec2_dict': ec2_info_dict}
	return ec2_info_dict'''


def subnet_list(ec2,instance_list):
	'''This grabs all of the subnets that are linked to the running instances
		Parameters:
			ec2: That is just the resource passed over from ec2_describe_instances function
			instance_list: instance_list: List of all the running ec2 instances
		Returns:
			subnet_list: Is a list containing the subnet ids
			subnets: That is a dict containing additional information about the subnets
			'''
	subnets = {}
	subnet_list = [instance_list[item]['subnet_id'] for item in instance_list.keys()]
	for item in subnet_list:
		try:
			subnet = ec2.Subnet(item)
			subnets[item] = {'vpc_id': subnet.vpc_id,'az': subnet.availability_zone,'cidr': subnet.cidr_block, 'resource_tags': subnet.tags}
			if subnets[item]['resource_tags']:
				subnets = tags_dict(subnets, 'resource_tags', item)
			else:
				subnets[item]['resource_tags'] = {}
		except botocore.exceptions.ClientError as e:
			print('The subnet operation failed due to:', e.reason)
	subnets = {'subnet_dict': subnets}
	return subnet_list,subnets

def route_table_info(ec2, instance_list, subnet_list):
	'''This grabs all of the route tables that are linked to the running instances
		Parameters:
			ec2: That is just the resource passed over from ec2_describe_instances function
			instance_list: instance_list: List of all the running ec2 instances
			subnet_list: List of subnet_ids that are linked to the running ec2 instances
		Returns:
			subnet_route_table: Is a dict where the keys are the subnet id and value is the route table id
			routes: That is a dict containing additional information about the route tables
		'''
	subnet_route_table = {}
	routes = {}
	for subnet in subnet_list:
		try:
			route_table = ec2.route_tables.filter(Filters=[{'Name': 'association.subnet-id', 'Values': [subnet]}])
			for item in route_table:
				subnet_route_table[subnet] = item.id
				subnet_ids = []
				for x in item.associations_attribute:
					subnet_ids.append(x['SubnetId'])
				mapping = {'DestinationCidrBlock':'dest','GatewayId':'gateway_id','NatGatewayId':'gateway_id'}
				#Adding additional function to handle the re-mapping for the item.routes_attribute
				routes_attribute = remap_dict(mapping,item.routes_attribute)
				routes[item.id] = {'vpc_id': item.vpc_id,'subnets': subnet_ids,'routes': routes_attribute}
		except botocore.exceptions.ClientError as e:
			print('The route table operation failed due to:', e.reason)
	routes = {'route_dict': routes}
	return subnet_route_table, routes

def remap_dict(dict_map,orig_dict):
	'''This function is used to change the key:value mapping for a dict to match the Ansible mapping

	Parameters:
		dict_map: This is the new mapping
		orig_dict: Existing dict name that will have it's mapping changed

	Returns:
		new_list: A new list containing the new_dict is returned

	'''
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
	acls = {'nacl_dict': acls}
	return acl_subnet,acls


def nacl_info(entries):
	ingress = []
	egress = []
	protocols = {'-1':'all','6':'tcp','17':'udp','1':'icmp'}
	for item in entries:
		print(item)
		#if item['Egress']:
		protocol = item['Protocol']
		#Are we supporting ICMP if so then need to additional function for that
		if protocols[protocol] == 'all':
			from_port = 'Null'
			to_port = 'Null'
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

def security_groups(ec2,instance_list):
		sec_gr_list = [instance_list[item]['security_groups'] for item in instance_list.keys()]
		sec_gr_ids = [value for sec_gr in sec_gr_list for item in sec_gr for key,value in item.items() if key == 'GroupId']
		sec_gr_ids = set(sec_gr_ids)
		sec_gr = {}
	        	
		for id in sec_gr_ids:
			try:
				security_group = ec2.SecurityGroup(id)
				sec_gr[id] = {'group_id': security_group.group_id, 'group_name': security_group.group_name, 'rules': security_group.ip_permissions, 'rules_egress': security_group.ip_permissions_egress, 'vpc_id': security_group.vpc_id}
				sec_gr = security_groups_info(sec_gr,'rules',id)
				sec_gr = security_groups_info(sec_gr,'rules_egress',id)
			except botocore.exceptions.ClientError as e:
				print('The security_groups operation failed due to:', e.reason)
		sec_gr = {'sg_dict': sec_gr}
		return sec_gr


def security_groups_info(sec_gr, rule_name, sec_id):
	rule = []

	if sec_gr[sec_id][rule_name]:
		for rules in sec_gr[sec_id][rule_name]:
			#print(rules['IpProtocol'])
			if rules['IpProtocol'] != '-1':
				if rules['IpRanges']:
					for entry in rules['IpRanges']:
						rule.append(
							{'proto': rules['IpProtocol'], 'from_port': rules['FromPort'], 'to_port': rules['ToPort'],
							 'cidr_ip': entry['CidrIp']})
				elif rules['UserIdGroupPairs']:
					for entry in rules['UserIdGroupPairs']:
						rule.append(
							{'proto': rules['IpProtocol'], 'from_port': rules['FromPort'], 'to_port': rules['ToPort'],
							 'group_id': entry['GroupId']})
			elif rules['IpProtocol'] == '-1':
				if rules['IpRanges']:
					for entry in rules['IpRanges']:
						rule.append({'proto': 'all', 'cidr_ip': entry['CidrIp'], 'from_port': 'all', 'to_port': 'all'})
				elif rules['UserIdGroupPairs']:
					for entry in rules['UserIdGroupPairs']:
						rule.append(
							{'proto': rules['IpProtocol'], 'from_port': rules['FromPort'], 'to_port': rules['ToPort'],
							 'group_id': entry['GroupId']})

			sec_gr[sec_id][rule_name]= rule
	return sec_gr

	



def vpc_list(ec2,instance_list):
	'''This grabs all of the VPC that are linked to the running instances
		Parameters:
			ec2: That is just the resource passed over from ec2_describe_instances function
			instance_list: List of all the running ec2 instances
		Returns:
			vpc_list: A list of vpc_id that are linked to those running instances
			vpcs: A dict output of all the various vpc attributes linked to the various vpc instances
	'''
	vpcs = {}
	vpc_list = [instance_list[item]['vpc_id'] for item in instance_list.keys()]
	for item in vpc_list:
		try:
			vpc = ec2.Vpc(item)
			vpcs[item] = {'vpc_id': vpc.vpc_id,'dhcp_opts_id': vpc.dhcp_options_id,'cidr_block': vpc.cidr_block, 'resource_tags': vpc.tags}
			if vpcs[item]['resource_tags']:
				vpcs = tags_dict(vpcs, 'resource_tags', item)
				vpcs[item]['name'] = vpcs[item]['resource_tags']['Name']
			else:
				vpcs[item]['name'] = None
				vpcs[item]['resource_tags'] = {}
		except botocore.exceptions.ClientError as e:
			print('The vpc operation failed due to:', e.reason)
	vpcs = {'vpc_dict': vpcs}
	return vpc_list,vpcs

def tags_dict(dict_name,tag_name,key):
	'''This function converts a list of tags containing a dict into a dict so yaml does not complain about it
		Parameters:
			dict_name: A dictionary that needs to be edited
			tag_name: The tag name which would be the key in that dict
		Returns:
			dict_name: Returns the modified dict containing a dict instead of a list of dicts
	'''
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


def get_ykeykey_key(key):
	try:
		key_value = yahoo.ysecure.get_key(key)
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
	region = 'us-west-1' 

	#key = get_ykeykey_key('aws_ansible_ghe')
	#print(key)
	#value = get_ykeykey_key('aws_ansible_ghe_secret')
	#print(value)
	
	ec2,instance_list = ec2_describe_instances(region)
	print(instance_list)
	volume_list,volume_dict = volume_list(ec2,instance_list)
	print(volume_list)

	'''    
	snapshot_dict = create_snapshot(ec2,volume_list,volume_dict)
	print("snapshot info is:", snapshot_dict)
	volume_info_dict = volume_info(ec2,volume_dict,snapshot_dict)
	yaml_file(volume_info_dict,volume_file,'volume_dict')
	ec2_dict = ec2_info(ec2,region, volume_dict, volume_info_dict)
	yaml_file(ec2_dict,ec2_file,'ec2_dict')
	print(ec2_dict)
	'''

	subnet_list,subnets = subnet_list(ec2,instance_list)
	print(subnet_list,subnets)
	yaml_file(subnets,subnet_file,'subnet_dict')
	subnet_route_table,routes = route_table_info(ec2, instance_list, subnet_list)
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
	elb_info()
