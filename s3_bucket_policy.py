#!/usr/bin/env python3
# @AB feel free to use it however you wish!

import boto3
import botocore
import yahoo.ysecure


def assign_client(service_name):
	client = boto3.client(
		service_name,
		aws_access_key_id=get_ykeykey_key('aws_ansible_ghe'),
		aws_secret_access_key=get_ykeykey_key('aws_ansible_ghe_secret'),
	)
	return client


def assign_client_region(service_name, region):
	client = boto3.client(
		service_name,
		region,
		aws_access_key_id=get_ykeykey_key('aws_ansible_ghe'),
		aws_secret_access_key=get_ykeykey_key('aws_ansible_ghe_secret'),
	)
	return client


def get_regions(ec2):
	regions = []
	response = ec2.describe_regions()
	for item in response['Regions']:
		regions.append(item['RegionName'])
	return regions


def get_bucket_names(s3, regions):
	bucket_list = []
	bucket_dict = {}

	for region in regions:
		response = s3.list_buckets()
		for item in response['Buckets']:
			bucket_name = item['Name']
			bucket_list.append(bucket_name)
			bucket_dict[bucket_name] = region
	return bucket_list, bucket_dict


def get_ykeykey_key(key):
	try:
		key_value = yahoo.ysecure.get_key(key)
		return key_value
	except RuntimeError:
		print('Could not execute the call to ysecure')


def check_bucket_encryption(s3, bucket_name):
	try:
		print('Checking bucket encryption for: ', bucket_name)
		encrypt = s3.get_bucket_encryption(Bucket=bucket_name)
	except botocore.exceptions.ClientError as e:
		print('The get bucket encryption operation failed due to:', e.response['Error']['Code'])
		encrypt = None
	return encrypt


def check_bucket_policy(s3, bucket_name):
	try:
		print('Checking bucket policy for: ', bucket_name)
		policy = s3.get_bucket_policy(Bucket=bucket_name)
	except botocore.exceptions.ClientError as e:
		print('The get bucket policy operation failed due to:', e.response['Error']['Code'])
		policy = None
	return policy

def check_bucket_logging(s3, bucket_name):
	try:
		print('Checking bucket logging for: ', bucket_name)
		logging = s3.get_bucket_logging(Bucket=bucket_name)
	except botocore.exceptions.ClientError as e:
		print('The get bucket logging operation failed due to:', e.response['Error']['Code'])
		logging = None
	return logging


def make_policy(region_name, bucket):
	policy_info = '''{
	"Version": "2012-10-17",
	"Statement": [
		{
			"Effect": "Deny",
			"Principal": "*",
			"Action": "s3:*",
			"Resource": "arn:aws:s3:::{bucket_name}/*",
			"Condition": {
				"Bool": {
					"aws:SecureTransport": "false"
				}
			}
		},
		{
			"Sid": "AWSCloudTrailAclCheck20150319",
			"Effect": "Allow",
			"Principal": {
				"Service": "logs.{region}.amazonaws.com"
			},
			"Action": "s3:GetBucketAcl",
			"Resource": "arn:aws:s3:::{bucket_name}"
		},
		{
			"Sid": "AWSCloudTrailWrite20150319",
			"Effect": "Allow",
			"Principal": {
				"Service": "logs.{region}.amazonaws.com"
			},
			"Action": "s3:PutObject",
			"Resource": "arn:aws:s3:::{bucket_name}/*",
			"Condition": {
				"StringEquals": {
					"s3:x-amz-acl": "bucket-owner-full-control",
					"s3:x-amz-server-side-encryption": "AES256"
				},
				"Bool": {
					"aws:SecureTransport": "true"
				}
			}
		},
		{
			"Sid": "AWSCloudTrailAclCheck20150319",
			"Effect": "Allow",
			"Principal": {
				"Service": "cloudtrail.amazonaws.com"
			},
			"Action": "s3:GetBucketAcl",
			"Resource": "arn:aws:s3:::{bucket_name}"
		},
		{
			"Sid": "AWSCloudTrailWrite20150319",
			"Effect": "Allow",
			"Principal": {
				"Service": "cloudtrail.amazonaws.com"
			},
			"Action": "s3:PutObject",
			"Resource": "arn:aws:s3:::{bucket_name}/*",
			"Condition": {
				"StringEquals": {
					"s3:x-amz-acl": "bucket-owner-full-control",
					"s3:x-amz-server-side-encryption": "AES256"
				},
				"Bool": {
					"aws:SecureTransport": "true"
				}
			}
		}
	]
}'''
	policy_info = policy_info.replace('{bucket_name}', bucket)
	policy_info = policy_info.replace('{region}', region_name)
	return policy_info


def push_policy(s3, bucket, policy_info):
	try:
		print("Adding this policy for ", bucket, policy_info)
		s3.put_bucket_policy(Bucket=bucket, Policy=policy_info)
	except botocore.exceptions.ClientError as e:
		print("The push bucket policy operation failed due to:", e.response['Error']['Code'])


def push_encryption(s3, bucket):
	encryption = {
		'Rules': [
			{
				'ApplyServerSideEncryptionByDefault': {
					'SSEAlgorithm': 'AES256'
				}
			},
		]
	}
	try:
		print("Adding encryption for ", bucket)
		s3.put_bucket_encryption(Bucket=bucket, ServerSideEncryptionConfiguration=encryption)
	except botocore.exceptions.ClientError as e:
		print("The push bucket encryption operation failed due to:", e.response['Error']['Code'])

def push_logging(s3, bucket):
	logging={
		'LoggingEnabled': {
			'TargetBucket': bucket,
			'TargetPrefix': bucket
		}
	}
	try:
		print("Adding this logging for ", bucket)
		s3.put_bucket_logging(Bucket=bucket, BucketLoggingStatus=logging)
	except botocore.exceptions.ClientError as e:
		print("The push bucket logging operation failed due to:", e.response['Error']['Code'])



if __name__ == '__main__':
	ec2 = assign_client('ec2')
	s3 = assign_client('s3')
	regions = get_regions(ec2)
	bucket_names, bucket_region = get_bucket_names(s3, regions)
	for bucket in bucket_names:
		bucket = bucket.strip()
		policy = check_bucket_policy(s3, bucket)
		encrypt = check_bucket_encryption(s3, bucket)
		logging = check_bucket_logging(s3, bucket)
		if not logging or 'LoggingEnabled' not in logging:
			logging = None
		if not policy:
			region = bucket_region[bucket]
			region = region.strip()
			policy_info = make_policy(region, bucket)
			push_policy(s3, bucket, policy_info)
		if not encrypt:
			push_encryption(s3, bucket)
		if not logging:
			push_logging(s3, bucket)

