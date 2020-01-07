import os
import boto3

AMI = 'ami-000db10762d0c4c05'
INSTANCE_TYPE = 't2.micro'
KEY_NAME = 'K8testkey'
SUBNET_ID = 'subnet-4802dd03'

ec2 = boto3.resource('ec2')

def instance_one(event, context):

    instance = ec2.create_instance(
        ImageId=AMI,
        InstanceType=INSTANCE_TYPE,
        KeyName=KEY_NAME,
        SubnetId=SUBNET_ID
        MaxCount=1,
        MinCount=1
    )
    print("New instace created:", instance[0].id)
