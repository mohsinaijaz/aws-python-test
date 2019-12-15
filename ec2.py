import boto3
import random, string
import json
import re
import subprocess
import paramiko
import sys
import os
try:
   from io import StringIO
except ImportError:
   from io import StringIO

from botocore.config import Config

#
## Variables
#
keypair_prefix='jenkins_temp_key_'
instance_prefix='jenkins_temp_key_'
stack_prefix='jenkins_temp_stack_'
sg_id='sg-c832efba'
source_ami ='ami-000db10762d0c4c05'
#source_ami = sys.argv[1]
subnet_id='subnet-4802dd03'
#cidr_ip = sys.argv[2]
cidr_ip ='172.31.0.0/16'
ec2_size='t2.micro'
region='us-east-1'
ec2_tag_prefix='jenkins_temp_ec2_instance'


# AWS SDK calls
session = boto3.Session(region_name='us-east-1')
ec2_cli = session.client('ec2', config=Config(retries = dict(max_attempts = 50)))
ec2_res = session.resource('ec2', config=Config(retries = dict(max_attempts = 50)))
waiter = ec2_cli.get_waiter('instance_status_ok')
waiter_inst_term = ec2_cli.get_waiter('instance_terminated')


#
## Funtions
#
def random_number_generator(random_number=None):
    '''
    Creates a random string to be used to label components
    '''
    concat_random_string = ''.join(random.choice(string.ascii_lowercase + string.digits) for _ in range(16))
    return concat_random_string


def create_dynamic_key_pair(random_variable=None):
    '''
    Creates  Dynamic Key pair
    '''
    #ec2 = boto3.resource('ec2')
    key_name = keypair_prefix + random_variable
    custom_key_pair = ec2_res.create_key_pair(
        KeyName=key_name,
    )
    ssh_priv_key = custom_key_pair.key_material
    print(ssh_priv_key)
    return ssh_priv_key, key_name


def get_vpc_id(vpc_id=None):
    '''
    Gets VPC ID
    '''
    vpc_id = ec2_cli.describe_subnets(
        SubnetIds=[subnet_id],
    )

    return vpc_id['Subnets'][0]['VpcId']

#Attach a role policy
iam = boto3.resource('iam')

IamInstanceProfile = iam.InstanceProfile('JENKINS_PROFILE')

try:
    IamInstanceProfile.add_role(RoleName='JENKINS-TRUST')
except Exception:
    pass


#def create_dynamic_security_group(random_variable=None):
#    '''
#    Creates Dynamic Security Group for Test
#    '''
#    sec_group = ec2_cli.create_security_group(
#        Description='Jenkins Test Security Group',
#        GroupName=sg_prefix + random_variable,
#        VpcId=get_vpc_id(),
#    )
#    add_sg_ingress(group_id=sec_group['GroupId'])
#    return sec_group['GroupId']
#
#def add_sg_ingress(group_id=None):
#    add_sg_ssh = ec2_cli.authorize_security_group_ingress(
#        FromPort=22,
#        CidrIp=cidr_ip,
#        GroupId=group_id,
#        ToPort=22,
#        IpProtocol='tcp'
#    )


def describe_ec2_instance(instance_id=None):
    get_ec2_ip = ec2_cli.describe_instances(InstanceIds=[instance_id])

    print((get_ec2_ip['Reservations'][0]['Instances'][0]['PrivateIpAddress']))

    return get_ec2_ip['Reservations'][0]['Instances'][0]['PrivateIpAddress']


def exit_on_fail(failed_cmd=None):
    print((" %s Failed! Exiting From Test Failure" %(failed_cmd)))
    sys.exit(1)


def test_services(ec2_ip=None, secret_key=None):
    not_really_a_file = StringIO(secret_key)
    priv_key_for_shell = paramiko.RSAKey.from_private_key(not_really_a_file)
    not_really_a_file.close()
    ssh_shell = paramiko.SSHClient()
    ssh_shell.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    print("connecting")
    ssh_shell.connect(hostname = ec2_ip , username="ec2-user", pkey = priv_key_for_shell)
    print("connected")
    commands = [
            ("cat /etc/redhat-release; echo $?","Print out Red Hat Version:", "os_version.txt"),
        ]
    for command, description, filename in commands:
        stdin, stdout, stderr = ssh_shell.exec_command(command)
        lines = stdout.readlines()
        error_code = str(lines[-1]).strip()
        output = ''.join(lines[0:-1])
        if error_code == '0':
            print(description)
            print(("%s successful with error code %s - SUCCESS\n" %(command,error_code)))
            if filename:
                with open(filename,'w') as file:
                    print(('Writing file {}'.format(filename)))
                    print(('{}\n'.format(output)))
                    file.write(output)
        else:
            print(description)
            print(("%s failed with error code %s - FAILURE\n" %(command,error_code)))
            clean_up(instance_id,key_name)
            exit_on_fail(command)
    nessus_scan(ec2_ip)
    clean_up(instance_id,key_name)
    ssh_shell.close()
#
#
#def nessus_scan(ec2_ip):
#    '''
#    Run Nessus Scan
#    '''
#    nessus_scan_params = ("%s '%s' '%s' '%s' '%s'" %(nessus_scan_path,nessus_login,nessus_password,scan_id,ec2_ip))
#    #nessus_scan_params = ("exit 1")
#    if (os.system(nessus_scan_params) != 0):
#        clean_up(instance_id,key_name)
#        exit_on_fail(nessus_scan_path)
#
#    '''
#    Run vulnerability scan
#    '''
#    nessus_scan_params = ("%s '%s' '%s' '%s' '%s'" %(nessus_scan_path,nessus_login,nessus_password,vulnerability_scan_id,ec2_ip))
#    #nessus_scan_params = ("exit 1")
#    if (os.system(nessus_scan_params) != 0):
#        clean_up(instance_id,key_name)
#        exit_on_fail(nessus_scan_path)
#
#
def create_dynamic_instance(random_variable=None):
    '''
    Creates Dynamic EC2 Instance for Test
    Creates Key pair inside function and returns those values
        in order to be used for clean up when complete
    '''
    key_priv, key_name = create_dynamic_key_pair(random_variable)
    #sec_group_id = create_dynamic_security_group(random_variable)

    create_instance = ec2_res.create_instances(
        ImageId=source_ami,
        InstanceType=ec2_size,
        KeyName=key_name,
        IamInstanceProfile={
            'Arn': IamInstanceProfile.arn
        },
        MaxCount=1,
        MinCount=1,
        Monitoring={
            'Enabled': False
        },
        SecurityGroupIds=[
            sg_id,
        ],
        TagSpecifications=[
            {
            'ResourceType': 'instance',
            'Tags': [
                {
                    'Key': 'Name',
                    'Value': ec2_tag_prefix + random_variable,
                },
                ]
            },
        ],
        SubnetId=subnet_id,
        #EbsOptimized=True,
    )

    #
    ## Waits for EC2 Instance to be running
    #
    waiter.wait(
        InstanceIds=[
            create_instance[0].id,
        ],
        WaiterConfig={
            'Delay': 15,
            'MaxAttempts': 40
        }
    )

    print("System is Up!")

    ec2_instance_ip_address = describe_ec2_instance(create_instance[0].id)

    return create_instance[0].id, ec2_instance_ip_address, key_priv, key_name


def del_instance(instance_id=None):
    print(("Terminating Instance: %s" %(instance_id)))
    ec2_cli.terminate_instances(
        InstanceIds=[instance_id,],
    )

    #
    ## Wait for EC2 Instance to fully terminate
    #
    waiter_inst_term.wait(
        InstanceIds=[instance_id,],
        WaiterConfig={
            'Delay': 123,
            'MaxAttempts': 123
        }
    )


def del_key_pair(key_name=None):
    print(("Deleting Key Pair: %s" %(key_name)))
    ec2_cli.delete_key_pair(
        KeyName=key_name,
    )


#def del_security_group(sg_id=None):
#    print("Deleting Security Group: %s" %(sg_id))
#    ec2_cli.delete_security_group(
#        GroupId=sg_id,
#    )


def clean_up(instance_id=None,key_name=None):
    del_instance(instance_id)
    del_key_pair(key_name)
    #del_security_group(sg_id)
    print(("Finished clean up of: EC2 ID: %s - Key Name: %s" %(instance_id,key_name)))


random_variable =random_number_generator()
instance_id, ec2_instance_ip_address, key_priv, key_name = create_dynamic_instance(random_variable)
test_services(ec2_instance_ip_address, key_priv)
