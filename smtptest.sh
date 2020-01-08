#!/usr/bin/env bash

ec2_size='t2.micro'
cidr_ip='172.31.0.0/16'
subnet_id='subnet-4802dd03'
region='us-east-1'
source_ami='ami-000db10762d0c4c05'
#source_ami=`aws ssm get-parameter --name "/ccs/ami/rhel7/lvm/latest"`
smtp_loadbalancer=''
securitygroup_id='sg-c832efba'
smtp_eni_1='eni-0331c5e11c70144db'
smtp_eni_2='eni-096a0c47835b10ece'
smtp_delete_1=$1
smtp_delete_2=$2

#echo "Deatching SMTP ENI 1"
#aws ec2 detach-network-interface --attachment-id $smtp_eni_1

#sleep 60

echo "Now Terminating SMTP 1"
aws ec2 terminate-instances --instance-ids $smtp_delete_1
#aws elb deregister-instances-from-load-balancer --load-balancer-name $smtp_loadbalancer --instances $smtp_delete_1

echo "Now Terminating SMTP 2"
aws ec2 terminate-instances --instance-ids $smtp_delete_2
#aws elb deregister-instances-from-load-balancer --load-balancer-name $smtp_loadbalancer --instances $smtp_delete_2


sleep 2m

#create SMTP 1 instance
echo "Creating New SMTP1 instance"
instance_id_1=$(aws ec2 run-instances --image-id $source_ami \
--count 1 --instance-type $ec2_size --key K8testkey \
--security-group-ids $securitygroup_id \
--subnet-id $subnet_id --no-associate-public-ip-address --region $region --query 'Instances[0].InstanceId' --output text)


if [[ -z $instance_id_1 ]]
then
    echo "ERROR. Unable to create an instance."
    exit 1
fi

#echo "Creating instance. Waiting..."
echo "Instance ID is $instance_id_1"
aws ec2 wait instance-status-ok --instance-ids $instance_id_1

aws ec2 attach-network-interface --network-interface-id $smtp_eni_1 --instance-id $instance_id_1 --device-index 1
#aws elb register-instances-with-load-balancer --load-balancer-name $smtp_loadbalancer --instances $instance_id_1


instance_ip_1=$(aws ec2 describe-instances --instance-ids $instance_id_1 \
--query 'Reservations[0].Instances[0].NetworkInterfaces[0].PrivateIpAddresses[0].PrivateIpAddress' --output text)
echo "SMTP 1 IP is $instance_ip_1"

sleep 2m



#create SMTP 2 instance
echo "Creating New SMTP2 instance"
instance_id_2=$(aws ec2 run-instances --image-id $source_ami \
--count 1 --instance-type $ec2_size --key K8testkey \
--security-group-ids $securitygroup_id \
--subnet-id $subnet_id --no-associate-public-ip-address --region $region --query 'Instances[0].InstanceId' --output text)



if [[ -z $instance_id_2 ]]
then
    echo "ERROR. Unable to create an instance."
    exit 1
fi

#echo "Creating instance. Waiting..."
echo "Instance ID is $instance_id_2"
aws ec2 wait instance-status-ok --instance-ids $instance_id_2

aws ec2 attach-network-interface --network-interface-id $smtp_eni_2 --instance-id $instance_id_2 --device-index 1
#aws elb register-instances-with-load-balancer --load-balancer-name $smtp_loadbalancer --instances $instance_id_2

instance_ip_2=$(aws ec2 describe-instances --instance-ids $instance_id_2 \
--query 'Reservations[0].Instances[0].NetworkInterfaces[0].PrivateIpAddresses[0].PrivateIpAddress' --output text)
echo "SMTP 2 IP is $instance_ip_2"
#run tests
### OTHER TESTS GO HERE
#kick off nessus scan
#./run-nessus-scan.sh $nessus_login $nessus_password $profile_id $instance_ip
