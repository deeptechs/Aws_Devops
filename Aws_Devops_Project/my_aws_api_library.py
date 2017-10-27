import io
import boto3
import pandas

# For detailed logs
# boto3.set_stream_logger('')


class MyAws:

    _conn_args, _ec2R, _ssmC, _iamR, _pb_ky_fl, _key_pair_name = None, None, None, None, None, None

    def __init__(self, aws_cr_fl, pb_ky_fl):

        """Initialize the aws service objects with the provided environmental variable.

        Args:
            aws_cr_fl: Csv file path of Aws access key id and security access key.
            pb_ky_fl: pub file of the Aws SSH public key.
        """
        self.conn_args = self._read_con_arg(aws_cr_fl)
        self.ec2R = boto3.resource('ec2', **self.conn_args)
        self.ssmC = boto3.client('ssm', **self.conn_args)
        self.iamR = boto3.resource('iam', **self.conn_args)
        self.pb_ky_fl = pb_ky_fl

        self.key_pair_name = "COMPANY_KEYPAIR"
        self._find_key_pair()

    def create_ec2_instance(self, customer_id, node_type):

        """Crete the Ec2 instance, and save the customer-id tag value.

        Each instance will have Amazon SSMAgent at launch. Tested only with Amazon Linux Instances (Free Tier).

        Each instance have *"AmazonEC2RoleforSSM"* to build a SSM connection for remote command run.

        If node_type **"Peer"**, Instance is *t2.micro* and has 10gb *EBS* disk.

        If node_type **"Manager"**, Instance is *t2.medium* and has 20gb *EBS* disk.

        Args:
            customer_id: The customer id tag value of instance that will be created.

            node_type  : The node type of instance that will be created. ("Peer" or "Manager")

        Returns:
            The created instance id. 0 shows error.

        """

        # Define "userdata field" to be run at instance launch for SSM Agent installation.
        # Creating a dummy script file to run it future
        # Note: After 2017.09 Amazon Linux AMIs have SSM default.
        # If you manually want to install SSM add this line to runcmd:
        # - cd /tmp
        # - yum install -y https://s3.amazonaws.com/ec2-downloads-windows/SSMAgent/latest/linux_amd64/amazon-ssm-agent.rpm
        # For more information about yaml, cloud-init visit:
        # http://cloudinit.readthedocs.io/en/latest/topics/examples.html
        userdata ="""#cloud-config

        runcmd:
         - 
         
        write_files:
         -   path: /home/sysop/updatePackages.sh
             content: |
               date
               uname -a
             owner: root:root
             permissions: '0700'
"""

        rolename = "amazonec2ssmrole"
        i_pro_name = "ins_pro_for_ssm"

        # Create an iam instance profile and add required role to this instance profile.
        # Create a role and attach a policy to it if not exist.
        # Instances will have this role to build ssm (ec2 systems manager) connection.
        try:
            self.iamR.meta.client.get_instance_profile(InstanceProfileName=i_pro_name)
        except self.iamR.meta.client.exceptions.NoSuchEntityException:
            self.iamR.create_instance_profile(InstanceProfileName=i_pro_name)
        try:
            self.iamR.meta.client.get_role(RoleName=rolename)
        except self.iamR.meta.client.exceptions.NoSuchEntityException:
            self.iamR.create_role(
                AssumeRolePolicyDocument='{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":'
                                         '{"Service":["ec2.amazonaws.com"]},"Action":["sts:AssumeRole"]}]}',
                RoleName=rolename)
            role = self.iamR.Role(rolename)
            role.attach_policy(PolicyArn='arn:aws:iam::aws:policy/service-role/AmazonEC2RoleforSSM')
            self.iamR.meta.client.add_role_to_instance_profile(InstanceProfileName=i_pro_name, RoleName=rolename)

        iam_ins_profile = {'Name': i_pro_name}

        if node_type == "Manager":
            instance = self.ec2R.create_instances(
                ImageId='ami-c7ee5ca8',
                MinCount=1,
                MaxCount=1,
                UserData=userdata,
                InstanceType='t2.medium',
                KeyName=self.key_pair_name,
                IamInstanceProfile=iam_ins_profile,
                BlockDeviceMappings=[{"DeviceName": "/dev/xvda", "Ebs": {"VolumeSize": 20}}])
        elif node_type == "Peer":
            instance = self.ec2R.create_instances(
                ImageId='ami-c7ee5ca8',
                MinCount=1,
                MaxCount=1,
                UserData=userdata,
                InstanceType='t2.micro',
                KeyName=self.key_pair_name,
                IamInstanceProfile=iam_ins_profile,
                BlockDeviceMappings=[{"DeviceName": "/dev/xvda", "Ebs": {"VolumeSize": 10}}])
        else:
            print("Wrong Node Type")
            return 0

        # Wait for the instance state, default one wait is 15 seconds, 40 attempts
        print('Waiting for instance {0} to switch to running state'.format(instance[0].id))
        waiter = self.ec2R.meta.client.get_waiter('instance_running')
        waiter.wait(InstanceIds=[instance[0].id])
        instance[0].reload()
        print('Instance is running, public IP: {0}'.format(instance[0].public_ip_address))

        self.ec2R.create_tags(Resources=[instance[0].id], Tags=[{'Key': 'customer-id', 'Value': str(customer_id)}])
        self.ec2R.create_tags(Resources=[instance[0].id], Tags=[{'Key': 'node-type', 'Value': node_type}])

        return instance[0].id

    def get_customer_by_instance_id(self, ins_id):

        """When given an instance ID, return the Customer IDs from the Instance's customer-id tag.

        Args:
            ins_id: Instance ID

        .. warning::

            Assumes that an instance should be owned by only one customer.

        Returns:
            Customer ID
        """
        ec2instance = self.ec2R.Instance(ins_id)
        cus_id = ''
        if ec2instance.tags and ec2instance.state["Name"] == "running":
            for tags in ec2instance.tags:
                if tags["Key"] == 'customer-id':
                    cus_id = tags["Value"]
        return cus_id

    def get_instance_by_customer_id(self, cid):

        """When given a Customer ID, return the Instances's IDs using the Instance's customer-id tag.

        Args:
            cid: Customer ID

        Returns:
            Instance Id list.

        """
        instancelst = list()
        for instance in self.ec2R.instances.all():
            if instance.tags and instance.state["Name"] == "running":
                for tags in instance.tags:
                    if tags["Key"] == 'customer-id' and tags["Value"] == cid:
                        instancelst.append(instance.id)
        return instancelst

    def get_instance_by_node_type(self, ntype):

        """ When given an Node Type, return the instance IDs using the Instance's node-type tag.

        Args:
            ntype: Instance Node Type

        Returns:
            Instance Id list

        """
        instancelst = list()
        for instance in self.ec2R.instances.all():
            if instance.tags and instance.state["Name"] == "running":
                for tags in instance.tags:
                    if tags["Key"] == 'node-type' and tags["Value"] == ntype:
                        instancelst.append(instance.id)
        return instancelst

    def terminate_instances(self, i_id):
        """Terminate the specified Instances.

        Args:
            i_id: Instance Id list. "ALL" means all IDs.

        Returns:
            Prints the termination output
        """
        id_list = list()
        if i_id == 'ALL':
            for instance in self.ec2R.instances.all():
                id_list.append(instance.id)
        else:
            i_id = i_id.split()
            id_list.extend(i_id)

        for instance_id in id_list:
            instance = self.ec2R.Instance(instance_id)
            response = instance.terminate()
            print(response)

    def get_all_instances(self):
        """List the all Instances according to their sorted Customer ID

        Returns:
            List of (customer_id, instance_id, instance_state)
        """
        cust = list()
        for instance in self.ec2R.instances.all():
            if instance.tags:  # Instance a hic tag atanmamis ise nonetype olmakta, bu sebeple kontrol gerek.
                for tags in instance.tags:
                    if tags["Key"] == 'customer-id':
                        c_id = tags["Value"]
                        if instance.state["Name"] == "pending" or instance.state["Name"] == "running":
                            if instance.public_ip_address:
                                cust.append([c_id, instance.id, instance.public_ip_address])
                            else:
                                cust.append([c_id, instance.id, instance.state["Name"]])
        cust.sort()
        return cust

    def execute_commands_on_linux_instances(self, commands, instance_ids):

        """Execute the specified commands on specified Instances using SSM service.

        Args:
            commands: Command phrases that will be executed

            instance_ids: Instances that will run the commands

        Returns: List of;
            1. Instances that have SSM agent and are in specified Instances,
            2. Instances that didn't run the command and are in specified Instances,
            3. Command run outputs.

        .. seealso::

            Amazon EC2 Systems Manager (SSM) requires;

            1. An IAM role for EC2 instances that will process commands. There should be a system manager role and the
            instance should use this role ! (It is done while creation instance)

            2. And a separate role for users executing commands. Aws IAM user that has access and secret keys should
            have ssm permission. (i.e. *AmazonSSMFullAccess*)

            http://docs.aws.amazon.com/systems-manager/latest/userguide/sysman-configuring-access-policies.html

        """
        all_ssm_enabled_instances, ssm_enabled_instances, not_worked_instances = [], [], []
        not_worked_instances = instance_ids.copy()
        all_ssm_enabled_instances = list()
        outputs = list({})
        not_executed = list()

        # Select only the Instances that have an active ssm agent.
        if len(self.ssmC.describe_instance_information()['InstanceInformationList']) > 0:
            resp = self.ssmC.describe_instance_information(MaxResults=20)['InstanceInformationList']
            for ins in resp:
                all_ssm_enabled_instances.append(ins['InstanceId'])
            ssm_enabled_instances = list(set(all_ssm_enabled_instances).intersection(instance_ids))
            not_worked_instances = list(set(instance_ids).difference(all_ssm_enabled_instances))

            # Now, send the command !
            resp = self.ssmC.send_command(
                DocumentName="AWS-RunShellScript",
                Parameters={'commands': [commands]},
                InstanceIds=ssm_enabled_instances,
            )

            # get the command id generated by the send_command
            com_id = resp['Command']['CommandId']

            # Wait until all the commands status are out of Pending and InProgress. Check if infinite loops !
            while True:
                list_comm = self.ssmC.list_commands(CommandId=com_id)
                if list_comm['Commands'][0]['Status'] == 'Pending' or list_comm['Commands'][0]['Status'] == \
                        'InProgress':
                    continue
                else:
                    # Commands on all Instances were executed
                    break

            # Get the responses the instances gave to this command. (stdoutput and stderror)
            # Although the command could arrive to instance, if it couldn't be executed by the instance (response -1)
            # it will be addes to not_executed list
            for i in ssm_enabled_instances:
                resp2 = self.ssmC.get_command_invocation(CommandId=com_id, InstanceId=i)
                if resp2['ResponseCode'] == -1:
                    not_executed.append(i)
                else:
                    outputs.append({'ins_id': i, 'stdout': resp2['StandardOutputContent'],
                                    'stderr': resp2['StandardErrorContent']})

            # Remove the instance that couldn't execute the command ever, add it to not_worked_instances
            ssm_enabled_instances = list(set(ssm_enabled_instances).difference(not_executed))
            not_worked_instances.extend(not_executed)

            return ssm_enabled_instances, not_worked_instances, outputs
        else:
            print("There is no available instance that has a worked SSM!")
            return ssm_enabled_instances, not_worked_instances, outputs

    def make_backup(self, n_id):

        """Backup the specified Instance's "/data" mount point.

        For clearness, first, script creates a volume for Instance, format it and mount it to /data mount point.

        .. note::

            Don't forget to provide an IAM role (policy --> *AmazonEC2RoleforSSM*) for the Instance and permission
            (*AmazonSSMFullAccess*) for the user. This script uses SSM send_command !


        Args:
            n_id: Instance Id that will be backed up.

        Returns:
            Snapshot Id of the backup or None if errors.

        """
        ins = self.ec2R.Instance(n_id)
        s_id = None

        device_name = self._generate_device_name(n_id)
        if device_name is None:
            print('There is no available any proper device name')
            return None

        # Only for testing purpose, create a volume and attach it to instance with device_name device. Then mount it.
        # Now we have a /data mount point to backup.
        self._create_and_mount(device_name, n_id)

        # Starting to backup, list the devices and their mount points, get the device that has /data mount point
        a, b, out = self.execute_commands_on_linux_instances('lsblk;', [n_id])
        print(out[0]['stdout'])

        # Check the stdout if there is a /data mount point, if exists get the device name and convert to proper name.
        output_f = io.StringIO(out[0]['stdout'])

        dev_name = None
        for line in output_f:
            line = line.split()
            if line[-1] == '/data':
                dev_name = '/dev/sd' + str(line[0]).split('xvd')[-1]
                break
        if dev_name is None:
            print("There is no mount point named '/data' in this Instance")
            return None

        # Creating snapshot of Instance's device named by "dev_name"
        for device in ins.block_device_mappings:
            if device.get('DeviceName') == dev_name:
                snapshot = self.ec2R.create_snapshot(Description='My first snapshot', VolumeId=device.get('Ebs').
                                                     get('VolumeId'))
                print("Creating Snapshot...\n")
                snapshot.wait_until_completed()
                print("Snapshot Creation Done\n")
                s_id = snapshot.snapshot_id

        if s_id is None:
            print("Error on getting device that has /data mount point ")
            return None

        return s_id

    def _create_and_mount(self, device_name, n_id):

        """Create a volume and name it with device_name on specified Instance

        Args:
            device_name: Device Name

            n_id: Instance ID

        .. seealso::

            When attaching /dev/sdf aws renames it to /dev/xvdf (incrementing the f character g,h,...)
            For more information about naming : http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/device_naming.html

        """
        instance = self.ec2R.Instance(n_id)
        avz = instance.placement['AvailabilityZone']
        print("Creating volume...\n")
        resp = self.ec2R.meta.client.create_volume(AvailabilityZone=avz, Size=1)
        waiter = self.ec2R.meta.client.get_waiter('volume_available')
        waiter.wait(VolumeIds=[resp.get('VolumeId')])

        print("Attaching volume to instance...\n")
        self.ec2R.meta.client.attach_volume(Device=device_name, InstanceId=n_id, VolumeId=resp.get('VolumeId'))
        waiter = self.ec2R.meta.client.get_waiter('volume_in_use')
        waiter.wait(VolumeIds=[resp.get('VolumeId')])

        print("Volume created and attached to instance, formatting as Ext4 and mounting...\n")
        self.execute_commands_on_linux_instances('sudo mkdir /data;', [n_id])
        self.execute_commands_on_linux_instances('sudo mkfs -t ext4 ' + device_name, [n_id])
        self.execute_commands_on_linux_instances('sudo mount ' + device_name + " /data" + ' -t ext4', [n_id])
        print("Mounted as /data\n")

    def list_backups(self, node_id):
        """Return all the backups belongs to specified Instance, with their start-time.

        Args:
            node_id: Instance ID

        Returns:
            List of (Snapshot ID, Snapshot Start-time), None if errors.

        """
        snaps_date = list()

        instance = self.ec2R.Instance(node_id)
        volumes = instance.volumes.all()
        vol_id_list = [v.id for v in volumes]

        snaps = self.ec2R.meta.client.describe_snapshots(Filters=[{'Name': 'volume-id', 'Values': vol_id_list}])
        for snap in snaps['Snapshots']:
            snaps_date.append([snap['SnapshotId'], str(snap['StartTime'])])

        if snaps_date:
            return snaps_date
        else:
            return None

    def roll_back(self, back_id, n_id):

        """Search for the volumes associate with the given snapshot, detach and delete these volumes.
        Create new volumes from specified snapshot then attach them to the instance. While doing this steps, take into
        account the mount points.


        Args:
            back_id: Snapshot ID that will restore

            n_id: Instance ID

        Returns:
            True if success. Otherwise False.

        """
        instance = self.ec2R.Instance(n_id)
        volumes = instance.volumes.all()
        vol_id_list = list()

        # Find the volumes assosiate with the given snapshot
        for v in volumes:
            if v.snapshot_id == back_id:
                vol_id_list.append(v.volume_id)

        # There is no volumes associated with the snapshot ID.
        if len(vol_id_list) == 0:
            print("No Volumes on Instance, associated with the snapshot ID")
            return None

        for old_vol_id in vol_id_list:

            if old_vol_id in vol_id_list:

                # Find the device name of the old volume
                volume = self.ec2R.Volume(old_vol_id)
                ins_dev_name = volume.attachments[0]['Device']
                aws_dev_name = 'xvd' + str(ins_dev_name).split('sd')[-1]

                # List the devices and their mount points on instance, get the mount point of instance' device,to umount
                a, b, out = self.execute_commands_on_linux_instances('lsblk;', [n_id])
                print(out[0]['stdout'])

                # Check the stdout if there is dev_name, if exists get the mount point.
                output_f = io.StringIO(out[0]['stdout'])
                mp_name = None
                for line in output_f:
                    line = line.split()
                    if line[0] == aws_dev_name:
                        mp_name = line[-1]
                        break
                if mp_name is None:
                    print("Device Name Error")
                    return None

                # Umouunt the mount point
                self.execute_commands_on_linux_instances('sudo umount ;' + mp_name, [n_id])

                # Detach the old volume (Assumes not a root volume, if so stop the instance)
                instance.detach_volume(VolumeId=old_vol_id)
                print("Detaching old volume..\n")
                waiter = self.ec2R.meta.client.get_waiter('volume_available')
                waiter.wait(VolumeIds=[old_vol_id])
                print("Old volume detached\n")

                # Create new volume with given snapshot
                resp = self.ec2R.meta.client.create_volume(AvailabilityZone='us-east-2a', SnapshotId=back_id)
                new_vol_id = resp.get('VolumeId')
                print("Creating Volume...\n")
                waiter = self.ec2R.meta.client.get_waiter('volume_available')
                waiter.wait(VolumeIds=[new_vol_id])
                print("Volume Created\n")

                # Attach new volume to the instance
                self.ec2R.meta.client.attach_volume(Device=ins_dev_name, InstanceId=n_id, VolumeId=new_vol_id)
                waiter = self.ec2R.meta.client.get_waiter('volume_in_use')
                waiter.wait(VolumeIds=[new_vol_id])

                print("New volume created, attached to instance, formatting Ext4 and mounting...\n")
                self.execute_commands_on_linux_instances('sudo mkdir /data;', [n_id])
                self.execute_commands_on_linux_instances('sudo mkfs -t ext4 ' + ins_dev_name, [n_id])
                self.execute_commands_on_linux_instances('sudo mount ' + ins_dev_name + ' ' + mp_name + ' -t ext4',
                                                         [n_id])

                # Delete the old volume
                self.ec2R.meta.client.delete_volume(VolumeId=old_vol_id)
                print("Deleting Old Volume...\n")
                waiter = self.ec2R.meta.client.get_waiter('volume_deleted')
                waiter.wait(VolumeIds=[old_vol_id])
                print("Old Volume Deleted\n")

            else:
                print(
                    "There is no related attached volume with the snapshot, on instance, not enough information to "
                    "roll back")
                return None
        return True

    def _generate_device_name(self, n_id):
        """Try to find a proper device name, searches from /dev/sdf to /dev/sdp.

        Returns:
            Returns an unused device name formatted as "/dev/sd?" or if not found returns None
        """
        d_name = '/dev/sdf'
        num = ord('f')
        used_device_names = set()
        ins = self.ec2R.Instance(n_id)
        for device in ins.block_device_mappings:
            used_device_names.add(device['DeviceName'])

        while True:
            if d_name in used_device_names:
                num = num + 1
                if num > ord('p'):
                    return None
                d_name = '/dev/sd' + chr(num)
            else:
                return d_name

    @staticmethod
    def _read_con_arg(cred_file):

        """Read the Access Key Id and Secret Access Key from a csv credential file downloaded from Aws portal.

        Args:
            cred_file: File that consists Aws credentials.

        Returns:
            Connection string dictionary (Keys are aws_access_key_id, aws_secret_access_key, region_name)

        .. warning::

            Set the region default 'eu-central-1'
        """
        df = pandas.read_csv(cred_file, sep=',')

        access_key_id = df.loc[0, 'Access key ID']
        secret_access_key = df.loc[0, 'Secret access key']

        dic = {
            'aws_access_key_id': access_key_id,
            'aws_secret_access_key': secret_access_key,
            'region_name': 'eu-central-1'
        }

        return dic

    def _find_key_pair(self):

        """Create the key pair named "COMPANY_KEYPAIR", if not exist.

        First, check if there is a keypair named "COMPANY_KEYPAIR" on EC2 service.
        If exists use it  and return True
        If not exist, check if there is a local public key provided by **COMPANY_PUBKEY** env. variable.
        If there is public key, use it and import key pair on EC2 service and return True. Other wise False.

        .. note::

            If there is no RSA public key, It can be easily generated from a RSA private key with a 3rd party tool such
            as PuTTYgen. Importing the public key provides no Private Key transfer to AWS or any other 3rd party sides.

        Returns:
            True if key pair import success or not necessary to import, otherwise False.
        """

        response = self.ec2R.meta.client.describe_key_pairs()

        # Check that if there is a key pair named by key_pair_name.
        for k in response['KeyPairs']:
            if k['KeyName'] == self.key_pair_name:
                return True

        # Check that if there is a provided public key.
        if not self.pb_ky_fl:
            return False

        # No key pair named by key_pair_name, generate the key pair using public key.
        fp = open(self.pb_ky_fl)
        pub_key_material = fp.read()
        fp.close()
        self.ec2R.meta.client.import_key_pair(KeyName=self.key_pair_name, PublicKeyMaterial=pub_key_material)
        return True
