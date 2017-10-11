from subprocess import call
from random import randint

def run():

    """This script demonstrate the solution of the challenge at:

    https://github.com/picussecurity/picus-challenge-questions/blob/master/devops/Fleet.md

    Simply run this script (adjusting the call procedure you desire) to demonstrate all 7 challenge or
    call directly "foo" module in bash as written in challenge's github page.

    .. note::

        Before running this script, follow the steps if not available;

        1. Create an AWS account on portal. https://portal.aws.amazon.com/billing/signup

        2. Create a IAM User in this account. https://console.aws.amazon.com/iam/home?region=us-east-2#/users

        2.1. Select Access Type as "Programmatic access" for this user. Thus, enables an access key ID and secret access
        key for the AWS API, CLI, SDK, and other development tools.

        2.2. Attach *"AmazonEC2FullAccess","AmazonSSMFullAccess" and "IAMFullAccess"* policy for the user.

        2.3. Set **"AWS_CRED_FILE"** env. variable showing access key ID & secret access key a in a csv file downloaded
        from AWS (2.1).

        2.4. Set **"COMPANY_PUBKEY"**  env. variable showing Public Key to import key pair on EC2 service.

        .. important::

            AMI (Amazon Machine Image) is selected as Amazon Linux AMI. Region is selected as Ohio and hard coded AMI
            (ami-ea87a78f) is in also Ohio (us-east-2) region.

        2.5. To run this script, you should install The AWS SDK for Python **"boto3"** and Powerful data structures for
        data analysis, time series,and statistics **"pandas"** libraries;

        Simply;

        $ pip install boto3

        $ pip install pandas



    Returns:
        None:

    """

    # Create
    # 1.Given a CustomerId and a NodeType, it should be able to create an ec2 instance (see Node Properties)
    # and return a node_id
    # $ foo create --customer-id “a11f4af4b693” --node-type “Manager”
    # i-9b7891db92fdda53f
    # call(["python.exe", "foo.py", "create", "--customer-id", str(randint(0,10)), "--node-type", "Peer"])

    # List Nodes
    # 2.Given a CustomerId, it should be able to list all the NodeIds belonging to a specific CustomerId
    # $ foo list-nodes --customer-id “a11f4af4b693”
    # i-9b7891db92fdda53f
    # i-8aa344f8c2fa2983c
    # call(["python.exe", "foo.py", "list-nodes", "--customer-id", str(randint(0,10))])

    # List All
    # 3.It should be able to list all NodeIds, CustomerIds and their corresponding IPs (ex: to execute a specific
    # command on all nodes)
    # $ foo list-all
    # a11f4af4b693, i-9b7891db92fdda53f, 34.32.55.11
    # a11f4af4b693, i-8aa344f8c2fa2983c, 45.44.23.39
    # call(["python.exe", "foo.py", "list-all"])

    # Execute
    # 4.Given a selector (CustomerId and/or a NodeType) and an absolute file path, it should be able to execute a
    # script on all nodes saving each execution’s stdout and stderr to some medium
    # $ foo execute --customer-id “a11f4af4b693” --script /home/sysop/updatePackages.sh
    # $ foo execute --node-type “Manager” --script /home/sysop/genReport.sh
    call(["python.exe", "foo.py", "execute", "--customer-id", str(randint(0, 10)), "--node-type", "Peer", "--script", "/home/sysop/updatePackages.sh"])

    # Backup
    # Should be able to snapshot a specific Node’s ‘/data’ mount point
    # $ foo backup --node-id “i-9b7891db92fdda53f”
    # i-913749823749211
    # call(["python.exe", "foo.py", "backup", "--node-id", "i-04cddff49921b7e4f"])

    # List Backups
    # Should be able to list backups of a specific node along with the snapshot date
    # $ foo list-backups --node-id “i-9b7891db92fdda53f”
    # i-913749823749211, 2017-03-20 21:19
    # i-913749823749233, 2017-02-21 07:30
    # call(["python.exe", "foo.py", "list-backups", "--node-id", "i-04cddff49921b7e4f"])

    # Roll Back
    # Should be able to roll-back to a specific BackupId for a given node_id
    # $ foo rollback --backup-id “i-913749823749211”
    # call(["python.exe", "foo.py", "roll-back", "--node-id", "i-04cddff49921b7e4f", "--backup-id", "snap-094a7f8d36c5e3374"])

    # Terminate All
    # Bonus
    # call(["python.exe", "foo.py", "terminate-all"])


if __name__ == "__main__":
    run()
