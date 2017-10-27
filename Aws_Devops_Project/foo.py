import my_aws_api_library
import argparse
import os


def run():

    """Check the command line arguments and decide the library function will be called

    Returns:
        True on successful calls, otherwise False.

    """
    if args.action == "create":
        if args.customer_id and args.node_type:
            my_aws = createaws()
            node_id = my_aws.create_ec2_instance(args.customer_id, args.node_type)
            print("Node Created: ", node_id, "\n")
            return True
        else:
            print("Missed command parameters for Instance Creation")
            return False

    elif args.action == "list-nodes":
        if args.customer_id:
            my_aws = createaws()
            instance_lst = my_aws.get_instance_by_customer_id(args.customer_id)
            print("Customer", args.customer_id, "has " + str(len(instance_lst)) + " Instances: ", ",".join(instance_lst)
                  ,"\n")
            return True
        else:
            print("Missed command parameters for Instance Listing")
            return False

    elif args.action == "list-all":
        my_aws = createaws()
        cust_inst_ip = my_aws.get_all_instances()
        print("All the Instances: customer_id, instance_id, instance_ip formatted\n")
        if len(cust_inst_ip) > 0:
            for rec in cust_inst_ip:
                print(', '.join(rec))
        else:
            print("No Instances!")
            return False
        return True

    elif args.action == "execute":
        instance_ids, succ_id_list, not_worked_is_list, outs = [], [], [], []
        if args.script and (args.customer_id or args.node_type):
            my_aws = createaws()
            commands = args.script
            if args.customer_id:
                instance_ids.extend(my_aws.get_instance_by_customer_id(args.customer_id))
            if args.node_type:
                instance_ids.extend(my_aws.get_instance_by_node_type(args.node_type))
                instance_ids = list(set(instance_ids))

                succ_id_list, not_worked_is_list, outs = \
                    my_aws.execute_commands_on_linux_instances(commands, instance_ids)
            print("\nInstances that run the commands:\n", '\n '.join(succ_id_list))
            print("\nInstances that don't run the commands: (Instance is not running or its SSM agent doesn't work or "
                  "command couldn't be executed\n", '\n '.join(not_worked_is_list))
            print("\nOutputs of the Instances that run the commands:")
            for i in outs:
                print("\n")
                for k, v in dict(i).items():
                    print(str(k).lstrip(), "-->", str(v).replace('\n', ""))
            return True
        else:
            print("Missed command parameters for Execution on Instance")
            return False

    elif args.action == "backup":
        if args.node_id:
            my_aws = createaws()
            s_id = my_aws.make_backup(args.node_id)
            print(s_id)
        else:
            return False

    elif args.action == "list-backups":
        if args.node_id:
            my_aws = createaws()
            backup_list = my_aws.list_backups(args.node_id)
            if len(backup_list) > 0:
                for rec in backup_list:
                    print(', '.join(rec))
                return True
            else:
                print("Snapshot yok !")
                return True
        else:
            return False

    elif args.action == "roll-back":
        if args.backup_id:
            my_aws = createaws()
            my_aws.roll_back(args.backup_id, args.node_id)
    elif args.action == "terminate-all":
        my_aws = createaws()
        my_aws.terminate_instances('ALL')
    else:
        print("Please select a proper action")


def createaws() -> my_aws_api_library.MyAws:

    """Reads the credentials and instantiates a MyAws object.

    .. note::

        Required Environmental Variables:

        **AWS_CRED_FILE** --> Indicates the .csv file that consists AWS Access key ID, Secret access key to access AWS
        APIs.

        **COMPANY_PUBKEY** --> Indicates the .pub file that consists Public Key to access Aws Instances.

    Returns:
        object: :class:`~my_aws_api_library.MyAws` object


    """
    aws_cred_file_path = os.environ['AWS_CRED_FILE']
    comp_pubkey = os.environ['COMPANY_PUBKEY']
    my_aws = my_aws_api_library.MyAws(aws_cred_file_path, comp_pubkey)
    return my_aws


def read_args():

    """Read the command line arguments

    """
    global args
    parser = argparse.ArgumentParser(
        description='Executes create, list-nodes, list-all, execute, backup, list-backups and rollback tasks on AWS '
                    'system')

    # What the code will do? The actions...
    parser.add_argument('action', help='Type of work', choices=["create", "list-nodes", "list-all", "execute", "backup",
                                                                "list-backups", "roll-back", "terminate-all"])
    parser.add_argument('--customer-id', help='Shows customer ID', required=False)
    parser.add_argument('--node-type', help='Shows node type, values can be "Manager" or "Peer"',
                        choices=["Manager", "Peer"], required=False)
    parser.add_argument('--script', help='Shows the script that will be executed on Aws instance', required=False)
    parser.add_argument('--node-id', help='Shows node (Instance) ID on AWS', required=False)
    parser.add_argument('--backup-id', help='Shows snapshot ID on AWS', required=False)

    args = parser.parse_args()


if __name__ == "__main__":
    read_args()
    run()

# Globals
args = None