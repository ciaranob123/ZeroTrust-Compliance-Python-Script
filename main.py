import csv
from datetime import datetime
import paramiko
from pyVim import connect
from pyVmomi import vim
import ssl
import re
import pdfkit
import subprocess
import json


AZ_PATH = r"C:\Program Files\Microsoft SDKs\Azure\CLI2\wbin\az.cmd"
SUBSCRIPTION_ID = "Enter your Subscription ID here"
config = pdfkit.configuration(wkhtmltopdf=r"C:\Program Files\wkhtmltopdf\bin\wkhtmltopdf.exe")

def az_cli_login(subscription_id):
    subprocess.run([AZ_PATH, "login"], check=True)
    subprocess.run([AZ_PATH, "account", "set", "--subscription", subscription_id], check=True)

def generate_pdf_html(html_content, output_pdf_path):
    pdfkit.from_string(html_content, output_pdf_path, configuration=config)

def load_html_template(filepath):
    with open(filepath, "r", encoding="utf-8") as file:
        return file.read()


def build_detailed_findings(scan_results):
    findings_html = ""
    for result in scan_results:
        findings_html += f"""
        <h3>{result['resource']} - {result['status']}</h3>
        <p><b>Check:</b> {result['check']}</p>
        <p><b>Result:</b> {result['status']} - {result['comments']}</p>
        """

        if result.get('details'):
            findings_html += "<p><b>Details:</b></p><table border='1' cellpadding='3' cellspacing='0'>"
            for key, value in result['details'].items():
                findings_html += f"<tr><td>{key}</td><td>{value}</td></tr>"
            findings_html += "</table>"
        else:
            findings_html += "<p><em>No additional detailed information available.</em></p>"

        findings_html += "<hr>"
    return findings_html




def build_table_rows(scan_results):
    table_html = ""
    for result in scan_results:
        table_html += f"""
        <tr>
            <td>{result['resource']}</td>
            <td>{result['check']}</td>
            <td >{result['status']}</td>
            <td>{result['comments']}</td>
        </tr>
        """
    return table_html

def load_credentials(filename):
    credentials = []
    with open(filename, newline='', encoding='utf-8') as file:
        reader = csv.DictReader(file)
        for row in reader:
            credentials.append((row['host'], row['username'], row['password']))
    return credentials

def run_command(client, command):
    stdin, stdout, stderr = client.exec_command(command)
    return stdout.read().decode(), stderr.read().decode()

#=================== ESXi Check Functions ===================#
def check_ssh_restricted(client):
    output, _ = run_command(client, "cat /etc/ssh/sshd_config")
    lines = output.splitlines()
    detailed_info = {"Username": "SSH Status"}
    score = 0

    for line in lines:
        line = line.strip()
        if line.startswith("AllowUsers") and not line.startswith("#"):
            users = line.split()[1:]
            for user in users:
                detailed_info[user] = "Allowed"
            score = 8
            break

    if score == 0:
        detailed_info["AllowUsers"] = "Not set — SSH unrestricted"
    print(detailed_info)
    return score, detailed_info





def check_esxi_host_segmentation(host_obj):
    score = 0
    pg_vlan_map = {}
    #detailed_info = ["Port Group : VLAN"]
    detailed_info= {}
    detailed_info["Port Group"]= "VLAN ID"
    for pg in host_obj.config.network.portgroup:
        vlan = pg.spec.vlanId
        pg_name = pg.spec.name
        detailed_info[pg_name]=vlan
        #pg_vlan = f"{pg_name}:{vlan}"
        #detailed_info.append(pg_vlan)

        if vlan in pg_vlan_map:
            pg_vlan_map[vlan].append(pg_name)
        else:
            pg_vlan_map[vlan] = [pg_name]
    print(detailed_info)
    duplicates_found = any(len(groups) > 1 for groups in pg_vlan_map.values())

    if not duplicates_found:
        score += 15
    return score, detailed_info

def check_lockdown_mode(host_obj):
    detailed_results= {}
    lockdown_mode = getattr(host_obj.config, "lockdownMode", None)
    detailed_results["Lockdown Mode"] = lockdown_mode
    #print(detailed_results)
    print(lockdown_mode)
    if lockdown_mode == "lockdownNormal" or "lockdownStrict":
        return 6, detailed_results
    return 0 , detailed_results


def check_host_services(host_obj):
    score = 0
    detailed_results= {"Service":"Status"}
    try:
        service_system = host_obj.configManager.serviceSystem
        services = service_system.serviceInfo.service
        for service in services:
            detailed_results[service.key]=service.running
        print(detailed_results)
        statuses = {s.key: s.running for s in services}

        if not statuses.get("TSM-SSH", True) and not statuses.get("TSM-ESXiShell", True):
            score += 10
    except Exception:
        pass
    return score, detailed_results



def check_esxi_version_sdk(host_obj):

    latest_build = "24585291"
    build = host_obj.summary.config.product.build
    detailed_info = {"ESXi Host Build Number": build, "Latest ESXI Build":latest_build}

    print(detailed_info)
    if build == latest_build:
        return 5, detailed_info
    return 0, detailed_info


def get_vm_os_info(content):
    unsupported_os_versions = [
        "Windows 2000", "Windows XP", "Windows Vista", "Windows 7",
        "Windows Server 2003", "Windows Server 2008", "Ubuntu 10.04 LTS",
        "Ubuntu 12.04 LTS", "CentOS 5", "CentOS 6", "Red Hat Enterprise Linux 5", "Debian 7"
    ]
    score = 4
    detailed_info={"Operating System": "Supported Status"}
    container = content.viewManager.CreateContainerView(content.rootFolder, [vim.VirtualMachine], True)
    vms = container.view
    for vm in vms:
        guest_os = vm.summary.config.guestFullName

        if any(unsupported in guest_os for unsupported in unsupported_os_versions):
            detailed_info[guest_os] = "Unsupported"
            score =0
        else:
            detailed_info[guest_os]= "Supported"
    container.Destroy()
    print(detailed_info)
    return score, detailed_info

def check_all_vm_encryption(host_obj):
    vms = get_all_vms(host_obj)
    detailed_info ={"VM Name": "Encryption Status"}
    score = 12
    for vm in vms:
        encrypted, _ = check_vm_encryption(vm)
        detailed_info[vm.config.name]= encrypted
        if not encrypted:
            score =0
    print(detailed_info)
    return score, detailed_info

def check_vm_encryption(vm):
    try:
        #print(vm.config.name)

        enc_info = vm.config.vmEncryptionInfo

        return bool(enc_info), enc_info
    except Exception:
        return False, None

def get_all_vms(entity):
    if hasattr(entity, 'rootFolder'):
        container = entity.rootFolder
        viewType = [vim.VirtualMachine]
        recursive = True
        containerView = entity.viewManager.CreateContainerView(container, viewType, recursive)
        vms = containerView.view
        containerView.Destroy()
        return vms
    elif hasattr(entity, 'vm'):
        return entity.vm
    else:
        raise TypeError("Unsupported entity type passed to get_all_vms")

def list_esxi_permissions(client):
    output, _ = run_command(client, "esxcli system permission list")
    print(output)
    authorized = ["root", "administrator", "vpxuser", "dcui", "AliceJohnson"]
    score = 8
    detailed_info={"User": "Access Level"}
    lines = output.splitlines()[2:]
    for line in lines:
        if not line.strip():
            continue
        parts = re.split(r'\s{2,}', line.strip())
        if len(parts) < 4:
            continue
        principal, _, role, role_desc = parts
        detailed_info[principal] = role_desc
        if role_desc == "Full access rights" and principal not in authorized:
            score =0

    print(detailed_info)
    return score, detailed_info

def check_log_forwarding(client):
    output, _ = run_command(client, "esxcli system syslog config get")
    detailed_info = {}
    score=0
    ip=""
    for line in output.splitlines():
        if "Remote Host" in line:
            log_hosts_value = line.split(":", 1)[1].strip()

            ip = log_hosts_value.split()[0]  # Take the first part
            print(f"Found Log Server: {ip}")

            detailed_info={"Syslog Forwarding":"True", "Log Server IP": ip}
            score=8
            break
        else:
            score=0

    #print(detailed_info)
    return score, detailed_info

def check_firewall(client):
    output, _ = run_command(client, "esxcli network firewall get")
    detailed_info = {}

    if "Enabled: true" in output:
        detailed_info["Firewall Status"] = "Enabled"
        return 10, detailed_info
    else:
        detailed_info["Firewall Status"] = "Disabled"
        return 0, detailed_info

def check_esxi_password_expiration(client):
    output, _ = run_command(client, "cat /etc/shadow")
    score = 2
    detailed_info = {"Username": "Password Expires after x days"}
    lines = output.splitlines()
    for line in lines:
        parts = line.strip().split(":")
        if len(parts) < 5:
            continue

        username = parts[0]
        max_age = parts[4]

        if max_age == "99999":
            detailed_info[username] = "Password never expires"
            score = 0
        else:
            detailed_info[username] = max_age

    print(detailed_info)
    return score, detailed_info
def check_esxi_password_policies(client):
    output, _ = run_command(client, "grep -E 'pam_pwquality.so|pam_cracklib.so|pam_passwdqc.so' /etc/pam.d/passwd")
    score = 2
    detailed_info = {"Password Complexity Status":"Required Password Length"}

    for line in output.strip().splitlines():
        if "retry" in line:
            match = re.search(r"min=([\w,]+)", line)
            if match:
                min_values = match.group(1).split(",")
                password_len = min_values[3]
                print(password_len)
                if int(password_len) < 12:
                    score = 0
                    detailed_info["False"]=password_len
                else:
                    detailed_info["True"] = password_len
        else:
            print("coudlnt find password policy")
    print(detailed_info)

    return score,detailed_info


def check_root_ssh_login(client):
    output, _ = run_command(client, "grep '^PermitRootLogin' /etc/ssh/sshd_config")
    detailed_info = {}

    if "no" in output.lower():
        detailed_info["SSH Root Login"] = "Disabled"
        return 5, detailed_info
    else:
        detailed_info["SSH Root Login"] = "Enabled"
        return 0, detailed_info

def check_vm_snapshots(client):
    output, _ = run_command(client, "vim-cmd vmsvc/getallvms")
    detailed_info = {"VM Name":"Snapshot Name"}
    score =5
    lines = output.strip().splitlines()

    for line in lines[1:]:
        parts = line.split()
        if len(parts) < 2:
            continue
        vmid = parts[0]
        vmname = parts[1]

        snap_output, _ = run_command(client, f"vim-cmd vmsvc/snapshot.get {vmid}")
        if "No snapshots" in snap_output:
            detailed_info["VM Snapshots"].append(f"{vmname}: No snapshots")
            score -= 2
        else:
            detailed_info[vmname]="Snapshots Found"

    return score, detailed_info


#----------------------------AZURE FUNCTION------------------------------------------------------



def az_cli_login(subscription_id):
    subprocess.run([AZ_PATH, "login"], check=True)
    subprocess.run([AZ_PATH, "account", "set", "--subscription", subscription_id], check=True)



#-------------Identity Management Functions-----------------
def list_users_roles_and_permissions():
    print("\nUsers and Permissions")
    users_result = subprocess.run([AZ_PATH, "ad", "user", "list", "--output", "json"],
                                  capture_output=True, text=True, check=True)
    users = json.loads(users_result.stdout)

    # Build mapping of user ID to user details.
    user_dict = {}
    for user in users:
        user_id = user.get("id")
        user_dict[user_id] = user.get("displayName")


    print(user_dict)

# check is owner role is assigned to any user
def check_user_roles():

    print("\nChecking User Role Assignments...")
    result = subprocess.run(
        [AZ_PATH, "role", "assignment", "list", "--output", "json"],
        capture_output=True, text=True, check=True
    )
    assignments = json.loads(result.stdout)

    for assignment in assignments:
        principal_name = assignment.get("principalName", "Unknown")
        role = assignment.get("roleDefinitionName")
        scope = assignment.get("scope")
        if role.lower() == "owner":
            print(f"Over-privileged role: {principal_name} has Owner on {scope}")
        else:
            print(f"{principal_name} has {role} on {scope}")

def check_subscription_owners():
    score=10
    detailed_info={"Username", "Role"}
    print("\nChecks if there are owners count assigned to subscription")

    detailed_info = {"Username":"Admin Role"}


    result = subprocess.run(
        [AZ_PATH, "role", "assignment", "list", "--all","--output", "json","--query", f"[?roleDefinitionName=='Owner' && scope=='/subscriptions/{SUBSCRIPTION_ID}'].[principalName, principalType, roleDefinitionName]"],
        capture_output=True, text=True, check=True
    )
    owners = json.loads(result.stdout)
    for owner in owners:
        name= owner[0]
        role= owner[2]
        detailed_info[name] = role
    if len(owners) > 3:
        score=0
        print("Owner Count exceeds as per Microsoft's Reccomendation")

    #print(detailed_info)
    return score, detailed_info



def check_users_group_membership(limit=5):
    print("\nChecking if users are members of too many groups")
    detailed_info = {"Username": "Group Memberships"}
    score = 10

    result = subprocess.run(
        [AZ_PATH, "ad", "user", "list", "--query", "[].{Name:displayName, UPN:userPrincipalName}", "--output", "json"],
        capture_output=True, text=True, check=True
    )
    users = json.loads(result.stdout)

    for user in users:
        name = user.get("Name")
        upn = user.get("UPN")

        group_result = subprocess.run(
            [AZ_PATH, "ad", "user", "get-member-groups", "--id", upn, "--output", "json"],
            capture_output=True, text=True
        )
        groups = json.loads(group_result.stdout)

        group_names = [group.get("displayName") for group in groups]

        group_count = len(group_names)
        if group_count > 0:
            detailed_info[name] = group_names if group_names else ""

        if group_count > limit:
            print(f"{name} is in {group_count} groups — exceeds threshold of {limit}")
            score = 0
        else:
            if group_count==0:
                continue
            else:
                print(f"{name} is a member of {group_count} groups — OK")

    print(detailed_info)
    return score, detailed_info


#---------Checks Backups-------
def check_vm_backup_azure():
    score = 10
    detailed_info = {"VM Name / Resource Group ": "Backup Vault Name"}

    result = subprocess.run(
        [AZ_PATH, "vm", "list", "--output", "json"],
        capture_output=True, text=True, check=True
    )
    vms = json.loads(result.stdout)

    for vm in vms:
        vm_name = vm.get("name")
        vm_id = vm.get("id")
        rg = vm.get("resourceGroup")

        vault = subprocess.run(
            [AZ_PATH, "backup", "protection", "check-vm", "--vm", vm_id],
            capture_output=True, text=True)
        output = vault.stdout.strip()
        vault_name = output.split("/")[-1]
        print(vault_name)
        if vault_name:
            detailed_info[f"{vm_name} / {rg}"] = vault_name
        else:
            detailed_info[f"{vm_name} / {rg}"] = "No Backups Configured"
        if output:
            print(f"Backups are enabled for {vm_name} (Resource Group: {rg})")
        else:
            print(f"Backups NOT enabled for {vm_name} (Resource Group: {rg})")
            score = 0
    print(detailed_info)
    return score, detailed_info

#-------------Encryption Functions-----------------




def check_vms_encryption():
    score=10
    detailed_info={}
    result = subprocess.run([AZ_PATH, "vm", "list", "--output", "json"],
        capture_output=True, text=True, check=True  #capturs output as string
    )
    vms = json.loads(result.stdout)

    for vm in vms:
        vm_name = vm.get("name")
        resource_group = vm.get("resourceGroup")
        security_profile = vm.get("securityProfile")
        encrypted =security_profile.get("encryptionAtHost", False)

        if encrypted:
            status = "Encrypted"
        else:
            status = "Not Encrypted"
            score =0


        detailed_info[f"{resource_group}/{vm_name}"] = status

        print(f"VM: {vm_name} (Resource Group: {resource_group}) is {status}")

    print(detailed_info)
    return score, detailed_info


def check_vnet_encryption(vnets):
    detailed_info={"VNET Resource":"Encryption Status"}
    score = 10
    print("\nChecking VNet Encryption...")

    for vnet in vnets:
        vnet_name = vnet.get("name")
        vnet_encryption = vnet.get("encryption", {})
        vnet_encrypted = vnet_encryption.get("enabled", False)
        if vnet_encrypted:
            status="Enabled"
        else:
            status="disabled"
            score =0
        detailed_info[vnet_name]= status

        print(f" {vnet_name} - Encryption: {status}")

        # check encryption for all peerings
        peerings = vnet.get("virtualNetworkPeerings", [])
        for peering in peerings:
            peering_name = peering.get("name")
            encryption = peering.get("remoteVirtualNetworkEncryption", {})

            peering_encrypted = encryption.get("enabled", False)
            if peering_encrypted:
                status = "Enabled"
            else:
                status = "disabled"
                score = 0
            detailed_info[peering_name]=status
            print(f"Peering: {peering_name} - Encryption: {status}")
    #print(detailed_info)
    return score, detailed_info

def check_key_vault_encryption():
    print("\nChecking Key Vault access and encryption...")
    score = 10
    detailed_info = {}
    result = subprocess.run([AZ_PATH, "keyvault", "list", "--output", "json"],
        capture_output=True, text=True, check=True
    )
    vaults = json.loads(result.stdout)

    for vault in vaults:

        name = vault.get("name")
        resource_group = vault.get("resourceGroup")

        # Get full vault details using `az keyvault show`
        detail_result = subprocess.run(
            [AZ_PATH, "keyvault", "show", "--name", name, "--resource-group", resource_group, "--output", "json"],
            capture_output=True, text=True, check=True
        )
        full_vault = json.loads(detail_result.stdout)
        props = full_vault.get("properties", {})

        enable_rbac = props.get("enableRbacAuthorization", False)
        soft_delete = props.get("enableSoftDelete", False)
        purge_protection = props.get("enablePurgeProtection", False)


        if vault:

            detailed_info["Vault name"]= name
            detailed_info["RBAC Status"] = enable_rbac
            detailed_info["Soft Delete name"] = soft_delete
            detailed_info["Purge Proetction"] = purge_protection
            score = 10
        else:
            score=0

        print(f"\nKey Vault: {name}")
        print(f" RBAC Enabled: {enable_rbac}")
        print(f" Soft Delete: {soft_delete}")
        print(f" Purge Protection: {purge_protection}")

    #print(detailed_info)
    return score, detailed_info
#-------------Segmentation Functions-----------------
def get_vnets():
    result = subprocess.run([AZ_PATH, "network", "vnet", "list", "--output", "json"],
        capture_output=True,
        text=True,
        check=True
    )
    return json.loads(result.stdout)

def check_vm_nsg_port_restrictions():
    print("\nChecking if VMs have unrestricted inbound ports via NSG\n")
    score = 10
    detailed_info = {"VM Name / NSG": "Open Port / Source"}

    nic_result = subprocess.run(
        [AZ_PATH, "network", "nic", "list", "--output", "json"],
        capture_output=True, text=True, check=True
    )

    nics = json.loads(nic_result.stdout)

    for nic in nics:
        vm_name = nic.get("virtualMachine", {}).get("id", "Unattached").split("/")[-1]
        nsg = nic.get("networkSecurityGroup", {})
        nsg_id = nsg.get("id")

        if not nsg_id:
            continue
        else:
            print("NIC has no NSG's")

        nsg_name = nsg_id.split("/")[-1]
        rg = nic.get("resourceGroup")


        nsg_result = subprocess.run(
            [AZ_PATH, "network", "nsg", "rule", "list", "--nsg-name", nsg_name, "--resource-group", rg, "--output", "json"],
            capture_output=True, text=True, check=True
        )
        rules = json.loads(nsg_result.stdout)

        for rule in rules:
            access = rule.get("access")
            direction = rule.get("direction")
            source = rule.get("sourceAddressPrefix")
            ports = rule.get("destinationPortRange")
            if direction == "Inbound" and access == "Allow" and (source == "*" or source == "0.0.0.0/0"):
                print(f"VM: {vm_name} (NSG: {nsg_name}) allows inbound from {source} on port {ports}")
                detailed_info[f"{vm_name} / {nsg_name}"] = f" allows inbound from {source} / on port {ports}"
                score = 0
            else:
                detailed_info[f"{vm_name} / {nsg_name}"] = "Restricted"

    print(detailed_info)
    return score, detailed_info





def check_vnet_segmentation(vnets):
    print("\nChecking if vNets are segmented")
    ip_range= []
    score=10

    detailed_info={"Name":"Address"}
    if len(vnets) < 2:
        score= 0

    for vnet in vnets:

        vnet_name = vnet.get("name")
        address_space = vnet.get("addressSpace", {}).get("addressPrefixes")
        address_space_str = ", ".join(address_space)
        ip_range.append(address_space_str)
        detailed_info[vnet_name]= address_space
        print(f"{vnet_name} : {address_space}")

        #add code to check if vnets are segmented.

        subnets = vnet.get("subnets", [])
        if subnets:
            print("Subnets:")
            for subnet in subnets:
                subnet_name = subnet.get("name")

                subnet_addresses = subnet.get("addressPrefixes", [])
                detailed_info[subnet_name]= subnet_addresses
             # If there's at least one address range, display the first one; otherwise, indicate not found.
                if subnet_addresses:
                    print(f"    {subnet_name}: {subnet_addresses[0]}")
                else:
                    print(f"    {subnet_name}: No address range found")
        else:
            print("  No subnets found.")
    return score, detailed_info



#-------------Other Functions-----------------

def check_nsg_rules():
    print("\nChecking NSGs for overly permissive rules...")
    score=0
    detailed_info={"NSG Name": "Rule/Destination"}
    result = subprocess.run(
        [AZ_PATH, "network", "nsg", "list", "--output", "json"],
        capture_output=True, text=True, check=True
    )
    nsgs = json.loads(result.stdout)

    for nsg in nsgs:
        nsg_name = nsg.get("name")
        for rule in nsg.get("securityRules", []):
            dest = rule.get("destinationAddressPrefix")
            detailed_info[nsg_name]= f"{rule} "
            if dest == "0.0.0.0/0" and rule.get("access") == "Allow":
                print(f"Warning - NSG '{nsg_name}' has insecure rule: {rule.get('name')} allows all traffic!")
                score=0
            else:
                print(f"NSG '{nsg_name}' rule '{rule.get('name')}' is scoped properly.")
                score=10
    print(detailed_info)
    return score, detailed_info



def check_azure_bastion():
    print("\nChecking for Azure Bastion deployments...")
    score =0
    detailed_info= {"Bastion Name":"Location"}
    result = subprocess.run(
        [AZ_PATH, "network", "bastion", "list", "--output", "json"],
        capture_output=True, text=True, check=True
    )
    bastions = json.loads(result.stdout)

    if bastions:
        for bastion in bastions:
            detailed_info[bastion.get('name')]= bastion.get('location')
            print(f"Bastion host found: {bastion.get('name')} in {bastion.get('location')}")
            score = 10
    else:
        print("Warning - No Azure Bastion hosts found. Secure access may be missing.")
        score=0
    print(detailed_info)
    return score, detailed_info


def check_azure_backup_snapshots():
    score = 10
    detailed_info={"VM Name/Resource Group":"Snapshot Ststus / Name"}
    print("\nChecking if vms are backed up ...")
    result = subprocess.run(
        [AZ_PATH, "vm", "list", "--output", "json"],
        capture_output=True, text=True, check=True
    )
    vms = json.loads(result.stdout)
    result = subprocess.run(
        [AZ_PATH,  "snapshot", "list", "--output", "json"],
        capture_output=True, text=True, check=True
    )
    snapshots = json.loads(result.stdout)


    for vm in vms:
        name = vm.get('name')
        rg = vm.get('resourceGroup')

        storage_profile = vm.get('storageProfile', {})
        os_disk = storage_profile.get('osDisk', {})
        managed_disk = os_disk.get('managedDisk', {})
        os_disk_id = managed_disk.get('id')

        snapshot_exists=False
        snapshot_name="None"

        for snap in snapshots:
            snapshot_name = snap.get('name',False)
            if snap.get('creationData', {}).get('sourceResourceId')== os_disk_id:
                snapshot_exists=True
                break
        detailed_info[f"{name} : {rg}"] = f"{snapshot_exists} :{snapshot_name}"
        if snapshot_exists:
            print(f"Backup exists for {name} : {rg}")
        else:
            print(f"Backup found for {name} : {rg}")
            score=0

    return score, detailed_info

def check_azure_Firewall ():
    print("\nChecking for Azure Firewall deployments...")
    detailed_info = {"Name": "Location"}
    score=0
    result = subprocess.run(
        [AZ_PATH, "network", "firewall", "list", "--output", "json"],
        capture_output=True, text=True, check=True
    )
    firewalls = json.loads(result.stdout)

    if firewalls:
        for firewall in firewalls:
            detailed_info[firewall.get('name')]= firewall.get('location')
            print(f"Firewall host found: {firewall.get('name')} in {firewall.get('location')}")
            score = 10
    else:
        print("Warning - No Azure Firewall hosts found. Deploy immediately.")
        score = 0

    return score, detailed_info

def check_public_ips_on_vms():
    score = 10
    detailed_info={"Resource Name:":"IP address / Resource Group"}
    print("\nChecking for public IP addresses on virtual machines...")

    # Get list of all public IP addresses
    result = subprocess.run(
        [AZ_PATH, "network", "public-ip", "list", "--output", "json"],
        capture_output=True, text=True, check=True
    )
    public_ips = json.loads(result.stdout)

    if not public_ips:
        print("No public IP addresses found in the subscription.")
        return score


    found = False
    for ip in public_ips:
        ip_address = ip.get("ipAddress", "Unknown")
        ip_name = ip.get("name")
        resource_group = ip.get("resourceGroup")
        assigned = ip.get("ipConfiguration", None) is not None
        detailed_info[ip_name] = f"{ip_address} : {resource_group}"
        if assigned:
            found = True
            print(f"Warning - Public IP in use: {ip_name} ({ip_address}) in {resource_group}")
            score =0
        else:
            print(f" Unassigned public IP: {ip_name} ({ip_address}) in {resource_group}")

    if not found:
        print("No public IPs are currently assigned to VMs or NICs.")
    print(detailed_info)
    return score, detailed_info


#------------------------------MAIN FUNCTION0-------------------------------


def main():
    scan_results = []
    azure_scan_results=[]
    filename = "hostdetails.csv"
    pdf_filename = "Hybrid-Cloud-ZTA-Report.pdf"
    total_possible_score_esxi = 100
    actual_score = 0
    azure_actual_score=0
    total_possible_score_azure = 100


    try:
        credentials = load_credentials(filename)
        for host, username, password in credentials:
            context = ssl._create_unverified_context()
            service_instance = connect.SmartConnect(host=host, user=username, pwd=password, sslContext=context)
            content = service_instance.RetrieveContent()
            host_obj = content.rootFolder.childEntity[0].hostFolder.childEntity[0].host[0]

            # SDK functions
            score_segmentation, details_segmentation = check_esxi_host_segmentation(host_obj)
            score_lockdown, details_lockdown = check_lockdown_mode(host_obj)
            score_services, details_services = check_host_services(host_obj)
            score_vm_encryption, details_encryption = check_all_vm_encryption(host_obj)
            score_version, details_build= check_esxi_version_sdk(host_obj)
            score_vm_os, details_os = get_vm_os_info(content)

            checks = [
                ("Network Segmentation", "Check ESXi VLAN segmentation", score_segmentation, details_segmentation),
                ("Services Status", "SSH & Shell services status", score_services, details_services),
                ("Lockdown Mode", "Host lockdown status", score_lockdown, details_lockdown),
                ("VM Encryption", "VMs encryption check", score_vm_encryption, details_encryption),
                ("ESXi Version", "Check ESXi version against latest", score_version, details_build),
                ("VM OS Info", "Unsupported OS versions detection", score_vm_os, details_os)
            ]

            for resource, check, score, details in checks:
                actual_score += score
                scan_results.append({
                    "resource": resource,
                    "check": check,
                    "status": "Pass" if score > 0 else "Fail",
                    "comments": "OK" if score > 0 else "Needs Review",
                    "details": details
                })

            # SSH functions
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            try:
                client.connect(host, username=username, password=password)


                ssh_checks = [
                    ("ESXi Permissions", "Unauthorized full rights check", list_esxi_permissions(client)),
                    ("Firewall Status", "Firewall enabled check", check_firewall(client)),
                    ("Log Forwarding", "Verify Syslog forwarding", check_log_forwarding(client)),
                    ("Check SSH Access Restrictions", "Checks if specified users are added to ssh config file to ensure least privilege access", check_ssh_restricted(client)),
                    ("VM Snapshot Availability", "Checks if VM's have snapshots", check_vm_snapshots(client)),
                    ("SSH Root Login", "PermitRootLogin check", check_root_ssh_login(client)),
                    ("ESXI Host Password Complexity Policy", "Checks if password complexity polices are set on host. ", check_esxi_password_policies(client)),
                    ("ESXI Host Password Expiration Policy", "Checks password expiration policy. ", check_esxi_password_expiration(client))

                ]

                for resource, check, (score, details) in ssh_checks:
                    actual_score += score
                    scan_results.append({
                        "resource": resource,
                        "check": check,
                        "status": "Pass" if score > 0 else "Fail",
                        "comments": "OK" if score > 0 else "Needs Review",
                        "details": details
                    })

            except Exception as e:
                print(f"SSH Connection Failed: {e}")
            finally:
                client.close()

    except FileNotFoundError:
        print("Error: CSV file not found.")






    az_cli_login(SUBSCRIPTION_ID)
    vnets = get_vnets()
    score_owners, owners_details = check_subscription_owners()
    score_backups, backups_details = check_vm_backup_azure()
    score_vnet_seg, vnet_details = check_vnet_segmentation(vnets)
    score_nsg, nsg_details = check_nsg_rules()
    score_public_ips, public_ip_details = check_public_ips_on_vms()
    score_bastion, bastion_details = check_azure_bastion()
    score_vnets, vnets_details = check_vnet_encryption(vnets)
    score_vm_encryption,vm_encryption_details  = check_vms_encryption()
    score_inbound_nsg_vm, vm_nsg_details = check_vm_nsg_port_restrictions()
    score_kv, kv_details = check_key_vault_encryption()
    score_fw, fw_details = check_azure_Firewall()
    score_group_membership, membership_details = check_users_group_membership()
    score_snap, snap_details= check_azure_backup_snapshots()
    #check_user_roles()
    #list_users_roles_and_permissions()

    azure_checks = [
        ("Network Segmentation", "Check if VNets are segmented", score_vnet_seg, vnet_details),
        ("NSG Rules", "Check for overly permissive NSG rules", score_nsg, nsg_details),
        ("Public IP Exposure", "Check for public IPs assigned to resources", score_public_ips, public_ip_details),
        ("Azure Bastion", "Check if Azure Bastion is deployed for secure access", score_bastion, bastion_details),
        ("VNet Encryption", "Check if VNets and peerings have encryption enabled", score_vnets, vnets_details),
        ("VM Inbound NSG Rules", "Chekcs if VM's have service ports open for all inbound IP addresses", score_inbound_nsg_vm, vm_nsg_details),
        ("VM Encryption", "Check if VMs have encryption at host enabled", score_vm_encryption, vm_encryption_details),
        ("Key Vault Security", "Check Key Vault RBAC, Soft Delete, and Purge Protection", score_kv, kv_details),
        ("Azure Firewall", "Check if Azure Firewall is deployed for perimeter security", score_fw, fw_details),
        ("Azure Snapshots", "Checks if snapshots are taken of VM's", score_snap, snap_details),
        ("Azure Backups", "Checks if Azure backups are configured for VM's", score_backups, backups_details),
        ("Subsctiption Owners", "Checks the number of owners on the subscription, Microsoft reccomends less than 3", score_owners, owners_details),
        ("Group Membership", "Check if users belong to too many groups", score_group_membership, membership_details)
    ]

    for resource, check, score, details in azure_checks:
        azure_actual_score += score
        azure_scan_results.append({
            "resource": resource,
            "check": check,
            "status": "Pass" if score > 0 else "Fail",
            "comments": "OK" if score > 0 else "Needs Review",
            "details": details
        })

    compliance_percent = round((actual_score / total_possible_score_esxi) * 100, 2)
    compliance_percent_azure = round((azure_actual_score / total_possible_score_azure) * 100, 2)


   # total_actual_score = actual_score + azure_actual_score
    #total_possible_score = total_possible_score_esxi + total_possible_score_azure
   # total_compliance_percent = round((total_actual_score / total_possible_score) * 100, 2)


    #print(compliance_percent)
    scan_date = datetime.now().strftime("%Y-%m-%d")
    year = datetime.now().year

    table_rows = build_table_rows(scan_results)
    table_rows_azure = build_table_rows(azure_scan_results)
    detailed_findings = build_detailed_findings(scan_results)
    detailed_findings_azure = build_detailed_findings(azure_scan_results)

    html_template = load_html_template("report_template.html")
    html_filled = html_template.replace("{{ scan_date }}", scan_date) \
                                .replace("{{ year }}", str(year)) \
                                .replace("{{ hostIP }}", str(host)) \
                                .replace("{{ table_rows }}", table_rows) \
                                .replace("{{ detailed_findings }}", detailed_findings) \
                                .replace("{{ subscription }}", SUBSCRIPTION_ID) \
                                .replace("{{ table_rows_azure }}", table_rows_azure) \
                                .replace("{{ detailed_findings_azure }}", detailed_findings_azure) \
                                .replace("{{ compliance_percent_azure }}", str(compliance_percent_azure)) \
                                .replace("{{ compliance_percent }}", str(compliance_percent))

    generate_pdf_html(html_filled, pdf_filename)
    print(f"\nreport generated: {pdf_filename}")

if __name__ == '__main__':
    main()
