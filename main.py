import csv
from datetime import datetime
from multiprocessing.reduction import duplicate

import paramiko
from pyVim import connect
from pyVmomi import vim
import ssl
import re
import pdfkit
import subprocess
import json
import smtplib
from email.message import EmailMessage

AZ_PATH = r"C:\Program Files\Microsoft SDKs\Azure\CLI2\wbin\az.cmd"
SUBSCRIPTION_ID = "ENTER SUBSCRIPTION ID HERE"
config = pdfkit.configuration(wkhtmltopdf=r"C:\Program Files\wkhtmltopdf\bin\wkhtmltopdf.exe")




#--------------SCRIPT OPERATION FUNCTIONS------------------
#https://apitemplate.io/blog/how-to-generate-pdfs-from-html-with-python-pdfkit/
def generate_pdf_html(html_content, output_pdf_path):
    pdfkit.from_string(html_content, output_pdf_path, configuration=config)

def load_html_template(filepath):
    with open(filepath, "r", encoding="utf-8") as file:
        return file.read()

'''
Builds table that stores the details findings for each check. Loops through the scan results and extracts the list elements. 
The detailed results are score in the list as a dictionary. 
Function returns the HTML table code
'''
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



'''
Builds the table for the summary section of the report
Scan results are passed in as a list and it creates a HTML table and returns it. 
'''
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

'''
Reads a CVS files that contains ESXI host details. Loops through each line and adds it to a list. 
'''
def load_credentials(filename):
    credentials = []
    with open(filename, newline='', encoding='utf-8') as file:
        reader = csv.DictReader(file)
        for row in reader:
            credentials.append((row['host'], row['username'], row['password']))
    return credentials


'''
Used for running SSH commands
'''
def run_command(client, command):
    stdin, stdout, stderr = client.exec_command(command)
    return stdout.read().decode(), stderr.read().decode()




'''
Creates an email with the give inputs and attaches the specified file. Uses EmailMessage libarary to then send the email
https://medium.com/@abdullahzulfiqar653/sending-emails-with-attachments-using-python-32b908909d73
'''
def send_email_with_report(sender_email, app_password, recipient_email, subject, body, attachment_path):

    msg = EmailMessage()
    msg["From"] = sender_email
    msg["To"] = recipient_email
    msg["Subject"] = subject
    msg.set_content(body)

    with open(attachment_path, "rb") as f:
        pdf_data = f.read()
        msg.add_attachment(pdf_data, maintype="application", subtype="pdf", filename="Hybrid-Cloud-ZTA-Report.pdf")
    with smtplib.SMTP_SSL("smtp.gmail.com", 465) as smtp:
        smtp.login(sender_email, app_password)
        smtp.send_message(msg)

    print("email sent .")

#------------------------ ESXi Check Functions ----------------------#

'''
Checks if SSH access is restricted on the ESXi host. 
Queries the sshd_config file to check if "AllowedUsers" is present. Indicating that access is restricted
'''

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
            score = 6
            break

    if score == 0:
        detailed_info["AllowUsers"] = "Not set — SSH unrestricted"

    print(detailed_info)
    return score, detailed_info

'''
Queries the sshd_config file on the ESXi host to check if TCP forwarding is disabled, as per recommendations
'''
def check_ssh_tcp_forwarding(client):
    detailed_info = {}
    score = 6

    stdin, stdout, stderr = client.exec_command("cat /etc/ssh/sshd_config |grep '^AllowTcpForwarding'")
    output = stdout.read().decode().strip()

    if output:
        value = output.split()[1].lower()
        detailed_info["AllowTcpForwarding"] = value
        if value == "no":
            detailed_info["Status"] = "Enabled (Non-compliant)"
        else:
            detailed_info["Status"] = "Disabled (Compliant)"
            score = 0
    else:
        score = 0
        detailed_info["AllowTcpForwarding"] = "Not Set"

    print(detailed_info)
    return score, detailed_info


'''
Checks if a SSH Banner is enabled, used to deter attacker. 

'''
def check_ssh_banner(client):
    detailed_info = {}
    score = 4

    stdin, stdout, stderr = client.exec_command("cat /etc/issue")
    output = stdout.read().decode().strip()

    if output:
        detailed_info["Enabled"] = "Yes"
        detailed_info["Banner Content"] = output
    else:
        score = 0
        detailed_info["Enabled"] = "No"
        detailed_info["Banner Content"] = "No content found in /etc/issue"
    print(detailed_info)
    return score, detailed_info



'''
Queries the /etc/passwd file and checks of the DCUI account has shell access disabled as reccommended 
'''

def check_dcui_shell_access(client):
    detailed_info = {}
    score = 5
    stdin, stdout, stderr = client.exec_command("grep '^dcui' /etc/passwd")
    output = stdout.read().decode().strip()


    fields = output.split(":")
    login_shell = fields[-1]
    detailed_info["dcui_shell"] = login_shell

    if login_shell in ["/bin/false", "/sbin/nologin"]:

        detailed_info["dcui_shell_access"] = "Disabled"
    else:
        score = 0
        detailed_info["dcui_shell_access"] = "Enabled"

    return score, detailed_info



'''
Extracts the portgroup information via the SDK and determines if port groups have the same VLAN ID. 
Same VLAN ID's suggested that workloads are not segmenetd .
'''
def check_esxi_host_segmentation(host_obj):
    score = 7
    pg_vlan_map = {}
    detailed_info= {}
    detailed_info["Port Group"]= "VLAN ID"
    for pg in host_obj.config.network.portgroup:
        vlan = pg.spec.vlanId
        pg_name = pg.spec.name
        detailed_info[pg_name]=vlan

        if vlan in pg_vlan_map:
            pg_vlan_map[vlan].append(pg_name)
        else:
            pg_vlan_map[vlan] = [pg_name]
    print(detailed_info)

    duplicates_found=False
    for groups in pg_vlan_map.values():
        if len(groups) > 1:
            duplicates_found=True

    #duplicates_found = any(len(groups) > 1 for groups in pg_vlan_map.values())

    if duplicates_found:
        score =0
    return score, detailed_info


'''
Checks if lockdown mode is set to either normal or strict mode using the host object returned by the SDK. 

'''

def check_lockdown_mode(host_obj):
    detailed_results = {}
    score = 6

    lockdown_mode = getattr(host_obj.config, "lockdownMode", None)
    detailed_results["Lockdown Mode"] = lockdown_mode
    print(lockdown_mode)

    if lockdown_mode not in ("lockdownNormal", "lockdownStrict"):
        score = 0

    return score, detailed_results


'''
Using the SDK, it queries the list of running services on the host. The test fails if the SSH and Shell access are enabled
Returns a list of all running services on the scannned ESXI hsot. 
'''
def check_host_services(host_obj):
    score = 7
    detailed_results= {"Service":"Status"}
    try:
        service_system = host_obj.configManager.serviceSystem
        services = service_system.serviceInfo.service
        for service in services:
            detailed_results[service.key]=service.running
        print(detailed_results)
        statuses = {s.key: s.running for s in services}

        if statuses.get("TSM-SSH", True) and statuses.get("TSM-ESXiShell", True):
            score = 0
    except Exception:
        pass
    return score, detailed_results

'''
Checks that ESXI host is running the latest build, ensuring there is no vulnerabilities 
'''

def check_esxi_version_sdk(host_obj):
    score=8
    latest_build = "24585291"
    build = host_obj.summary.config.product.build
    detailed_info = {"ESXi Host Build Number": build, "Latest ESXI Build":latest_build}

    print(detailed_info)
    if build != latest_build:
        score =0
    return score , detailed_info


'''
Pulls the operating systems versions from the ESXI host and compares it to a list of 
unsupported operating systems
'''
def get_vm_os_info(content):
    unsupported_os_versions = [
        "Windows 2000", "Windows XP", "Windows Vista", "Windows 7",
        "Windows Server 2003", "Windows Server 2008", "Ubuntu 10.04 LTS",
        "Ubuntu 12.04 LTS", "CentOS 5", "CentOS 6", "Red Hat Enterprise Linux 5", "Debian 7"
    ]
    score = 6
    detailed_info={"Operating System": "Supported Status"}
    container = content.viewManager.CreateContainerView(content.rootFolder, [vim.VirtualMachine], True)
    vms = container.view
    for vm in vms:
        guest_os = vm.summary.config.guestFullName

        if guest_os in unsupported_os_versions:
            detailed_info[guest_os] = "Unsupported"
            score = 0
        else:
            detailed_info[guest_os] = "Supported"
    container.Destroy()
    print(detailed_info)
    return score, detailed_info


'''
Extracts the each VM's encryption status by accessing the vmEncryptionInfo field in VM config.
Check fails if any VM is not encrypted 
'''
def check_all_vm_encryption(host_obj):
    vms = get_all_vms(host_obj)
    detailed_info = {}
    score = 8

    for vm in vms:
        try:
            enc_info = vm.config.vmEncryptionInfo
            encrypted = bool(enc_info)
        except Exception:
            encrypted = False


        if encrypted:
            detailed_info[vm.config.name] = "Encrypted"
        else:
            detailed_info[vm.config.name] = "Not Encrypted"



        if not encrypted:
            score = 0  # if any VM is not encrypted, set score to 0

    print(detailed_info)
    return score, detailed_info



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


# SSH Based ESXi Functions

'''
Used esxclid to query the permissions list for users. 
The test fails if the user user has full access to the host and not part of allowed list.
'''

def list_esxi_permissions(client):
    output, _ = run_command(client, "esxcli system permission list")
    print(output)
    authorized = ["root", "administrator", "vpxuser", "dcui", "AliceJohnson"]
    score = 7
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


'''
Uses esxcli to retrieve the syslog cofig. Test fails if a remote log server is not configured
'''
def check_log_forwarding(client):
    output, _ = run_command(client, "esxcli system syslog config get")
    detailed_info = {}
    score = 0
    ip = ""

    for line in output.splitlines():
        if "Remote Host" in line:
            log_hosts_value = line.split(":", 1)[1].strip()
            if log_hosts_value:
                ip = log_hosts_value.split()[0]
                print(f"Found Log Server: {ip}")
                detailed_info = {"Syslog Forwarding": "True", "Log Server IP": ip}
                score = 3
            else:
                detailed_info = {"Syslog Forwarding": "False", "Log Server IP": "None"}
            break

    if not detailed_info:
        detailed_info = {"Syslog Forwarding": "False", "Log Server IP": "None"}

    return score, detailed_info

'''
Checks if the local ESXi firewall is enabled
'''

def check_firewall(client):
    output, _ = run_command(client, "esxcli network firewall get")
    detailed_info = {}
    score=4

    if "Enabled: true" in output:
        detailed_info["Firewall Status"] = "Enabled"

    else:
        detailed_info["Firewall Status"] = "Disabled"
        score=0
    return score,detailed_info

'''
Verifies the acount password expiration periods from the shadow file on ESXi host, test fails if there is no expiration set
'''

def check_esxi_password_expiration(client):
    output, _ = run_command(client, "cat /etc/shadow")
    score = 6
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


'''
Check's password complexity congiguration from the pam.d/passwd file. If minimium password less than 12, test fails. 
'''
def check_esxi_password_policies(client):
    output, _ = run_command(client, "grep -E 'pam_pwquality.so|pam_cracklib.so|pam_passwdqc.so' /etc/pam.d/passwd")
    score = 5
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

# Checks the sshd config file and looks to see if SSH login restrcitions are added for root user. 
def check_root_ssh_login(client):
    output, _ = run_command(client, "grep '^PermitRootLogin' /etc/ssh/sshd_config")
    detailed_info = {}
    score = 6

    if "no" in output.lower():
        detailed_info["SSH Root Login"] = "Disabled"

    else:
        detailed_info["SSH Root Login"] = "Enabled"
        score =0
    return score, detailed_info



# verifies if there
def check_vm_snapshots(client):
    output, _ = run_command(client, "vim-cmd vmsvc/getallvms")
    detailed_info = {"VM Name":"Snapshot Name"}
    score =6
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
            score =0
        else:
            detailed_info[vmname]="Snapshots Found"

    return score, detailed_info


#----------------------------AZURE FUNCTION------------------------------------------------------


def az_cli_login(subscription_id):
    subprocess.run([AZ_PATH, "login"], check=True)
    subprocess.run([AZ_PATH, "account", "set", "--subscription", subscription_id], check=True)



#-------------Identity Management Functions-----------------

'''
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
'''
'''
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
'''


def check_subscription_owners():
    score=7
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
    score = 7

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
    score = 8
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
    score=8
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
    score = 7
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
    score = 6
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

        else:
            score=0

        print(f"\nKey Vault: {name}")
        print(f" RBAC Enabled: {enable_rbac}")
        print(f" Soft Delete: {soft_delete}")
        print(f" Purge Protection: {purge_protection}")

    #print(detailed_info)
    return score, detailed_info

def get_vnets():
    result = subprocess.run([AZ_PATH, "network", "vnet", "list", "--output", "json"],
        capture_output=True,
        text=True,
        check=True
    )
    return json.loads(result.stdout)

def check_vm_nsg_port_restrictions():
    print("\nChecking if VMs have unrestricted inbound ports via NSG\n")
    score = 7
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
    print("\nChecking if vNets are segmented...")
    score = 7
    ip_ranges = {}
    detailed_info = {"Name": "Address"}

    if len(vnets) < 2:
        return 0, {"Error": "Less than 2 VNets provided. Consider segmenting workloads if necessary."}

    for vnet in vnets:
        vnet_name = vnet.get("name")
        address_space = vnet.get("addressSpace", {}).get("addressPrefixes", [])
        detailed_info[vnet_name] = address_space
        print(f"{vnet_name}: {address_space}")

        for prefix in address_space:
            if prefix in ip_ranges:
                print(f"Address space conflict: {prefix} used in both {ip_ranges[prefix]} and {vnet_name}")
                score = 0
                detailed_info["Conflict"] = f"{prefix} used in {ip_ranges[prefix]} and {vnet_name}"
            else:
                ip_ranges[prefix] = vnet_name

        subnets = vnet.get("subnets", [])
        if subnets:
            print("  Subnets:")
            for subnet in subnets:
                subnet_name = subnet.get("name")
                subnet_addresses = subnet.get("addressPrefixes", [])
                detailed_info[subnet_name] = subnet_addresses
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
    score = 7
    insecure_found = False
    detailed_info = {}

    result = subprocess.run(
        [AZ_PATH, "network", "nsg", "list", "--output", "json"],
        capture_output=True, text=True, check=True
    )
    nsgs = json.loads(result.stdout)

    for nsg in nsgs:
        nsg_name = nsg.get("name")
        for rule in nsg.get("securityRules", []):
            access = rule.get("access")
            proto = rule.get("protocol")
            src = rule.get("sourceAddressPrefix", "")
            dest = rule.get("destinationAddressPrefix", "")
            name= rule.get('name')
            if src == "*" or src == "0.0.0.0/0":
                is_any_src = True
            else:
                is_any_src = False

            if dest == "*" or  dest == "0.0.0.0/0":
                is_any_dest = True
            else:
                is_any_des= False

            rule_summary = f"{name} | Src: {src} | Dest: {dest} | Proto: {proto} | Access: {access}"
            if nsg_name not in detailed_info:
                detailed_info[nsg_name] = []

            detailed_info[nsg_name].append(rule_summary)

            if access == "Allow" and is_any_src and is_any_dest:
                print(f"Insecure rule in NSG '{nsg_name}': {rule_summary}")
                insecure_found = True
            else:
                print(f"NSG '{nsg_name}' rule '{rule.get('name')}' is scoped properly.")

    if insecure_found:
        score = 0

    return score, detailed_info



def check_azure_bastion():
    print("\nChecking for Azure Bastion deployments...")
    score =8
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

    else:
        print("Warning - No Azure Bastion hosts found. Secure access may be missing.")
        score=0
    print(detailed_info)
    return score, detailed_info


def check_azure_backup_snapshots():
    score = 8
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
            print(f"Snapchot exists for {name} : {rg}")
        else:
            print(f"Snapshot found for {name} : {rg}")
            score=0

    return score, detailed_info


def check_user_roles():

    print("\nChecking User Role Assignments...")
    score = 7
    detailed_info = {}

    result = subprocess.run(
        [AZ_PATH, "role", "assignment", "list", "--output", "json"],
        capture_output=True, text=True, check=True
    )
    assignments = json.loads(result.stdout)

    for assignment in assignments:
        principal_name = assignment.get("principalName")
        role = assignment.get("roleDefinitionName")
        scope = assignment.get("scope")

        if role.lower() == "owner":
            detailed_info[principal_name] = f"Owner on {scope}"

            if scope.count('/') > 2:
                print(f"Over-privileged: {principal_name} has Owner on nested scope: {scope}")
                score = 0
            else:
                print(f"{principal_name} has Owner on subscription: {scope}")
        else:
            print(f"{principal_name} has {role} on {scope}")

    return score, detailed_info




def check_azure_Firewall ():
    print("\nChecking for Azure Firewall deployments...")
    detailed_info = {"Name": "Location"}
    score=6
    result = subprocess.run(
        [AZ_PATH, "network", "firewall", "list", "--output", "json"],
        capture_output=True, text=True, check=True
    )
    firewalls = json.loads(result.stdout)

    if firewalls:
        for firewall in firewalls:
            detailed_info[firewall.get('name')]= firewall.get('location')
            print(f"Firewall host found: {firewall.get('name')} in {firewall.get('location')}")

    else:
        print("Warning - No Azure Firewall hosts found. Deploy immediately.")
        score = 0

    return score, detailed_info

def check_public_ips_on_vms():
    score = 7
    detailed_info={"Resource Name:":"IP address / Resource Group"}
    print("\nChecking for public IP addresses on virtual machines...")

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
            print(f"Public IP in use: {ip_name} ({ip_address}) in {resource_group}")
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
                    ("DCUI Shell Access", "Verifies if the DCUI account's shell access is disabled", check_dcui_shell_access(client)),
                    ("SSH Banner Content", "Verifies a SSH Banner is set to detter attackers", check_ssh_banner(client)),
                    ("SSH TCP Forwarding", "Checks if SSH TCP forwarding is disabled in the sshd_config file", check_ssh_tcp_forwarding(client)),
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
    score_permissive_owners, permissive_owners_details= check_user_roles()
    #list_users_roles_and_permissions()

    azure_checks = [
        ("Network Segmentation", "Check if VNets are segmented", score_vnet_seg, vnet_details),
        ("NSG Rules", "Check for overly permissive NSG rules", score_nsg, nsg_details),
        ("Azure Backups", "Checks if Azure backups are configured for VM's", score_backups, backups_details),
        ("VM Encryption", "Check if VMs have encryption at host enabled", score_vm_encryption, vm_encryption_details),
        ("Public IP Exposure", "Check for public IPs assigned to resources", score_public_ips, public_ip_details),
        ("Azure Firewall", "Check if Azure Firewall is deployed for perimeter security", score_fw, fw_details),
        ("Azure Bastion", "Check if Azure Bastion is deployed for secure access", score_bastion, bastion_details),
        ("Over permissive Owne Role", "Checks if Owner role is assigned outside the subscription scope",score_permissive_owners, permissive_owners_details),
        ("Key Vault Security", "Check Key Vault RBAC, Soft Delete, and Purge Protection", score_kv, kv_details),
        ("VM Inbound NSG Rules", "Checks if VM's have service ports open for all inbound IP addresses",score_inbound_nsg_vm, vm_nsg_details),
        ("Azure Snapshots", "Checks if snapshots are taken of VM's", score_snap, snap_details),
        ("VNet Encryption", "Check if VNets and peerings have encryption enabled", score_vnets, vnets_details),
        ("Subsctiption Owners", "Checks the number of owners on the subscription, Microsoft recommends less than 3",score_owners, owners_details),
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
    print(f"report generated: {pdf_filename}")

    send_email_with_report(
        sender_email="obrienciaran4@gmail.com",
        app_password="btuhojyekirqrksx",
        recipient_email="ciaran.obrien4@mycit.ie",
        subject=f"Zero Trust Security Report - {scan_date}",
        body="Please find attached the latest Zero Trust compliance report.",
        attachment_path="Hybrid-Cloud-ZTA-Report.pdf"
    )


if __name__ == '__main__':
    main()
