import math
import config
from getpass import getpass
import time
import shutil
import json
import paramiko
import os
import re


def find_proxy_by_ip(ip_to_find, json_file_path):
    with open(json_file_path, 'r') as file:
        proxies = json.load(file)

    for proxy in proxies:
        if proxy.get("ip_address") == ip_to_find:
            return proxy

    return None


# Create tmp file to update config
def prep_tmp_file(config_file, acl_list, rule_list):
    output_file = config_file + '.tmp'
    lines_to_delete = [str(acl).strip() for acl in acl_list] + [str(rule).strip() for rule in rule_list]
    try:
        with open(config_file, 'r') as file_in:
            lines = file_in.readlines()
        with open(output_file, 'w') as file_out:
            for line in lines:
                if line.strip() not in lines_to_delete:
                    file_out.write(line)
        print(f"[+] Temp file {output_file} created successfully.")
        return output_file
    except FileNotFoundError:
        print(f"Error: The config file '{config_file}' was not found.")
    except Exception as e:
        print(f"An error occurred: {str(e)}")


# Create backup locally
def local_backup(config_file_path, temp_file_path):
    # Create a backup of the current configuration file
    backup_file_path = config_file_path + f"_{str(math.floor(time.time()))}" + ".bak"
    # shutil.copy(config_file_path, backup_file_path)
    os.rename(config_file_path, backup_file_path)
    try:
        # Rename the temporary file to the configuration file
        os.rename(temp_file_path, config_file_path)
        print(f"[+] Backup created at: {backup_file_path}")
        print(f"[+] Configuration file updated successfully.")
    except Exception as e:
        # If an error occurs, restore the backup
        shutil.move(backup_file_path, config_file_path)
        print(f"An error occurred. Restored the backup. Error: {str(e)}")


# Validate server json file
def valid_server_input(server):
    print(f'[*] Validating server [{server["name"] if server["name"] else "Unnamed host"}] information')
    if not re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", server.get('ip_address')) or not server.get('ip_address'):
        print(f'[!] Invalid IP address: {server.get("ip_address")}')
        return False
    if not server.get('password') or server.get('password') == "":
        if not server.get('ssh_key_path') or server.get('ssh_key_path') == "":
            server['ssh_key_path'] = config.SSH_KEY_PATH
        if not server.get('ssh_key_passphrase') or server.get('ssh_key_passphrase') == "":
            print('Please provide passphrase to decrypt SSH key.')
            decrypt_passwd = getpass(
                f'[+] Enter passphrase for key {server.get("ssh_key_path")}: ')
            server['ssh_key_passphrase'] = decrypt_passwd
    print(
        f'[+] Config loaded for {server["name"]} | IP: {server["ip_address"]} | user: {server["username"]} | key: {server["ssh_key_path"] if server["ssh_key_path"] else "None"} | config: {server["config_path"] if "config_path" in server and server["config_path"] != "" else "None"}')
    return True


# Loops
def batch_setup(servers: list):
    for server in servers:
        try:
            single_setup(server)
            print('\n' + '=' * 80 + '\n')
        except Exception as e:
            print(f'[!] Setting up server {server["ip_address"]} failed: {e}')
            print('\n' + '=' * 80 + '\n')


# Setup
def single_setup(server: dict):
    if valid_server_input(server):
        hostname = server.get('ip_address')
        username = server.get('username')
        password = server.get('password')
        key_filename = server.get('ssh_key_path')
        passphrase = server.get('ssh_key_passphrase')
        try:
            config_path = server.get('config_path')
        except:
            config_path = ''
    else:
        print('[!] Failed to load server information!')
        return

    # Install
    print('[*] Checking if Squid is already installed...')
    if not squid_installed(hostname, username, password, key_filename, passphrase):
        print('[!] Squid is not installed. Preparing to install Squid...')
        install_squid(hostname, username, password, key_filename, passphrase)
        if squid_installed(hostname, username, password, key_filename, passphrase):
            print('[+] Installed Squid successfully.')
        else:
            print('[!] Failed to install squid. Aborting...')
            return
    else:
        print('[+] Squid is already installed.')

    # Backup
    if have_backup_squid(hostname, username, password, key_filename, passphrase):
        print('[+] Backup for squid.conf exists.')
        cont = input("[?] Continue to proceed [Y/n]: ")
        if cont.lower() == '' or cont.lower() == 'y':
            pass
        else:
            print(f"[+] Skipping setup for server {server['ip_address']}")
            return
    else:
        print('[!] No backup for squid.conf. Creating backup...')
        backup_squid(hostname, username, password, key_filename, passphrase)
        print('[+] Backup is created.')

    # Configure
    if config_path != '':
        print(f'[*] Uploading new configurations')
        if os.path.exists(f"{config.SAMPLE_DIR}/{config_path}"):
            put_proxy_config(hostname, username, password, key_filename,
                             passphrase, config_file=f"{config.SAMPLE_DIR}/{config_path}")
        elif os.path.exists(config_path):
            put_proxy_config(hostname, username, password, key_filename,
                     passphrase, config_file=config_path)
        else:
            print("[!] Config file is not found.")
    else:
        print('[!] No configuration file loaded. Skipping configuring procedure.')


# RCE
def run_command(hostname, username, password, key_filename, passphrase, command, prompt=None):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(hostname=hostname, port=22, username=username,
                       password=password, key_filename=key_filename, passphrase=passphrase, timeout=10)
        _stdin, _stdout, _stderr = client.exec_command(command)
        if prompt is not None:
            _stdin.write(f'{prompt}\n')
            _stdin.flush()
        stdout = _stdout.read().decode()
        stderr = _stderr.read().decode()
        client.close()
        return stdout, stderr
    except Exception as e:
        print(f'[!] Error in executing {command}: {e}')


# Check squid is installed
def squid_installed(hostname, username, password, key_filename, passphrase):
    command = 'service squid status'
    stdout, stderr = run_command(
        hostname, username, password, key_filename, passphrase, command)
    if len(stderr) > 0 or "Unit squid.service not found" in stdout:
        return False
    else:
        return True


# Install squid
def install_squid(hostname, username, password, key_filename, passphrase):
    command = 'sudo -S apt-get update && sudo -S apt-get install squid-openssl -y'
    if not password and username != 'root':
        prompt = getpass('[+] Enter password to install Squid: ')
    else:
        prompt = password
    run_command(
        hostname, username, password, key_filename, passphrase, command, prompt=f"{prompt}\n{prompt}")


# Purge squid
def purge_squid(hostname, username, password, key_filename, passphrase):
    command = 'sudo -S apt-get purge --auto-remove squid* -y && sudo -S rm -rf /etc/squid'
    if not password and username != 'root':
        prompt = getpass('[+] Enter password to purge Squid: ')
    else:
        prompt = password
    try:
        print("[!] Uninstalling Squid")
        run_command(
            hostname, username, password, key_filename, passphrase, command, prompt=f"{prompt}\n{prompt}")
        print("[+] Squid has been uninstalled successfully.")
    except Exception as e:
        print(f'[!] Error in removing squid: {e}')


# Create backup remotely
def backup_squid(hostname, username, password, key_filename, passphrase):
    command = 'sudo -S chmod -R 777 /etc/squid && sudo -S cp /etc/squid/squid.conf /etc/squid/squid.conf.bak && sudo -S chmod -R 744 /etc/squid'
    if not password and username != 'root':
        prompt = getpass('[+] Enter password to backup Squid: ')
    else:
        prompt = password
    try:
        run_command(
            hostname, username, password, key_filename, passphrase, command, prompt=f"{prompt}\n{prompt}\n{prompt}")
    except Exception as e:
        print(f'Backup error: {e}')


# Check if backup is created
def have_backup_squid(hostname, username, password, key_filename, passphrase):
    command = 'sudo -S ls /etc/squid/squid.conf.bak'
    if not password and username != 'root':
        prompt = getpass('[+] Enter password to backup Squid: ')
    else:
        prompt = password
    stdout, stderr = run_command(
        hostname, username, password, key_filename, passphrase, command, prompt)
    if len(stdout) > 0:
        return True
    elif len(stderr) > 0:
        return False


# Upload config files
def put_proxy_config(hostname, username, password, key_filename, passphrase, config_file, working_dir_ip=''):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    command = 'sudo -S chmod -R 777 /etc/squid'
    if not password and username != 'root':
        prompt = getpass('[+] Enter password to config Squid: ')
    else:
        prompt = password
    run_command(hostname, username, password, key_filename,
                    passphrase, command, prompt)
    try:

        client.connect(hostname, port=22, username=username,
                       password=password, key_filename=key_filename, passphrase=passphrase, timeout=10)
        sftp_client = client.open_sftp()
        try:
            sftp_client.mkdir(f'{config.SQUID_PATH}/ssl_cert')
        except:
            pass
        try:
            sftp_client.mkdir(f'{config.SQUID_PATH}/blacklist')
        except:
            pass
        try:
            sftp_client.mkdir(f'{config.SQUID_PATH}/whitelist')
        except:
            pass
        sftp_client.put(config_file, f'{config.SQUID_PATH}/squid.conf')
        command = 'sudo -S chmod -R 700 /etc/squid/ssl_cert'
        if username != 'root' and not password:
            prompt = getpass('[+] Enter password to backup Squid: ')
        else:
            prompt = password
        run_command(hostname, username, password, key_filename,
                        passphrase, command, prompt)
        if working_dir_ip == '':
            sftp_client.put(config.SAMPLE_PEM, config.SQUID_PEM)
            sftp_client.put(config.SAMPLE_DER, config.SQUID_DER)
            sftp_client.put(config.BLACKLIST_DOMAIN_TEMPLATE,
                            f'{config.SQUID_PATH}/blacklist/domain.txt')
            sftp_client.put(config.BLACKLIST_EXTENSION_TEMPLATE,
                            f'{config.SQUID_PATH}/blacklist/extension.txt')
            sftp_client.put(config.BLACKLIST_IP_TEMPLATE,
                            f'{config.SQUID_PATH}/blacklist/ip.txt')
            sftp_client.put(config.WHITELIST_DOMAIN_TEMPLATE,
                            f'{config.SQUID_PATH}/whitelist/domain.txt')
            sftp_client.put(config.WHITELIST_IP_TEMPLATE,
                            f'{config.SQUID_PATH}/whitelist/ip.txt')
            sftp_client.put(config.WHITELIST_EXTENSION_TEMPLATE,
                            f'{config.SQUID_PATH}/whitelist/extension.txt')
        else:
            sftp_client.put(f'{config.WORKING_DIR}/{working_dir_ip}/blacklist/domain.txt',
                            f'{config.SQUID_PATH}/blacklist/domain.txt')
            sftp_client.put(f'{config.WORKING_DIR}/{working_dir_ip}/blacklist/extension.txt',
                            f'{config.SQUID_PATH}/blacklist/extension.txt')
            sftp_client.put(f'{config.WORKING_DIR}/{working_dir_ip}/blacklist/ip.txt',
                            f'{config.SQUID_PATH}/blacklist/ip.txt')
            sftp_client.put(f'{config.WORKING_DIR}/{working_dir_ip}/whitelist/domain.txt',
                            f'{config.SQUID_PATH}/whitelist/domain.txt')
            sftp_client.put(f'{config.WORKING_DIR}/{working_dir_ip}/whitelist/extension.txt',
                            f'{config.SQUID_PATH}/whitelist/extension.txt')
            sftp_client.put(f'{config.WORKING_DIR}/{working_dir_ip}/whitelist/ip.txt',
                            f'{config.SQUID_PATH}/whitelist/ip.txt')
        sftp_client.close()
        client.close()

    except Exception as e:
        print(f'An error occurred in putting new config: {e}')
    if username != 'root':
        command = f'sudo -S chmod -R 744 /etc/squid && sudo -S squid -f {config.SQUID_PATH}/squid.conf'
        if not password and username != 'root':
            prompt = getpass('[+] Enter password to restart Squid: ')
        else:
            prompt = password
        run_command(hostname, username, password, key_filename,
                    passphrase, command, prompt=f"{prompt}\n{prompt}")

    print('[*] Restarting squid service')
    command = 'sudo -S systemctl restart squid'
    if not password and username != 'root':
        prompt = getpass('[+] Enter password to restart Squid: ')
    else:
        prompt = password
    sO, sE = run_command(hostname, username, password, key_filename, passphrase, command, prompt=f"{prompt}")
    if "error" in sE.lower() or "failed" in sE.lower():
        print('[!] Error. Please check log')
    else:
        print('[+] Done.')


# Download config files
def get_proxy_config(hostname, username, password, key_filename, passphrase):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    if username != 'root':
        command = 'sudo -S chmod -R 777 /etc/squid'
        run_command(hostname, username, password, key_filename,
                    passphrase, command, password)
    try:
        client.connect(hostname, port=22, username=username,
                       password=password, key_filename=key_filename, passphrase=passphrase, timeout=10)
        sftp_client = client.open_sftp()
        try:
            os.mkdir(f'{config.WORKING_DIR}/{hostname}')
        except Exception as e:
            pass
        try:
            os.mkdir(f'{config.WORKING_DIR}/{hostname}/blacklist')
        except Exception as e:
            pass
        try:
            os.mkdir(f'{config.WORKING_DIR}/{hostname}/whitelist')
        except Exception as e:
            pass

        sftp_client.get(f'{config.SQUID_PATH}/squid.conf',
                        f'{config.WORKING_DIR}/{hostname}/squid.conf')
        print("[+] Downloaded file config")
        try:
            sftp_client.get(config.DOMAIN_BLACKLIST,
                            f'{config.WORKING_DIR}/{hostname}/blacklist/domain.txt')
            sftp_client.get(config.EXTENSION_BLACKLIST,
                            f'{config.WORKING_DIR}/{hostname}/blacklist/extension.txt')
            sftp_client.get(config.IP_BLACKLIST,
                            f'{config.WORKING_DIR}/{hostname}/blacklist/ip.txt')
            sftp_client.get(config.DOMAIN_WHITELIST,
                            f'{config.WORKING_DIR}/{hostname}/whitelist/domain.txt')
            sftp_client.get(config.EXTENSION_WHITELIST,
                            f'{config.WORKING_DIR}/{hostname}/whitelist/extension.txt')
            sftp_client.get(config.IP_WHITELIST,
                            f'{config.WORKING_DIR}/{hostname}/whitelist/ip.txt')
        except:
            pass
        sftp_client.close()
        client.close()
        if username != 'root':
            command = 'sudo -S chmod -R 744 /etc/squid'
            run_command(hostname, username, password, key_filename,
                        passphrase, command, password)
    except Exception as e:
        print(f'[!] An error occurred in getting file config: {e}')
        exit(0)


def download_config_file(server):
    if valid_server_input(server):
        hostname = server.get('ip_address')
        username = server.get('username')
        password = server.get('password')
        key_filename = server.get('ssh_key_path')
        passphrase = server.get('ssh_key_passphrase')
    else:
        print('[!] Failed to load server information!')
        return

    print(f"[+] Retrieving server {hostname} configurations")
    get_proxy_config(hostname, username, password, key_filename, passphrase)
    config_file = f"{config.WORKING_DIR}/{hostname}/squid.conf"
    return config_file


def upload_config_file(server, config_file):
    if valid_server_input(server):
        hostname = server.get('ip_address')
        username = server.get('username')
        password = server.get('password')
        key_filename = server.get('ssh_key_path')
        passphrase = server.get('ssh_key_passphrase')
    else:
        print('[!] Failed to load server information!')
        return

    print(f"[+] Updating server {hostname} configurations")
    put_proxy_config(hostname, username, password, key_filename, passphrase, config_file, working_dir_ip=hostname)


# Modify config to tmp file
def add_config_to_file(file_path, new_conf):
    try:
        with open(file_path, 'a') as file:
            for obj in new_conf:
                line = str(obj)
                file.write(line + '\n')
        # print(f"New configurations updated to '{file_path}' successfully.")
    except FileNotFoundError:
        print(f"Error: The file '{file_path}' was not found.")
    except Exception as e:
        print(f"An error occurred: {str(e)}")


def backup_management(folder_path, valid_extensions=None):
    if valid_extensions is None:
        valid_extensions = [".bak", ".conf"]
    while True:
        # Get the list of files and subdirectories in the given folder
        items = os.listdir(folder_path)

        if not items:
            print("[!] No files or folders found in the given folder.")
            return

        # Display the list of files and subdirectories to the user
        print("[+] Select a configuration file:")
        for i, item in enumerate(items, start=1):
            print(f"{i}. {item}")

        # Let the user select an item
        try:
            selected_index = int(input("[+] Enter the number corresponding to the file/folder you want to select (0 to go back): "))

            # Handle the case where the user wants to go back to the parent directory
            if selected_index == 0:
                parent_folder = os.path.dirname(folder_path)
                # print(f"[*] Going back to the parent directory: {parent_folder}")
                folder_path = parent_folder
            elif 0 < selected_index <= len(items):
                selected_item = items[selected_index - 1]
                selected_item_path = os.path.join(folder_path, selected_item)

                if os.path.isfile(selected_item_path):
                    if any(selected_item.endswith(ext) for ext in valid_extensions):
                        print(f"[+] You selected a valid file: {selected_item}")
                        return selected_item_path
                    else:
                        print(
                            f"[!] Invalid file. Please select a file with one of the following extensions: {', '.join(valid_extensions)}")
                elif os.path.isdir(selected_item_path):
                    print(f"[+] You selected a folder: {selected_item}")
                    # Recursively call the function for the selected subdirectory
                    folder_path = selected_item_path
            else:
                print("[!] Invalid input. Please enter a valid number.")
        except ValueError:
            print("[!] Invalid input. Please enter a valid number.")
