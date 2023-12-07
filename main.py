from modules import core, utils
from getpass import getpass
import config


BANNER = '''
███████╗ ██████╗ ██╗   ██╗██╗██████╗     ██╗  ██╗███████╗██╗     ██████╗ ███████╗██████╗ 
██╔════╝██╔═══██╗██║   ██║██║██╔══██╗    ██║  ██║██╔════╝██║     ██╔══██╗██╔════╝██╔══██╗
███████╗██║   ██║██║   ██║██║██║  ██║    ███████║█████╗  ██║     ██████╔╝█████╗  ██████╔╝
╚════██║██║▄▄ ██║██║   ██║██║██║  ██║    ██╔══██║██╔══╝  ██║     ██╔═══╝ ██╔══╝  ██╔══██╗
███████║╚██████╔╝╚██████╔╝██║██████╔╝    ██║  ██║███████╗███████╗██║     ███████╗██║  ██║
╚══════╝ ╚══▀▀═╝  ╚═════╝ ╚═╝╚═════╝     ╚═╝  ╚═╝╚══════╝╚══════╝╚═╝     ╚══════╝╚═╝  ╚═╝

'''


def main():
    print(BANNER)
    server_ip = input('[+] Remote IP: ')
    server = utils.find_proxy_by_ip(server_ip, config.SETUP_FILE)
    if server is None:
        server = {
            'name': '',
            'ip_address': server_ip,
            'username': input('[+] Username: '),
            'password': getpass('[+] Password (leave empty to use SSH key): '),
            'ssh_key_path': None,
            'ssh_key_passphrase': None
        }
        if len(server['password']) == 0:
            server['ssh_key_path'] = input(f'[+] SSH key: ')
            if len(server['ssh_key_path']) == 0:
                server['ssh_key_path'] = config.SSH_KEY_PATH
                print(f'[+] Using SSH Key: {server["ssh_key_path"]}')
            server['ssh_key_passphrase'] = getpass(f'[+] Enter passphrase for key {server["ssh_key_path"]}: ')
    config_file = utils.download_config_file(server)
    extracted_acls = core.extract_squid_element(config_file)
    extracted_rules = core.extract_squid_rule(config_file)
    tmp_file = utils.prep_tmp_file(config_file, extracted_acls, extracted_rules)
    while True:
        print('\n[*] Features list:')
        print(f'{" ":>4}1. ACL MANAGEMENT')
        print(f'{" ":>4}2. RULE MANAGEMENT')
        print(f'{" ":>4}3. BACKUP MANAGEMENT')
        print(f'{" ":>4}4. SAVE CONFIG')
        print('----------------------')
        try:
            choice = int(input('\n[+] Select an option: '))
            if choice == 1:
                core.ACL_MENU(extracted_rules, extracted_acls)
            elif choice == 2:
                core.RULE_MENU(extracted_rules, extracted_acls)
            elif choice == 3:
                selected_file = utils.backup_management(r"servers")
                utils.local_backup(config_file, tmp_file)
                utils.upload_config_file(server, selected_file)
                break
            elif choice == 4:
                utils.add_config_to_file(tmp_file, extracted_acls)
                utils.add_config_to_file(tmp_file, extracted_rules)
                utils.local_backup(config_file, tmp_file)
                utils.upload_config_file(server, config_file)
                break
            else:
                utils.local_backup(config_file, tmp_file)
                break
        except Exception as e:
            print(f'An error occurred: {e}.')


if __name__ == "__main__":
    main()
