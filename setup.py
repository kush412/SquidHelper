import config
import json
from getpass import getpass
from modules import utils

banner = '''
███████╗ ██████╗ ██╗   ██╗██╗██████╗     ███████╗███████╗████████╗██╗   ██╗██████╗ 
██╔════╝██╔═══██╗██║   ██║██║██╔══██╗    ██╔════╝██╔════╝╚══██╔══╝██║   ██║██╔══██╗
███████╗██║   ██║██║   ██║██║██║  ██║    ███████╗█████╗     ██║   ██║   ██║██████╔╝
╚════██║██║▄▄ ██║██║   ██║██║██║  ██║    ╚════██║██╔══╝     ██║   ██║   ██║██╔═══╝ 
███████║╚██████╔╝╚██████╔╝██║██████╔╝    ███████║███████╗   ██║   ╚██████╔╝██║     
╚══════╝ ╚══▀▀═╝  ╚═════╝ ╚═╝╚═════╝     ╚══════╝╚══════╝   ╚═╝    ╚═════╝ ╚═╝     
                                                                                   
'''


def main():
	print(banner)
	while True:
		print('-' * 80)
		print('[+] SETUP OPTIONS:')
		print('\t1. BATCH SETUP')
		print('\t2. INTERACTIVE SETUP')
		print('\t3. UNINSTALL SQUID')
		print('-' * 80)
		try:
			choice = int(input('\n[+] Select an option: '))
			if choice == 1:
				batch_setup_file = input(f"[*] Path to setup file ({config.SETUP_FILE}): ")
				if len(batch_setup_file) == 0:
					batch_setup_file = config.SETUP_FILE
				with open(batch_setup_file, 'r') as file:
					servers = json.load(file)
					utils.batch_setup(servers)
			elif choice == 2:
				server = {
					"name": "",
					"ip_address": input('[+] Remote IP: '),
					"username": input('[+] Username: '),
					"password": getpass('[+] Password (leave empty to use SSH key): '),
					"ssh_key_path": None,
					"ssh_key_passphrase": None,
					"config_path": ""
				}
				if len(server['password']) == 0:
					server['ssh_key_path'] = input(f'[+] SSH key: ')
					if len(server['ssh_key_path']) == 0:
						server['ssh_key_path'] = config.SSH_KEY_PATH
						print(f'[+] Using SSH Key: {server["ssh_key_path"]}')
					server['ssh_key_passphrase'] = getpass(f'[+] Enter passphrase for key {server["ssh_key_path"]}: ')
				try:
					server['config_path'] = utils.backup_management(r'servers')
				except:
					pass
				utils.single_setup(server=server)
			elif choice == 3:
				hostname = input('[+] Remote IP: ')
				username = input('[+] Username: ')
				password = getpass('[+] Password (leave empty to use SSH key): ')
				ssh_key_path = None
				ssh_key_passphrase = None
				if len(password) == 0:
					ssh_key_path = input(f'[+] SSH key: ')
					if len(ssh_key_path) == 0:
						ssh_key_path = config.SSH_KEY_PATH
						print(f'[+] Using SSH Key: {ssh_key_path}')
					ssh_key_passphrase = getpass(f'[+] Enter passphrase for key {ssh_key_path}: ')
				utils.purge_squid(hostname, username, password, ssh_key_path, ssh_key_passphrase)
			else:
				print("\nGOOD LUCK!")
				break
		except Exception as e:
			print(f'An error has occurred in the setup procedure: {e}')


if __name__ == '__main__':
	main()
