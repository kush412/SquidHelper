from models.Rule import Rule
from models.Element import Element
import config


def extract_squid_element(file_path):
	elements = []
	element_acl = [element["name"] for element in config.LIST_ACL_NAME]
	try:
		with open(file_path, 'r') as squid_config:
			for line in squid_config:
				line = line.strip().split(' ')

				if len(line) > 2 and (line[0] == "acl" or line[0] == "#acl") and line[2] in element_acl:
					_enabled = line[0]
					name = line[1]
					acl = line[2]
					if '#' in line[3:]:
						index = line[3:].index('#')
						# print(index)
						value = ' '.join(line[3:3 + index])
						description = (' '.join(line[3 + index:])).strip('\n')
					# print(description)
					else:
						value = (' '.join(line[3:])).strip('\n')
						description = ''
					# new_ele = Element
					elements.append(Element(_enabled, name, acl, value, description))
				elif len(line) > 3 and line[1] == "acl" and line[3] in element_acl:
					_enabled = ' '.join(line[0:2])
					name = line[2]
					acl = line[3]
					if '#' in line[4:]:
						index = line[4:].index('#')
						value = ' '.join(line[4:4 + index])
						description = (' '.join(line[4 + index:])).strip('\n')
					# print(description)
					else:
						value = (' '.join(line[4:])).strip('\n')
						description = ''
					elements.append(Element(_enabled, name, acl, value, description))
				else:
					continue
			return elements
	except FileNotFoundError:
		print('Error with file parsing')


def extract_squid_rule(file_path):
	rules = []
	rule_name = [rule["name"] for rule in config.LIST_RULE_NAME]
	try:
		with open(file_path, 'r') as squid_config:
			for line in squid_config:
				line = line.strip().split(' ')

				if len(line) > 0 and line[0] in rule_name and (line[1] == "deny" or line[1] == "allow"):
					name = line[0]
					option = line[1]
					acls = line[2:]
					rules.append(Rule(name, option, acls))
				elif len(line) > 1 and line[1] in rule_name and (line[2] == "deny" or line[2] == "allow"):
					name = ' '.join(line[0:2])
					option = line[2]
					acls = line[3:]
					rules.append(Rule(name, option, acls))
				else:
					continue
			return rules
	except FileNotFoundError:
		print('Error with file parsing')


def check_acl_name(acl_name, acl_element, acl_list):
	for acl in acl_list:
		if acl.name == acl_name:
			if acl.acl == acl_element:
				continue
			print(f'[!] Name "{acl_name}" already existed!')
			return True
		else:
			continue
	return False


def list_acl(acl_list, sub_list=None):
	print("[+] LIST OF ACLS:")
	if sub_list is None or len(sub_list) == 0:
		sub_list = acl_list
	for acl in sub_list:
		print(f'{acl_list.index(acl):>2} - {str(acl)}')


def select_acl(acl_list):
	found_acls = find_objects_with_substring(acl_list, input("[*] ACL keyword: "))
	list_acl(acl_list, found_acls)
	try:
		num = int(input('[+] Select index of acl: '))
		if num in range(len(acl_list)):
			acl = acl_list[num]
			# print(f'[+] Selected {acl}')
			return acl
		else:
			print('[!] No ACL is selected.')
			return
	except Exception as e:
		print(e)


def create_new_acl(acl_list):
	found_acls = find_objects_with_substring(config.LIST_ACL_NAME, input("[*] Element keyword: "))
	for acl in found_acls:
		print(f"- {acl['name']:<20} : {acl['description']}")
	acl_element = input("[?] ACL element: ")
	if acl_element in [element["name"] for element in config.LIST_ACL_NAME]:
		try:
			acl_name = input('[?] ACL name: ')
			if check_acl_name(acl_name, acl_element, acl_list):
				return
			if acl_name == '':
				print('[!] ACL name cannot be empty')
				return
			acl_value = input('[?] ACL value: ')
			if acl_value == '':
				print(f'[!] ACL value cannot be empty!')
				return
			acl_definition = input('[?] ACL definition: ')
			new_acl = Element(_enabled='acl', name=acl_name, acl=acl_element, value=acl_value,
			                  description=f'# {acl_definition}')
			add_to_list = input(f'[+] Add new acl: {new_acl} [Y/n]?')
			if add_to_list.lower() == 'y' or add_to_list == '':
				acl_list.append(new_acl)
				print(f'[+] New acl [{new_acl.name}] added successfully!')
			else:
				print('[!] Aborted!')
				return
		except Exception as e:
			print(e)
	else:
		print(f'[!] ACL {acl_element} not found!')


def update_acl(acl: Element, acl_list: list, rule_list: list):
	disable_acl = input(f'{"[?] Disable" if acl.check_enabled() else "[?] Enable"} ACL "{acl.name}" [Y/n]? ')
	if disable_acl.lower() == 'y' or disable_acl.lower() == '':
		acl.disable_element() if acl.check_enabled() else acl.enable_element()
	else:
		print(f"[+] Updating acl [{acl}]")
		found_acls = find_objects_with_substring(config.LIST_ACL_NAME, input("[*] New element keyword: "))
		for ele in found_acls:
			print(f"- {ele['name']:<20} : {ele['description']}")
		new_ele = input(f"[+] Current acl [{acl.acl}] - New acl (leave blank for no change): ")
		if new_ele in [element["name"] for element in config.LIST_ACL_NAME] or new_ele == '':
			if new_ele != '':
				acl.acl = new_ele
			try:
				rules_contain_acl = rules_contain_acl_name(acl.name, rule_list)
				new_name = input(f'[+] Current name [{acl.name}] - New name (leave blank for no change): ')
				if new_name != '':
					if not check_acl_name(new_name, new_ele, acl_list):
						for rule in rules_contain_acl:
							rule.acls[rule.acls.index(acl.name)] = new_name
						acl.name = new_name
				new_value = input(f'[+] Current value [{acl.value}] - New value (leave blank for no change: ')
				if new_value != '':
					acl.value = new_value
				new_definition = input(
					f'[+] Current definition [{acl.description}] - New definition (leave blank for no change): ')
				if new_definition != '':
					acl.description = new_definition
				print(f'[+] acl [{acl.name}] updated successfully!')
			except Exception as e:
				print(e)
		else:
			print(f'[!] acl [{new_ele}] not found!')
	return acl


def delete_acl(acl: Element, acl_list: list):
	choice = input(f"[?] Delete acl '{acl}' [Y/n]: ")
	if choice.lower() == 'y' or choice == '':
		acl_list.remove(acl)
		print(f"[-] ACL {acl} deleted successfully!")
	else:
		return


def map_acl_by_name(list_of_name, acl_list: [Element], is_print=False):
	list_of_acl = []
	for name in list_of_name:
		for acl in acl_list:
			if acl.name == name or name == f"!{acl.name}":
				if is_print:
					print(acl)
				list_of_acl.append(acl)
	return list_of_acl


def list_rule(rule_list, sub_list=None):
	print("[+] LIST OF RULES:")
	if sub_list is None or len(sub_list) == 0:
		sub_list = rule_list
	for rule in sub_list:
		print(f'{rule_list.index(rule):>2} - {rule}')


def select_rule(rule_list):
	found_rules = find_objects_with_substring(rule_list, input('[*] Rule keywords: '))
	list_rule(rule_list, found_rules)
	num = input('[+] Select index of rule: ')
	try:
		num = int(num)
		if num in range(len(rule_list)):
			rule = rule_list[num]
			# print(f'[+] Selected {rule}')
			return rule
		else:
			print("[!] No rule is selected.")
			return
	except Exception as e:
		print(e)


def rules_contain_acl_name(acl_name, rule_list):
	imp_rules = []
	for rule in rule_list:
		if acl_name in rule.acls:
			imp_rules.append(rule)
	return imp_rules


def create_new_rule(rule_list, acl_list):
	found_rules = find_objects_with_substring(config.LIST_RULE_NAME, input('[*] Rule keyword: '))
	for rule in found_rules:
		print(f"- {rule['name']:<25} : {rule['description']}")
	rule_name = input("[?] Rule: ")
	if rule_name in [rule['name'] for rule in config.LIST_RULE_NAME]:
		try:
			rule_option = input('[?] Rule option (allow|deny): ')
			if rule_option.lower() == 'a' or rule_option.lower() == 'allow':
				rule_option = 'allow'
			elif rule_option.lower() == 'd' or rule_option.lower() == 'deny':
				rule_option = 'deny'
			else:
				print(f'[!] Option [{rule_option}] not found!')
				return
			rule_value = []
			rule_value_number = input('[?] Number of acl(s): ')
			if (rule_value_number == '') or (int(rule_value_number) < 1) or (int(rule_value_number) > len(acl_list)):
				acl = select_acl(acl_list)
				value = acl.name
				rule_value.append(value)
			else:
				for num in range(int(rule_value_number)):
					acl = select_acl(acl_list)
					value = acl.name
					if value not in rule_value:
						rule_value.append(value)
					else:
						print(f'acl [{value}] already added!')
						continue
			new_rule = Rule(name=rule_name, option=rule_option, acls=rule_value)
			add_to_list = input(f'[+] Add new acl [{new_rule}] [Y/n]?')
			if add_to_list.lower() == 'y' or add_to_list == '':
				rule_list.append(new_rule)
				print(f'[+] Rule [{new_rule}] has been added successfully!')
				return new_rule
			else:
				print('[!] Aborted!')
		except Exception as e:
			print(e)
	else:
		print(f'[!] Rule [{rule_name}] not found!')


def validate_rule(acl: Element, rule_list, acl_list):
	print(f'[*] Validating rules with updated ACL: [{acl}]')
	for rule in rule_list:
		if acl.name in rule.acls:
			if [ele.name for ele in acl_list].count(acl.name) < 1:
				rule.disable_rule()
	print(f'[+] Validated rules with updated ACL: [{acl}]')


def validate_rules_and_acls(rule_list, acl_list):
	print('[*] Validating all rules and acls.')
	for rule in rule_list:
		if rule.check_enable():
			list_rule_acls_name = rule.acls
			for acl_name in list_rule_acls_name:
				if [ele.name for ele in acl_list].count(acl_name) < 1 and acl_name not in ['manager', 'all', 'localhost']:
					rule.disable_rule()
	print('[+] Validated all rules and acls.')


def update_rule(rule: Rule, acl_list):
	disable_rule = input(f'{"[?] Disable" if rule.check_enable() else "[?] Enable"} rule "{rule.name}" [Y/n]? ')
	if disable_rule.lower() == 'y' or disable_rule.lower() == '':
		rule.disable_rule() if rule.check_enable() else rule.enable_rule()
	else:
		print(f"[+] Updating rule [{rule}]")
		found_rules = find_objects_with_substring(config.LIST_RULE_NAME, input('[*] Rule keyword: '))
		for _rule in found_rules:
			print(f"- {_rule['name']:<25} : {_rule['description']}")
		new_name = input(f"[+] Current rule name [{rule.name}] - New rule name (leave blank for no change): ")
		if new_name in [rule['name'] for rule in config.LIST_RULE_NAME] or new_name == '':
			if new_name != '':
				rule.name = new_name
			try:
				new_option = input('[+] Rule option (allow|deny): ')
				if new_option.lower() == 'a' or new_option.lower() == 'allow':
					rule.option = 'allow'
				elif new_option.lower() == 'd' or new_option.lower() == 'deny':
					rule.option = 'deny'
				else:
					print(f'[!] Option [{new_option}] not found. Current option: [{rule.option}] is not changed.')
				print('[+] ACLs in this rule:')
				map_acl_by_name(rule.acls, acl_list, True)
				new_acl_number = input('[+] Number of new acl(s): ')
				if 0 < int(new_acl_number) < len(acl_list):
					for num in range(int(new_acl_number)):
						acl = select_acl(acl_list)
						new_acl_name = acl.name
						if new_acl_name not in rule.acls:
							rule.acls.append(new_acl_name)
						else:
							print(f'[!] acl [{new_acl_name}] already added!')
							continue
				else:
					print('[!] Failed to add new ACL')
				print('[+] ACLs in this rule:')
				map_acl_by_name(rule.acls, acl_list, True)
				remove_acl_number = input('[+] Number of removing acl(s): ')
				if 0 < int(remove_acl_number) < len(rule.acls):
					for num in range(int(remove_acl_number)):
						acl = select_acl(rule.acls)
						rule.acls.remove(acl)
				else:
					print('[!] Failed to remove ACL')
			except Exception as e:
				print(e)
		else:
			print(f'[!] Rule [{new_name}] not found!')
	return rule


def validate_acl(rule: Rule, acl_list):
	print("[*] Validating acls.")
	list_of_acl = map_acl_by_name(rule.acls, acl_list)
	if len(list_of_acl) > 0:
		for acl in list_of_acl:
			if ([ele.name for ele in acl_list].count(acl.name) <= 1 and not acl.check_enabled()) or \
				[ele._enabled for ele in acl_list].count(acl.check_enabled()) == len(list_of_acl) or \
				(len(list_of_acl) < len(rule.acls) and "manager" not in rule.acls):
				print(f"[!] Failed to enable rule [{rule.name}] due to invalid acls.")
				rule.disable_rule()
			else:
				print("[+] All acls are validated.")
	else:
		rule.disable_rule()


def delete_rule(rule: Rule, rule_list: list):
	choice = input(f"[?] Delete rule {rule} [Y/n]: ")
	if choice.lower() == 'y' or choice == '':
		rule_list.remove(rule)
		print(f"[-] Rule {rule} deleted successfully!")
	else:
		return


def swap_rule_index(rule_list: list, selected_rule: Rule):
	"""Swaps the positions of two objects in a list."""
	try:
		new_index = int(input(f"[+] New position (0-{len(rule_list) - 1}): "))
		if 0 <= rule_list.index(selected_rule) < len(rule_list) and 0 <= new_index < len(rule_list):
			rule_list[rule_list.index(selected_rule)], rule_list[new_index] = rule_list[new_index], rule_list[
				rule_list.index(selected_rule)]
		else:
			print("[!] Invalid positions. Make sure positions are within the list bounds.")
	except Exception as e:
		print(f"[!] An error occurred: {e}")


def find_objects_with_substring(my_list, substring):
	"""Finds objects in a list that contain a certain substring."""
	matching_objects = []

	for obj in my_list:
		if type(obj) is dict:
			# Iterate through the attributes of the dict
			for attr_name, attr_value in obj.items():
				# Check if the substring is present in the attribute value
				if substring in str(attr_value):
					matching_objects.append(obj)
					break
		else:
			# Iterate through the attributes of the object
			for attr_name, attr_value in vars(obj).items():
				# Check if the substring is present in the attribute value
				if substring in str(attr_value):
					matching_objects.append(obj)
					break

	if len(matching_objects) > 0:
		return matching_objects
	else:
		print('[!] Keyword not found!')
		return my_list


def ACL_MENU(rule_list, acl_list):
	# EXTRACTED_ACL_LIST = extract_squid_element(config_file)
	while True:
		print('\n[*] ACL Management:')
		print(f'{" ":>4}1. List acl')
		print(f'{" ":>4}2. Create acl')
		print(f'{" ":>4}3. Update acl')
		print(f'{" ":>4}4. Delete acl')
		print('----------------------')
		try:
			choice = int(input('\n[+] Select an option: '))
			if choice == 1:
				list_acl(acl_list)
			elif choice == 2:
				create_new_acl(acl_list)
			elif choice == 3:
				selected_acl = select_acl(acl_list)
				update_acl(selected_acl, acl_list, rule_list)
				validate_rule(selected_acl, rule_list, acl_list)
			elif choice == 4:
				selected_acl = select_acl(acl_list)
				delete_acl(selected_acl, acl_list)
				validate_rule(selected_acl, rule_list, acl_list)
			else:
				validate_rules_and_acls(rule_list, acl_list)
				break
		except Exception as e:
			print(f'An error occurred: {e}')


def RULE_MENU(rule_list, acl_list):
	# EXTRACTED_ACL_LIST = extract_squid_element(config_file)
	# EXTRACTED_RULE_LIST = extract_squid_rule(config_file)
	while True:
		print('\n[*] RULE MANAGEMENT:')
		print(f'{" ":>4}1. List rule')
		print(f'{" ":>4}2. Swap rule index')
		print(f'{" ":>4}3. Create new rule')
		print(f'{" ":>4}4. Update rule')
		print(f'{" ":>4}5. Delete rule')
		print('----------------------')
		try:
			choice = int(input('\n[+] Select an option: '))
			if choice == 1:
				list_rule(rule_list, [])
			elif choice == 2:
				swap_rule_index(rule_list, select_rule(rule_list))
			elif choice == 3:
				new_rule = create_new_rule(rule_list, acl_list)
				validate_acl(new_rule, acl_list)
			elif choice == 4:
				selected_rule = select_rule(rule_list)
				update_rule(selected_rule, acl_list)
				validate_acl(selected_rule, acl_list)
			elif choice == 5:
				delete_rule(select_rule(rule_list), rule_list)
			else:
				validate_rules_and_acls(rule_list, acl_list)
				break
		except Exception as e:
			print(f'An error has occurred: {e}')
