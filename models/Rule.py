class Rule:
	def __init__(self, name, option, acls):
		self.name = name
		self.option = option
		self.acls = list(acls)

	def __str__(self) -> str:
		return f"{self.name} {self.option} {' '.join(self.acls)}"

	def check_enable(self):
		if self.name.startswith("#"):
			return False
		else:
			return True

	def enable_rule(self):
		if not self.check_enable():
			self.name = self.name.split()[1]
			print(f"[+] Rule [{str(self)}] is enabled")
			return self.__str__()
		else:
			print(f"[!] Rule [{str(self)}] already enabled")

	def disable_rule(self):
		if self.check_enable():
			self.name = f"# {self.name}"
			print(f"[+] Rule [{str(self)}] is disabled")
			return self.__str__()
		else:
			print(f"[!] Rule [{str(self)}] already disabled")
