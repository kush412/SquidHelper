class Element:
	def __init__(self, _enabled, name, acl, value, description):
		self._enabled = _enabled
		self.name = name
		self.acl = acl
		self.value = value
		self.description = description

	def __str__(self) -> str:
		return f"{self._enabled} {self.name} {self.acl} {self.value} {self.description}"

	def check_enabled(self):
		if self._enabled.startswith("#"):
			return False
		else:
			return True

	def disable_element(self):
		if self.check_enabled():
			self._enabled = "# acl"
			print(f"[+] Disabled acl [{self.name}]")
			return self.__str__()
		else:
			print(f"[!] acl [{self.name}] already disabled")

	def enable_element(self):
		if not self.check_enabled():
			self._enabled = "acl"
			print(f"[+] Enabled acl [{self.name}]")
			return self.__str__()
		else:
			print(f"[!] acl [{self.name}] already enabled")
