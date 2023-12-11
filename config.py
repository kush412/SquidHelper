import json
import pathlib

PROJECT_ROOT = pathlib.Path(__file__).parent.resolve()

# SETUP FOR LOCAL MACHINE ENV
SSH_KEY_PATH = r"/root/.ssh/id_rsa"
WORKING_DIR = f"{PROJECT_ROOT}/servers"
SETUP_FILE = f"{PROJECT_ROOT}/server_list.json"
SAMPLE_DIR = f"{PROJECT_ROOT}/servers/sample"
CERT_DIR = f"{PROJECT_ROOT}/servers/sample/ssl_cert"
SAMPLE_PEM = f"{CERT_DIR}/squidCA.pem"
SAMPLE_DER = f"{CERT_DIR}/squidCA.cer"
BLACKLIST_DOMAIN_TEMPLATE = f'{SAMPLE_DIR}/blacklist/domain.txt'
BLACKLIST_IP_TEMPLATE = f'{SAMPLE_DIR}/blacklist/ip.txt'
BLACKLIST_EXTENSION_TEMPLATE = f'{SAMPLE_DIR}/blacklist/extension.txt'
WHITELIST_DOMAIN_TEMPLATE = f'{SAMPLE_DIR}/whitelist/domain.txt'
WHITELIST_IP_TEMPLATE = f'{SAMPLE_DIR}/whitelist/ip.txt'
WHITELIST_EXTENSION_TEMPLATE = f'{SAMPLE_DIR}/whitelist/extension.txt'
LIST_ACL_NAME = json.load(open(f"{PROJECT_ROOT}/data/elements_list.json"))
LIST_RULE_NAME = json.load(open(f"{PROJECT_ROOT}/data/access_list.json"))


# SETUP FOR PROXY SERVER ENV
SQUID_PATH = "/etc/squid"
DOMAIN_BLACKLIST = f"{SQUID_PATH}/blacklist/domain.txt"
EXTENSION_BLACKLIST = f"{SQUID_PATH}/blacklist/extension.txt"
IP_BLACKLIST = f"{SQUID_PATH}/blacklist/ip.txt"
DOMAIN_WHITELIST = f"{SQUID_PATH}/whitelist/domain.txt"
EXTENSION_WHITELIST = f"{SQUID_PATH}/whitelist/extension.txt"
IP_WHITELIST = f"{SQUID_PATH}/whitelist/ip.txt"
SQUID_PEM = f"{SQUID_PATH}/ssl_cert/squidCA.pem"
SQUID_DER = f"{SQUID_PATH}/ssl_cert/squidCA.cer"
