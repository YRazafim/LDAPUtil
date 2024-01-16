#!/usr/bin/python3

import argparse, base64, binascii, hashlib, struct, datetime, enum, io

# In case OpenSSL have MD4 disabled
import ctypes
ctypes.CDLL("libssl.so").OSSL_PROVIDER_load(None, b"legacy")
ctypes.CDLL("libssl.so").OSSL_PROVIDER_load(None, b"default")

# LDAP connection libs
from ldap3 import Server, Connection, NTLM, SASL, KERBEROS, ALL, SUBTREE, ALL_ATTRIBUTES, ALL_OPERATIONAL_ATTRIBUTES
from gssapi import Credentials

######################
### LDAP functions ###
######################

def connect_ldap(server_url, username, password, nthash, domain, authentication, ccache):
	use_ssl = server_url.lower().startswith("ldaps://")
	if server_url.lower().startswith("ldap-starttls://"):
		use_start_tls = True
		server_url = "ldap://{}".format(server_url.strip("ldap-starttls://"))
	else:
		use_start_tls = False

	server = Server(server_url, use_ssl = use_ssl, get_info = ALL)

	user_dn = f"{domain}\\{username}"
	if authentication == "NTLM":
		if (password == None and nthash == None):
			print("[-] Password or NT hash required for NTLM authentication")
			exit()
		if (nthash != None):
			password = "0" * 32 + ":" + nthash
		with Connection(server, user_dn, password, authentication = NTLM, auto_bind = True) as conn:
			if use_start_tls:
				conn.start_tls()
			print("[+] Authenticated successfully using NTLM")
			return conn
	elif authentication == "Kerberos":
		creds = Credentials(usage = "initiate", store = {"ccache": ccache})
		with Connection(server, user_dn, authentication = SASL, sasl_mechanism = KERBEROS,
                      sasl_credentials = (None, None, creds), auto_bind = True) as conn:
			if use_start_tls:
				conn.start_tls()
			print("[+] Authenticated successfully using Kerberos")
			return conn
	else:
		print("[-] Invalid authentication method")
		exit()

def search(conn, domain, filter = "(objectClass=*)", attributes = [ALL_ATTRIBUTES, ALL_OPERATIONAL_ATTRIBUTES], controls = None):
	base_dn = ",".join(f"DC={component}" for component in domain.split("."))
	entry_generator = conn.extend.standard.paged_search(search_base = base_dn,
                    search_filter = filter,
                    search_scope = SUBTREE,
                    attributes = attributes,
					controls = controls,
					paged_size = 100,
					generator = True)
	return entry_generator

##################
### objectGUID ###
##################

# https://learn.microsoft.com/en-us/windows/win32/api/guiddef/ns-guiddef-guid
# guid.py from https://github.com/skelsec/winacl
class GUID:
	def __init__(self):
		self.Data1 = None
		self.Data2 = None
		self.Data3 = None
		self.Data4 = None

	def to_bytes(self):
		return self.Data1[::-1] + self.Data2[::-1] + self.Data3[::-1] + self.Data4

	def to_buffer(self, buffer):
		buffer.write(self.to_bytes())

	@staticmethod
	def from_bytes(data):
		return GUID.from_buffer(io.BytesIO(data))

	@staticmethod
	def from_buffer(buffer):
		guid = GUID()
		guid.Data1 = buffer.read(4)[::-1]
		guid.Data2 = buffer.read(2)[::-1]
		guid.Data3 = buffer.read(2)[::-1]
		guid.Data4 = buffer.read(8)
		return guid

	@staticmethod
	def from_string(str):
		guid = GUID()
		guid.Data1 = bytes.fromhex(str.split('-')[0])
		guid.Data2 = bytes.fromhex(str.split('-')[1])
		guid.Data3 = bytes.fromhex(str.split('-')[2])
		guid.Data4 = bytes.fromhex(str.split('-')[3])
		guid.Data4 += bytes.fromhex(str.split('-')[4])
		return guid

	def __str__(self):
		return '-'.join([self.Data1.hex(), self.Data2.hex(),self.Data3.hex(),self.Data4[:2].hex(),self.Data4[2:].hex()])

def parseObjectGUID(guidB64):
	print("-------------------------")
	print("[+] Parsing objectGUID")
	print("-------------------------")

	# Base64 Decode + Binary format to GUID format
	guid = GUID.from_bytes(base64.b64decode(guidB64))

	# Print GUID
	print(f"[+] objectGUID = {guid.__str__()}")

def buildObjectGUID(guidStr):
	print("-------------------------")
	print("[+] Building objectGUID")
	print("-------------------------")

	# Build GUID object
	guid = GUID.from_string(guidStr)

	# Export to bytes
	guidBytes = guid.to_bytes()

	# Base64 encode
	guidB64 = base64.b64encode(guidBytes)

	print(f"[+] objectGUID = {guidB64.decode()}")

#################
### objectSid ###
#################

# sid.py from https://github.com/skelsec/winacl
class DOMAIN_ALIAS_RID(enum.Enum):
	ADMINS = 0x00000220 # A local group used for administration of the domain.
	USERS = 0x00000221 # A local group that represents all users in the domain.
	GUESTS = 0x00000222 # A local group that represents guests of the domain.
	POWER_USERS = 0x00000223 # A local group used to represent a user or set of users who expect to treat a system as if it were their personal computer rather than as a workstation for multiple users.
	ACCOUNT_OPS = 	0x00000224 # A local group that exists only on systems running server operating systems. This local group permits control over nonadministrator accounts.
	SYSTEM_OPS = 0x00000225 # A local group that exists only on systems running server operating systems. This local group performs system administrative functions, not including security functions. It establishes network shares, controls printers, unlocks workstations, and performs other operations.
	PRINT_OPS = 0x00000226 # A local group that exists only on systems running server operating systems. This local group controls printers and print queues.
	BACKUP_OPS = 0x00000227 # A local group used for controlling assignment of file backup-and-restore privileges.
	REPLICATOR = 0x00000228 # A local group responsible for copying security databases from the primary domain controller to the backup domain controllers. These accounts are used only by the system.
	RAS_SERVERS = 0x00000229 # A local group that represents RAS and IAS servers. This group permits access to various attributes of user objects.
	PREW2KCOMPACCESS = 0x0000022A # A local group that exists only on systems running Windows 2000 Server. For more information, see Allowing Anonymous Access.
	REMOTE_DESKTOP_USERS = 0x0000022B # A local group that represents all remote desktop users.
	NETWORK_CONFIGURATION_OPS = 0x0000022C # A local group that represents the network configuration.
	INCOMING_FOREST_TRUST_BUILDERS = 0x0000022D # A local group that represents any forest trust users.
	MONITORING_USERS = 0x0000022E # A local group that represents all users being monitored.
	LOGGING_USERS = 0x0000022F # A local group responsible for logging users.
	AUTHORIZATIONACCESS = 0x00000230 # A local group that represents all authorized access.
	TS_LICENSE_SERVERS = 0x00000231 # A local group that exists only on systems running server operating systems that allow for terminal services and remote access.
	DCOM_USERS = 0x00000232 # A local group that represents users who can use Distributed Component Object Model (DCOM).
	IUSERS = 0X00000238 # A local group that represents Internet users.
	CRYPTO_OPERATORS = 0x00000239 # A local group that represents access to cryptography operators.
	CACHEABLE_PRINCIPALS_GROUP = 0x0000023B # A local group that represents principals that can be cached.
	NON_CACHEABLE_PRINCIPALS_GROUP = 0x0000023C # A local group that represents principals that cannot be cached.
	EVENT_LOG_READERS_GROUP = 0x0000023D # A local group that represents event log readers.
	CERTSVC_DCOM_ACCESS_GROUP = 0x0000023E # The local group of users who can connect to certification authorities using Distributed Component Object Model (DCOM).
	RDS_REMOTE_ACCESS_SERVERS = 0x0000023F  # A local group that represents RDS remote access servers.
	RDS_ENDPOINT_SERVERS = 0x00000240 # A local group that represents endpoint servers.
	RDS_MANAGEMENT_SERVERS = 0x00000241 # A local group that represents management servers.
	HYPER_V_ADMINS = 0x00000242 # A local group that represents hyper-v admins
	ACCESS_CONTROL_ASSISTANCE_OPS = 0x00000243 # A local group that represents access control assistance OPS.
	REMOTE_MANAGEMENT_USERS = 0x00000244 # A local group that represents remote management users.
	DEFAULT_ACCOUNT = 0x00000245 # A local group that represents the default account.
	STORAGE_REPLICA_ADMINS = 0x00000246 # A local group that represents storage replica admins.
	DEVICE_OWNERS = 0x00000247 # A local group that represents can make settings expected for Device Owners.

class DOMAIN_GROUP_RID(enum.Enum):
	ADMINS = 0x00000200 # The domain administrators' group. This account exists only on systems running server operating systems.
	USERS = 0x00000201 # A group that contains all user accounts in a domain. All users are automatically added to this group.
	GUESTS = 0x00000202 # The guest-group account in a domain.
	COMPUTERS = 0x00000203 # The domain computers' group. All computers in the domain are members of this group.
	CONTROLLERS = 0x00000204 # The domain controllers' group. All DCs in the domain are members of this group.
	CERT_ADMINS = 0x00000205 # The certificate publishers' group. Computers running Certificate Services are members of this group.
	ENTERPRISE_READONLY_DOMAIN_CONTROLLERS = 0x000001F2 # The group of enterprise read-only domain controllers.
	SCHEMA_ADMINS = 0x00000206 # The schema administrators' group. Members of this group can modify the Active Directory schema.
	ENTERPRISE_ADMINS = 0x00000207 # The enterprise administrators' group. Members of this group have full access to all domains in the Active Directory forest. Enterprise administrators are responsible for forest-level operations such as adding or removing new domains.
	POLICY_ADMINS = 0x00000208 # The policy administrators' group.
	READONLY_CONTROLLERS = 0x00000209 # The group of read-only domain controllers.
	CLONEABLE_CONTROLLERS = 0x0000020A # The group of cloneable domain controllers.
	CDC_RESERVED = 0x0000020C # The reserved CDC group.
	PROTECTED_USERS = 0x0000020D # 	The protected users group.
	KEY_ADMINS = 0x0000020E # The key admins group.
	ENTERPRISE_KEY_ADMINS = 0x0000020F

class SECURITY_MANDATORY(enum.Enum):
	UNTRUSTED_RID = 0x00000000 # Untrusted.
	LOW_RID = 0x00001000 # Low integrity.
	MEDIUM_RID = 0x00002000 # Medium integrity.
	MEDIUM_PLUS_RID = 0x00002000 + 0x100 # Medium high integrity.
	HIGH_RID = 0x00003000 # High integrity.
	SYSTEM_RID = 0x00004000 # System integrity.
	PROTECTED_PROCESS_RID = 0x00005000

DOMAIN_USER_RID_ADMIN = 0x000001F4
DOMAIN_USER_RID_GUEST = 0x000001F5

SECURITY_LOCAL_SERVICE_RID  = 0x00000013
SECURITY_SERVER_LOGON_RID = 9
SECURITY_NETWORK_SERVICE_RID = 0x00000014

# https://docs.microsoft.com/en-us/windows/win32/secauthz/sid-strings
SDDL_NAME_VAL_MAPS = {
	"AN" : "S-1-5-7", # Anonymous logon. The corresponding RID is SECURITY_ANONYMOUS_LOGON_RID.
	"AO" : 	DOMAIN_ALIAS_RID.ACCOUNT_OPS.value, # Account operators. The corresponding RID is DOMAIN_ALIAS_RID_ACCOUNT_OPS.
	"AU" : 	"S-1-5-11", # Authenticated users. The corresponding RID is SECURITY_AUTHENTICATED_USER_RID.
	"BA" : 	DOMAIN_ALIAS_RID.ADMINS.value, # Built-in administrators. The corresponding RID is DOMAIN_ALIAS_RID_ADMINS.
	"BG" :  DOMAIN_ALIAS_RID.GUESTS.value, # Built-in guests. The corresponding RID is DOMAIN_ALIAS_RID_GUESTS.
	"BO" : 	DOMAIN_ALIAS_RID.BACKUP_OPS.value, # Backup operators. The corresponding RID is DOMAIN_ALIAS_RID_BACKUP_OPS.
	"BU" : 	"S-1-5-32-545", # Built-in users. The corresponding RID is DOMAIN_ALIAS_RID_USERS.
	"CA" :  DOMAIN_GROUP_RID.CERT_ADMINS.value, # Certificate publishers. The corresponding RID is DOMAIN_GROUP_RID_CERT_ADMINS.
	"CD" :  DOMAIN_ALIAS_RID.CERTSVC_DCOM_ACCESS_GROUP.value, # Users who can connect to certification authorities using Distributed Component Object Model (DCOM). The corresponding RID is DOMAIN_ALIAS_RID_CERTSVC_DCOM_ACCESS_GROUP.
	"CG" : 	"S-1-3", # Creator group. The corresponding RID is SECURITY_CREATOR_GROUP_RID.
	"CO" :  "S-1-3-0", # Creator owner. The corresponding RID is SECURITY_CREATOR_OWNER_RID.
	"DA" : 	DOMAIN_GROUP_RID.ADMINS.value, # Domain administrators. The corresponding RID is DOMAIN_GROUP_RID_ADMINS.
	"DC" : 	DOMAIN_GROUP_RID.COMPUTERS.value, # Domain computers. The corresponding RID is DOMAIN_GROUP_RID_COMPUTERS.
	"DD" : 	DOMAIN_GROUP_RID.CONTROLLERS.value, # Domain controllers. The corresponding RID is DOMAIN_GROUP_RID_CONTROLLERS.
	"DG" : 	DOMAIN_GROUP_RID.GUESTS.value, # Domain guests. The corresponding RID is DOMAIN_GROUP_RID_GUESTS.
	"DU" : 	DOMAIN_GROUP_RID.USERS.value, # Domain users. The corresponding RID is DOMAIN_GROUP_RID_USERS.
	"EA" : 	DOMAIN_GROUP_RID.ENTERPRISE_ADMINS.value, # Enterprise administrators. The corresponding RID is DOMAIN_GROUP_RID_ENTERPRISE_ADMINS.
	"ED" : 	SECURITY_SERVER_LOGON_RID, # Enterprise domain controllers. The corresponding RID is SECURITY_SERVER_LOGON_RID.
	"HI" : 	SECURITY_MANDATORY.HIGH_RID.value, # High integrity level. The corresponding RID is SECURITY_MANDATORY_HIGH_RID.
	"IU" : 	"S-1-5-4", # Interactively logged-on user. This is a group identifier added to the token of a process when it was logged on interactively. The corresponding logon type is LOGON32_LOGON_INTERACTIVE. The corresponding RID is SECURITY_INTERACTIVE_RID.
	"LA" : 	DOMAIN_USER_RID_ADMIN, # Local administrator. The corresponding RID is DOMAIN_USER_RID_ADMIN.
	"LG" : 	DOMAIN_USER_RID_GUEST, # Local guest. The corresponding RID is DOMAIN_USER_RID_GUEST.
	"LS" :  SECURITY_LOCAL_SERVICE_RID, # Local service account. The corresponding RID is SECURITY_LOCAL_SERVICE_RID.
	"LW" : 	SECURITY_MANDATORY.LOW_RID.value, # Low integrity level. The corresponding RID is SECURITY_MANDATORY_LOW_RID.
	"ME" : 	SECURITY_MANDATORY.MEDIUM_RID.value, # Medium integrity level. The corresponding RID is SECURITY_MANDATORY_MEDIUM_RID.
	# "MU" :  SDDL_PERFMON_USERS, # Performance Monitor users. TODO ERROR: NO VALUE FOUND FOR THIS!
	"NO" : 	DOMAIN_ALIAS_RID.NETWORK_CONFIGURATION_OPS.value, # Network configuration operators. The corresponding RID is DOMAIN_ALIAS_RID_NETWORK_CONFIGURATION_OPS.
	"NS" : 	SECURITY_NETWORK_SERVICE_RID, # Network service account. The corresponding RID is SECURITY_NETWORK_SERVICE_RID.
	"NU" : 	"S-1-5-2", # Network logon user. This is a group identifier added to the token of a process when it was logged on across a network. The corresponding logon type is LOGON32_LOGON_NETWORK. The corresponding RID is SECURITY_NETWORK_RID.
	"PA" : 	DOMAIN_GROUP_RID.POLICY_ADMINS.value, # Group Policy administrators. The corresponding RID is DOMAIN_GROUP_RID_POLICY_ADMINS.
	"PO" : 	DOMAIN_ALIAS_RID.PRINT_OPS.value, # Printer operators. The corresponding RID is DOMAIN_ALIAS_RID_PRINT_OPS.
	"PS" : 	"S-1-5-10", # Principal self. The corresponding RID is SECURITY_PRINCIPAL_SELF_RID.
	"PU" : 	DOMAIN_ALIAS_RID.POWER_USERS.value, # Power users. The corresponding RID is DOMAIN_ALIAS_RID_POWER_USERS.
	"RC" : 	"S-1-5-12", # Restricted code. This is a restricted token created using the CreateRestrictedToken function. The corresponding RID is SECURITY_RESTRICTED_CODE_RID.
	"RD" : 	DOMAIN_ALIAS_RID.REMOTE_DESKTOP_USERS.value, # Terminal server users. The corresponding RID is DOMAIN_ALIAS_RID_REMOTE_DESKTOP_USERS.
	"RE" : 	DOMAIN_ALIAS_RID.REPLICATOR.value, # Replicator. The corresponding RID is DOMAIN_ALIAS_RID_REPLICATOR.
	"RO" : 	DOMAIN_GROUP_RID.ENTERPRISE_READONLY_DOMAIN_CONTROLLERS.value, # Enterprise Read-only domain controllers. The corresponding RID is DOMAIN_GROUP_RID_ENTERPRISE_READONLY_DOMAIN_CONTROLLERS.
	"RS" :  DOMAIN_ALIAS_RID.RAS_SERVERS.value, # RAS servers group. The corresponding RID is DOMAIN_ALIAS_RID_RAS_SERVERS.
	"RU" :	DOMAIN_ALIAS_RID.PREW2KCOMPACCESS.value, # Alias to grant permissions to accounts that use applications compatible with operating systems previous to Windows 2000. The corresponding RID is DOMAIN_ALIAS_RID_PREW2KCOMPACCESS.
	"SA" : 	DOMAIN_GROUP_RID.SCHEMA_ADMINS.value, # Schema administrators. The corresponding RID is DOMAIN_GROUP_RID_SCHEMA_ADMINS.
	"SI" : 	SECURITY_MANDATORY.SYSTEM_RID.value, # System integrity level. The corresponding RID is SECURITY_MANDATORY_SYSTEM_RID.
	"SO" : 	DOMAIN_ALIAS_RID.SYSTEM_OPS.value, # Server operators. The corresponding RID is DOMAIN_ALIAS_RID_SYSTEM_OPS.
	"SU" : 	"S-1-5-6", # Service logon user. This is a group identifier added to the token of a process when it was logged as a service. The corresponding logon type is LOGON32_LOGON_SERVICE. The corresponding RID is SECURITY_SERVICE_RID.
	"SY" :	"S-1-5-18", # Local system. The corresponding RID is SECURITY_LOCAL_SYSTEM_RID.
	"WD" : 	"S-1-1-0"
}
SDDL_VAL_NAME_MAPS = {v: k for k, v in SDDL_NAME_VAL_MAPS.items()}

# https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/f992ad60-0fe4-4b87-9fed-beb478836861
class SID:
	def __init__(self):
		self.Revision = None
		self.SubAuthorityCount = None
		self.IdentifierAuthority = None
		self.SubAuthority = []

		self.wildcard = None # This is for well-known-sid lookups

	@staticmethod
	def from_string(sid_str, wildcard = False):
		if sid_str[:4] != 'S-1-':
			print(f"[-] {sid_str} is not a SID")
			exit()
		sid = SID()
		sid.wildcard = wildcard
		sid.Revision = 1
		sid_str = sid_str[4:]
		t = sid_str.split('-')[0]
		if t[:2] == '0x':
			sid.IdentifierAuthority = int(t[2:],16)
		else:
			sid.IdentifierAuthority = int(t)

		for p in sid_str.split('-')[1:]:
			try:
				p = int(p)
			except Exception as e:
				if wildcard != True:
					raise e
			sid.SubAuthority.append(p)
		return sid

	@staticmethod
	def from_bytes(data):
		return SID.from_buffer(io.BytesIO(data))

	@staticmethod
	def from_buffer(buff):
		sid = SID()
		sid.Revision = int.from_bytes(buff.read(1), 'little', signed = False)
		sid.SubAuthorityCount = int.from_bytes(buff.read(1), 'little', signed = False)
		sid.IdentifierAuthority = int.from_bytes(buff.read(6), 'big', signed = False)
		for _ in range(sid.SubAuthorityCount):
			sid.SubAuthority.append(int.from_bytes(buff.read(4), 'little', signed = False))
		return sid

	def to_bytes(self):
		t = self.Revision.to_bytes(1, 'little', signed = False)
		t += len(self.SubAuthority).to_bytes(1, 'little', signed = False)
		t += self.IdentifierAuthority.to_bytes(6, 'big', signed = False)
		for i in self.SubAuthority:
			t += i.to_bytes(4, 'little', signed = False)
		return t

	def __str__(self):
		t = 'S-1-'
		if self.IdentifierAuthority < 2**32:
			t += str(self.IdentifierAuthority)
		else:
			t += '0x' + self.IdentifierAuthority.to_bytes(6, 'big').hex().upper().rjust(12, '0')
		for i in self.SubAuthority:
			t += '-' + str(i)
		return t

	'''
	TODO: If we figure out how to properly convert the pretty names to the correct SIDs enable this part
			problem is that pretty names sometimes belong to full SIDs sometimes to RIDs only and there is no way to tell if it belonged to
			a domain-sid or a local sid
		
	for val in SDDL_VAL_NAME_MAPS:
		if isinstance(val, str) is True and val == x:
			return SDDL_VAL_NAME_MAPS[val]
		elif isinstance(val, int) is True and self.SubAuthority[-1] == val:
			return SDDL_VAL_NAME_MAPS[val]
	return x
	'''
	def to_sddl(self):
		x = str(self)
		return x

	@staticmethod
	def from_sddl(sddl, domain_sid = None):
		if len(sddl) > 2:
			return SID.from_string(sddl)
		else:
			if sddl not in SDDL_NAME_VAL_MAPS:
				raise Exception('%s was not found in the well known sid definitions!' % sddl)
			account_sid_val = SDDL_NAME_VAL_MAPS[sddl]
			if isinstance(account_sid_val, str):
				return SID.from_string(account_sid_val)
			else:
				if domain_sid is None:
					raise Exception('Missing domain_sid! Cant convert "%s" to a SID' % sddl)
				return SID.from_string(domain_sid + '-' +str(account_sid_val))

def parseObjectSID(sidB64):
	print("-------------------------")
	print("[+] Parsing objectSid")
	print("-------------------------")

	# Base64 Decode + Binary format to SID format
	sid = SID.from_bytes(base64.b64decode(sidB64))

	# Print SID
	print(f"[+] objectSid = {sid.__str__()}")

def buildObjectSID(sidStr):
	print("-------------------------")
	print("[+] Building objectSid")
	print("-------------------------")

	# Build SID object
	sid = SID.from_string(sidStr)

	# Export to bytes
	sidBytes = sid.to_bytes()

	# Base64 encode
	sidB64 = base64.b64encode(sidBytes)

	print(f"[+] objectSid = {sidB64.decode()}")

###########
### ACE ###
###########

# https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/628ebb1d-c509-4ea0-a10f-77ef97ca4586
class ACEType(enum.Enum):
	ACCESS_ALLOWED_ACE_TYPE = 0x00
	ACCESS_DENIED_ACE_TYPE = 0x01
	SYSTEM_AUDIT_ACE_TYPE = 0x02
	SYSTEM_ALARM_ACE_TYPE = 0x03
	ACCESS_ALLOWED_COMPOUND_ACE_TYPE = 0x04
	ACCESS_ALLOWED_OBJECT_ACE_TYPE = 0x05
	ACCESS_DENIED_OBJECT_ACE_TYPE = 0x06
	SYSTEM_AUDIT_OBJECT_ACE_TYPE = 0x07
	SYSTEM_ALARM_OBJECT_ACE_TYPE = 0x08
	ACCESS_ALLOWED_CALLBACK_ACE_TYPE = 0x09
	ACCESS_DENIED_CALLBACK_ACE_TYPE = 0x0A
	ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE = 0x0B
	ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE = 0x0C
	SYSTEM_AUDIT_CALLBACK_ACE_TYPE = 0x0D
	SYSTEM_ALARM_CALLBACK_ACE_TYPE = 0x0E
	SYSTEM_AUDIT_CALLBACK_OBJECT_ACE_TYPE = 0x0F
	SYSTEM_ALARM_CALLBACK_OBJECT_ACE_TYPE = 0x10 
	SYSTEM_MANDATORY_LABEL_ACE_TYPE = 0x11
	SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE = 0x12
	SYSTEM_SCOPED_POLICY_ID_ACE_TYPE = 0x13
# https://learn.microsoft.com/en-us/windows/win32/secauthz/ace-strings
SDDL_ACE_TYPE_MAPS = {
	"A"  : ACEType.ACCESS_ALLOWED_ACE_TYPE,
	"D"  : ACEType.ACCESS_DENIED_ACE_TYPE,
	"OA" : ACEType.ACCESS_ALLOWED_OBJECT_ACE_TYPE,
	"OD" : ACEType.ACCESS_DENIED_OBJECT_ACE_TYPE,
	"AU" : ACEType.SYSTEM_AUDIT_ACE_TYPE,
	"AL" : ACEType.SYSTEM_ALARM_ACE_TYPE,
	"OU" : ACEType.SYSTEM_AUDIT_OBJECT_ACE_TYPE,
	"OL" : ACEType.SYSTEM_ALARM_OBJECT_ACE_TYPE,
	"ML" : ACEType.SYSTEM_MANDATORY_LABEL_ACE_TYPE, # Windows Server 2003: Not available.
	"XA" : ACEType.ACCESS_ALLOWED_CALLBACK_ACE_TYPE, # Windows Server 2008, Windows Vista and Windows Server 2003: Not available.
	"XD" : ACEType.ACCESS_DENIED_CALLBACK_ACE_TYPE, # Windows Server 2008, Windows Vista and Windows Server 2003: Not available.
	"RA" : ACEType.SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE, # Windows Server 2008 R2, Windows 7, Windows Server 2008, Windows Vista and Windows Server 2003: Not available.
	"SP" : ACEType.SYSTEM_SCOPED_POLICY_ID_ACE_TYPE, # Windows Server 2008 R2, Windows 7, Windows Server 2008, Windows Vista and Windows Server 2003: Not available.
	"XU" : ACEType.SYSTEM_AUDIT_CALLBACK_ACE_TYPE, # Windows Server 2008 R2, Windows 7, Windows Server 2008, Windows Vista and Windows Server 2003: Not available.
	"ZA" : ACEType.ACCESS_ALLOWED_CALLBACK_ACE_TYPE, # Windows Server 2008 R2, Windows 7, Windows Server 2008, Windows Vista and Windows Server 2003: Not available.
	# "TL" : ACEType.SYSTEM_PROCESS_TRUST_LABEL_ACE_TYPE, # Windows Server 2012, Windows 8, Windows Server 2008 R2, Windows 7, Windows Server 2008, Windows Vista and Windows Server 2003: Not available.
	# "FL" : ACEType.SYSTEM_ACCESS_FILTER_ACE_TYPE # Windows Server 2016, Windows 10 Version 1607, Windows 10 Version 1511, Windows 10 Version 1507, Windows Server 2012 R2, Windows 8.1, Windows Server 2012, Windows 8, Windows Server 2008 R2, Windows 7, Windows Server 2008, Windows Vista and Windows Server 2003: Not available.
}
SDDL_ACE_TYPE_MAPS_INV = {v: k for k, v in SDDL_ACE_TYPE_MAPS.items()}
def ACE_TYPE_TO_SDDL(type):
    return SDDL_ACE_TYPE_MAPS_INV[type]
def SDDL_TO_ACE_TYPE(type_str):
    return SDDL_ACE_TYPE_MAPS[type_str]
def SDDL_TO_ACE_TYPE_STR(type_str):
    return SDDL_ACE_TYPE_MAPS[type_str].name

# https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/628ebb1d-c509-4ea0-a10f-77ef97ca4586
class ACEFlags(enum.IntFlag):
	CONTAINER_INHERIT_ACE = 0x02
	FAILED_ACCESS_ACE_FLAG = 0x80
	INHERIT_ONLY_ACE = 0x08
	INHERITED_ACE = 0x10
	NO_PROPAGATE_INHERIT_ACE = 0x04
	OBJECT_INHERIT_ACE = 0x01
	SUCCESSFUL_ACCESS_ACE_FLAG = 0x40
# https://learn.microsoft.com/en-us/windows/win32/secauthz/ace-strings
SDDL_ACE_FLAGS_MAPS = {
	"CI": ACEFlags.CONTAINER_INHERIT_ACE,
	"OI": ACEFlags.OBJECT_INHERIT_ACE,
	"NP": ACEFlags.NO_PROPAGATE_INHERIT_ACE,
	"IO": ACEFlags.INHERIT_ONLY_ACE,
	"ID": ACEFlags.INHERITED_ACE,
	"SA": ACEFlags.SUCCESSFUL_ACCESS_ACE_FLAG,
	"FA": ACEFlags.FAILED_ACCESS_ACE_FLAG,
	# "TP": ACEFlags.TRUST_PROTECTED_FILTER_ACE_FLAG, # Windows Server 2016, Windows 10 Version 1607, Windows 10 Version 1511, Windows 10 Version 1507, Windows Server 2012 R2, Windows 8.1, Windows Server 2012, Windows 8, Windows Server 2008 R2, Windows 7, Windows Server 2008, Windows Vista and Windows Server 2003: Not available.
	# "CR": ACEFlags.CRITICAL_ACE_FLAG # Windows Server Version 1803, Windows 10 Version 1803, Windows Server Version 1709, Windows 10 Version 1709, Windows 10 Version 1703, Windows Server 2016, Windows 10 Version 1607, Windows 10 Version 1511, Windows 10 Version 1507, Windows Server 2012 R2, Windows 8.1, Windows Server 2012, Windows 8, Windows Server 2008 R2, Windows 7, Windows Server 2008, Windows Vista and Windows Server 2003: Not available.
}
SDDL_ACE_FLAGS_MAPS_INV = {v: k for k, v in SDDL_ACE_FLAGS_MAPS.items()}
def ACE_FLAGS_TO_SDDL(flags):
	return "".join([SDDL_ACE_FLAGS_MAPS_INV[k] for k in SDDL_ACE_FLAGS_MAPS_INV if k & flags])
def SDDL_TO_ACE_FLAGS(flags_str):
    flags = 0
    for i in range(0, len(flags_str), 2):
        flags |= SDDL_ACE_FLAGS_MAPS[flags_str[i:i+2]]
    return flags
def SDDL_TO_ACE_FLAGS_STR(flags_str):
    if flags_str == '':
        return "<None>"
    else:
    	return "|".join([SDDL_ACE_FLAGS_MAPS[k].name for k in SDDL_ACE_FLAGS_MAPS if k in flags_str])
    
# General access rights
# 	https://learn.microsoft.com/en-us/windows/win32/secauthz/access-rights-and-access-masks
#	https://learn.microsoft.com/en-us/windows/win32/secauthz/ace-strings
# BUT we are only interested by Active Directory Domain Services (ADDS) objects access rights for LDAP
# 	https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/990fb975-ab31-4bc1-8b75-5da132cd4584
#	https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=dotnet-plat-ext-6.0
#	https://learn.microsoft.com/en-us/windows/win32/adschema/extended-rights
class ACEAccessRights(enum.IntFlag):
	CREATE_CHILD = 0x00000001 # The ObjectType GUID identifies a type of child object. The ACE controls the trustee's right to create this type of child object.
	DELETE_CHILD = 0x00000002 # The ObjectType GUID identifies a type of child object. The ACE controls the trustee's right to delete this type of child object.
	LIST_CHILDREN = 0x00000004 # Enumerate a DS object.
	SELF = 0x00000008 # The ObjectType GUID identifies a validated write.
	READ_PROPERTY = 0x00000010 # The ObjectType GUID identifies a property set or property of the object. The ACE controls the trustee's right to read the property or property set.
	WRITE_PROPERTY = 0x00000020 # The ObjectType GUID identifies a property set or property of the object. The ACE controls the trustee's right to write the property or property set.
	DELETE_TREE = 0x00000040 # The right to delete all children of this object, regardless of the permissions of the children.
	LIST_OBJECT = 0x00000080 # The right to list a particular object. For more information about this right, see the see the Controlling Object Visibility article.
	CONTROL_ACCESS = 0x00000100 # The ObjectType GUID identifies an extended access right.
	DELETE = 0x00010000 # The right to delete the object.
	READ_CONTROL = 0x00020000 # The right to read data from the security descriptor of the object, not including the data in the SACL.
	GENERIC_EXECUTE = 0x00020004 # The right to read permissions on, and list the contents of, a container object.
	GENERIC_WRITE = 0x00020028 # The right to read permissions on this object, write all the properties on this object, and perform all validated writes to this object.
	GENERIC_READ = 0x00020094 # The right to read permissions on this object, read all the properties on this object, list this object name when the parent container is listed, and list the contents of this object if it is a container.
	WRITE_DACL = 0x00040000 # The right to modify the DACL in the object security descriptor.
	WRITE_OWNER = 0x00080000 # The right to assume ownership of the object. The user must be an object trustee. The user cannot transfer the ownership to other users.
	GENERIC_ALL = 0x000f01ff # The right to create or delete children, delete a subtree, read and write properties, examine children and the object itself, add and remove the object from the directory, and read or write with an extended right.
	SYNCHRONIZE = 0x00100000 # The right to use the object for synchronization. This right enables a thread to wait until that object is in the signaled state.
	ACCESS_SYSTEM_SECURITY 	= 0x01000000 # The right to get or set the SACL in the object security descriptor.
SDDL_ACE_ACCESS_RIGHTS_MAPS = {
	"CC": ACEAccessRights.CREATE_CHILD,
	"DC": ACEAccessRights.DELETE_CHILD,
	"LC": ACEAccessRights.LIST_CHILDREN,
	"VW": ACEAccessRights.SELF,
	"RP": ACEAccessRights.READ_PROPERTY,
	"WP": ACEAccessRights.WRITE_PROPERTY,
	"DT": ACEAccessRights.DELETE_TREE,
	"LO": ACEAccessRights.LIST_OBJECT,
	"CR": ACEAccessRights.CONTROL_ACCESS,
	"DE": ACEAccessRights.DELETE,
	"RC": ACEAccessRights.READ_CONTROL,
	"GX": ACEAccessRights.GENERIC_EXECUTE, # GX = (RC | LC)
	"GW": ACEAccessRights.GENERIC_WRITE, # GW = (RC | WP | VW)
	"GR": ACEAccessRights.GENERIC_READ, # GR = (RC | LC | RP | LO)
	"WD": ACEAccessRights.WRITE_DACL,
	"WO": ACEAccessRights.WRITE_OWNER,
	"GA": ACEAccessRights.GENERIC_ALL, # GA = (DE | RC | WD | WO | CC | DC | DT | RP | WP | LC | LO | CR | VW)
	"SY": ACEAccessRights.SYNCHRONIZE, # Could not find a mapped symbol from docs -> Guessed "SY"
	"AS": ACEAccessRights.ACCESS_SYSTEM_SECURITY # https://learn.microsoft.com/en-us/windows/win32/secauthz/access-mask-format
}
SDDL_ACE_ACCESS_RIGHTS_MAPS_INV = {v: k for k, v in SDDL_ACE_ACCESS_RIGHTS_MAPS.items()}
def ACE_ACCESS_RIGHTS_TO_SDDL(rights):
    return "".join([SDDL_ACE_ACCESS_RIGHTS_MAPS_INV[k] for k in SDDL_ACE_ACCESS_RIGHTS_MAPS_INV if k & rights])
def SDDL_TO_ACE_ACCESS_RIGHTS(rights_str):
	try:
		# Access rights are in hexadecimal string
		mask = int(rights_str, 16)
	except ValueError as e:
		# Access rights as strings
		mask = 0
		for i in range(0, len(rights_str), 2):
			mask |= SDDL_ACE_ACCESS_RIGHTS_MAPS[rights_str[i:i+2]]
	return mask
def SDDL_TO_ACE_ACCESS_RIGHTS_STR(rights_str):
    if rights_str == '':
        return "<None>"
    else:
    	return "|".join([SDDL_ACE_ACCESS_RIGHTS_MAPS[k].name for k in SDDL_ACE_ACCESS_RIGHTS_MAPS if k in rights_str])
# https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/1522b774-6464-41a3-87a5-1e5633c3fbbb
SDDL_ACE_CONTROL_ACCESS_RIGHTS_MAPS = {
	"ee914b82-0a98-11d1-adbb-00c04fd8d5cd": "Abandon-Replication",
	"440820ad-65b4-11d1-a3da-0000f875ae0d": "Add-GUID",
	"1abd7cf8-0a99-11d1-adbb-00c04fd8d5cd": "Allocate-Rids",
	"68b1d179-0d15-4d4f-ab71-46152e79a7bc": "Allowed-To-Authenticate",
	"edacfd8f-ffb3-11d1-b41d-00a0c968f939": "Apply-Group-Policy",
	"0e10c968-78fb-11d2-90d4-00c04f79dc55": "Certificate-Enrollment",
	"a05b8cc2-17bc-4802-a710-e7c15ab866a2": "Certificate-AutoEnrollment",
	"014bf69c-7b3b-11d1-85f6-08002be74fab": "Change-Domain-Master",
	"cc17b1fb-33d9-11d2-97d4-00c04fd8d5cd": "Change-Infrastructure-Master",
	"bae50096-4752-11d1-9052-00c04fc2d4cf": "Change-PDC",
	"d58d5f36-0a98-11d1-adbb-00c04fd8d5cd": "Change-Rid-Master",
	"e12b56b6-0a95-11d1-adbb-00c04fd8d5cd": "Change-Schema-Master",
	"e2a36dc9-ae17-47c3-b58b-be34c55ba633": "Create-Inbound-Forest-Trust",
	"fec364e0-0a98-11d1-adbb-00c04fd8d5cd": "Do-Garbage-Collection",
	"ab721a52-1e2f-11d0-9819-00aa0040529b": "Domain-Administer-Server",
	"69ae6200-7f46-11d2-b9ad-00c04f79f805": "DS-Check-Stale-Phantoms",
	"2f16c4a5-b98e-432c-952a-cb388ba33f2e": "DS-Execute-Intentions-Script",
	"9923a32a-3607-11d2-b9be-0000f87a36b2": "DS-Install-Replica",
	"4ecc03fe-ffc0-4947-b630-eb672a8a9dbc": "DS-Query-Self-Quota",
	"1131f6aa-9c07-11d1-f79f-00c04fc2dcd2": "DS-Replication-Get-Changes",
	"1131f6ad-9c07-11d1-f79f-00c04fc2dcd2": "DS-Replication-Get-Changes-All",
	"89e95b76-444d-4c62-991a-0facbeda640c": "DS-Replication-Get-Changes-In-Filtered-Set",
	"1131f6ac-9c07-11d1-f79f-00c04fc2dcd2": "DS-Replication-Manage-Topology",
	"f98340fb-7c5b-4cdb-a00b-2ebdfa115a96": "DS-Replication-Monitor-Topology",
	"1131f6ab-9c07-11d1-f79f-00c04fc2dcd2": "DS-Replication-Synchronize",
	"05c74c5e-4deb-43b4-bd9f-86664c2a7fd5": "Enable-Per-User-Reversibly-Encrypted-Password",
	"b7b1b3de-ab09-4242-9e30-9980e5d322f7": "Generate-RSoP-Logging",
	"b7b1b3dd-ab09-4242-9e30-9980e5d322f7": "Generate-RSoP-Planning",
	"7c0e2a7c-a419-48e4-a995-10180aad54dd": "Manage-Optional-Features",
	"ba33815a-4f93-4c76-87f3-57574bff8109": "Migrate-SID-History",
	"b4e60130-df3f-11d1-9c86-006008764d0e": "msmq-Open-Connector",
	"06bd3201-df3e-11d1-9c86-006008764d0e": "msmq-Peek",
	"4b6e08c3-df3c-11d1-9c86-006008764d0e": "msmq-Peek-computer-Journal",
	"4b6e08c1-df3c-11d1-9c86-006008764d0e": "msmq-Peek-Dead-Letter",
	"06bd3200-df3e-11d1-9c86-006008764d0e": "msmq-Receive",
	"4b6e08c2-df3c-11d1-9c86-006008764d0e": "msmq-Receive-computer-Journal",
	"4b6e08c0-df3c-11d1-9c86-006008764d0e": "msmq-Receive-Dead-Letter",
	"06bd3203-df3e-11d1-9c86-006008764d0e": "msmq-Receive-journal",
	"06bd3202-df3e-11d1-9c86-006008764d0e": "msmq-Send",
	"a1990816-4298-11d1-ade2-00c04fd8d5cd": "Open-Address-Book",
	"1131f6ae-9c07-11d1-f79f-00c04fc2dcd2": "Read-Only-Replication-Secret-Synchronization",
	"45ec5156-db7e-47bb-b53f-dbeb2d03c40f": "Reanimate-Tombstones",
	"0bc1554e-0a99-11d1-adbb-00c04fd8d5cd": "Recalculate-Hierarchy",
	"62dd28a8-7f46-11d2-b9ad-00c04f79f805": "Recalculate-Security-Inheritance",
	"ab721a56-1e2f-11d0-9819-00aa0040529b": "Receive-As",
	"9432c620-033c-4db7-8b58-14ef6d0bf477": "Refresh-Group-Cache",
	"1a60ea8d-58a6-4b20-bcdc-fb71eb8a9ff8": "Reload-SSL-Certificate",
	"7726b9d5-a4b4-4288-a6b2-dce952e80a7f": "Run-Protect_Admin_Groups-Task",
	"91d67418-0135-4acc-8d79-c08e857cfbec": "SAM-Enumerate-Entire-Domain",
	"ab721a54-1e2f-11d0-9819-00aa0040529b": "Send-As",
	"ab721a55-1e2f-11d0-9819-00aa0040529b": "Send-To",
	"ccc2dc7d-a6ad-4a7a-8846-c04e3cc53501": "Unexpire-Password",
	"280f369c-67c7-438e-ae98-1d46f3c6f541": "Update-Password-Not-Required-Bit",
	"be2bb760-7f46-11d2-b9ad-00c04f79f805": "Update-Schema-Cache",
	"ab721a53-1e2f-11d0-9819-00aa0040529b": "User-Change-Password",
	"00299570-246d-11d0-a768-00aa006e0529": "User-Force-Change-Password",
	"3e0f7e18-2c7a-4c10-ba82-4d926db99a3e": "DS-Clone-Domain-Controller",
	"084c93a2-620d-4879-a836-f0ae47de0e89": "DS-Read-Partition-Secrets",
	"94825a8d-b171-4116-8146-1e34d8f54401": "DS-Write-Partition-Secrets",
	"4125c71f-7fac-4ff0-bcb7-f09a41325286": "DS-Set-Owner",
	"88a9933e-e5c8-4f2a-9dd7-2527416b8092": "DS-Bypass-Quota",
	"9b026da6-0d3c-465c-8bee-5199d7165cba": "DS-Validated-Write-Computer"
}
# https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/177c0db5-fa12-4c31-b75a-473425ce9cca
SDDL_ACE_PROPERTY_SETS_MAPS = {
	"72e39547-7b18-11d1-adef-00c04fd8d5cd": "DNS Host Name Attributes",
	"b8119fd0-04f6-4762-ab7a-4986c76b3f9a": "Other Domain Parameters (for use by SAM)",
	"c7407360-20bf-11d0-a768-00aa006e0529": "Domain Password & Lockout Policies",
	"e45795b2-9455-11d1-aebd-0000f80367c1": "Phone and Mail Options",
	"59ba2f42-79a2-11d0-9020-00c04fc2d3cf": "General Information",
	"bc0ac240-79a9-11d0-9020-00c04fc2d4cf": "Group Membership",
	"ffa6f046-ca4b-4feb-b40d-04dfee722543": "MS-TS-GatewayAccess",
	"77b5b886-944a-11d1-aebd-0000f80367c1": "Personal Information",
	"91e647de-d96f-4b70-9557-d63ff4f3ccd8": "Private Information",
	"e48d0154-bcf8-11d1-8702-00c04fb96050": "Public Information",
	"037088f8-0ae1-11d2-b422-00a0c968f939": "Remote Access Information",
	"5805bc62-bdc9-4428-a5e2-856a0f4c185e": "Terminal Server License Server",
	"4c164200-20c0-11d0-a768-00aa006e0529": "Account Restrictions",
	"5f202010-79a5-11d0-9020-00c04fc2d4cf": "Logon Information",
	"e45795b3-9455-11d1-aebd-0000f80367c1": "Web Information"
}
# https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/20504d60-43ec-458f-bc7a-754eb64446df
SDDL_ACE_VALIDATED_WRITES_MAPS = {
	"bf9679c0-0de6-11d0-a285-00aa003049e2": "Self-Membership",
	"72e39547-7b18-11d1-adef-00c04fd8d5cd": "Validated-DNS-Host-Name",
	"80863791-dbe9-4eb8-837e-7f0ab55d9ac7": "Validated-MS-DS-Additional-DNS-Host-Name",
	"d31a8757-2447-4545-8081-3bb610cacbf2": "Validated-MS-DS-Behavior-Version",
	"f3a64788-5306-11d1-a9c5-0000f80367c1": "Validated-SPN"
}
def SDDL_TO_ACE_OBJECT_GUID_STR(guid_str):
	if guid_str == '':
		return "<None>"
	else:
		if guid_str in SDDL_ACE_CONTROL_ACCESS_RIGHTS_MAPS:
			object_guid = SDDL_ACE_CONTROL_ACCESS_RIGHTS_MAPS[guid_str]
		elif guid_str in SDDL_ACE_PROPERTY_SETS_MAPS:
			object_guid = SDDL_ACE_PROPERTY_SETS_MAPS[guid_str]
		elif guid_str in SDDL_ACE_VALIDATED_WRITES_MAPS:
			object_guid = SDDL_ACE_VALIDATED_WRITES_MAPS[guid_str]
		else:
			object_guid = guid_str
		return object_guid

# https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/628ebb1d-c509-4ea0-a10f-77ef97ca4586
class ACEHeader:
	def __init__(self):
		self.AceType = None
		self.AceFlags = None
		self.AceSize = None

	def to_buffer(self, buff):
		buff.write(self.AceType.value.to_bytes(1, 'little', signed = False))
		buff.write(self.AceFlags.to_bytes(1, 'little', signed = False))
		buff.write(self.AceSize.to_bytes(2, 'little', signed = False))
		
	@staticmethod
	def from_bytes(data):
		return ACEHeader.from_buffer(io.BytesIO(data))
	
	@staticmethod
	def from_buffer(buff):
		hdr = ACEHeader()
		hdr.AceType = ACEType(int.from_bytes(buff.read(1), 'little', signed = False))
		hdr.AceFlags = ACEFlags(int.from_bytes(buff.read(1), 'little', signed = False))
		hdr.AceSize = int.from_bytes(buff.read(2), 'little', signed = False)
		return hdr
		
	@staticmethod
	def pre_parse(buff):
		pos = buff.tell()
		hdr = ACEHeader()
		hdr.AceType = ACEType(int.from_bytes(buff.read(1), 'little', signed = False))
		hdr.AceFlags = ACEFlags(int.from_bytes(buff.read(1), 'little', signed = False))
		hdr.AceSize = int.from_bytes(buff.read(2), 'little', signed = False)
		buff.seek(pos,0)
		return hdr

# https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/c79a383c-2b3f-4655-abe7-dcbb7ce0cfbe
class ACE_OBJECT_PRESENCE(enum.IntFlag):
	NONE = 0x00000000 # Neither ObjectType nor InheritedObjectType are valid.
	ACE_OBJECT_TYPE_PRESENT = 0x00000001 # ObjectType is valid.
	ACE_INHERITED_OBJECT_TYPE_PRESENT = 0x00000002 # InheritedObjectType is valid. If this value is not specified, all types of child objects can inherit the ACE.

# https://learn.microsoft.com/en-us/windows/win32/secauthz/ace-strings
class ACE:
	def __init__(self):
		pass

	@staticmethod
	def from_bytes(data, sd_object_type = None):
		return ACE.from_buffer(io.BytesIO(data), sd_object_type)

	@staticmethod
	def from_buffer(buff, sd_object_type = None):
		hdr = ACEHeader.pre_parse(buff)
		obj = ACEType2ACE.get(hdr.AceType)
		if not obj:
			raise Exception('[-] ACE type %s not implemented!' % hdr.AceType)
		return obj.from_buffer(io.BytesIO(buff.read(hdr.AceSize)), sd_object_type)

	def to_buffer(self, buff):
		pass

	def to_bytes(self):
		buff = io.BytesIO()
		self.to_buffer(buff)
		buff.seek(0)
		return buff.read()

	def to_sddl(self, sd_object_type = None):
		pass
	
	@staticmethod
	def from_sddl(sddl:str, object_type = None, domain_sid = None):

		if sddl.startswith('('):
			sddl = sddl[1:]
		if sddl.endswith(')'):
			sddl = sddl[:-1]
		
		ace_type, ace_flags, rights, object_guid, inherit_object_guid, account_sid = sddl.split(';')

		# ACE Type
		ace_type = SDDL_TO_ACE_TYPE(ace_type)
		ace = ACEType2ACE[ace_type]()
  
		# ACE Flags
		flags = SDDL_TO_ACE_FLAGS(ace_flags)
		ace.AceFlags = ACEFlags(flags)
  
		# ACE Access Rights
		mask = SDDL_TO_ACE_ACCESS_RIGHTS(rights)
		ace.Mask = mask
  
		# ACE Object Type and Inherited Object Type
		ace.sd_object_type = object_type
		ace.Flags = 0
		if object_guid != '':
			ace.Flags |= ACE_OBJECT_PRESENCE.ACE_OBJECT_TYPE_PRESENT
			ace.ObjectType = GUID.from_string(object_guid)
		if inherit_object_guid != '':
			ace.Flags |= ACE_OBJECT_PRESENCE.ACE_INHERITED_OBJECT_TYPE_PRESENT
			ace.InheritedObjectType = GUID.from_string(inherit_object_guid)
   
		# ACE SID
		ace.Sid = SID.from_sddl(account_sid, domain_sid = domain_sid)

		return ace

	@staticmethod
	def add_padding(x):
		if (4 + len(x)) % 4 != 0:
			x += b'\x00' * ((4 + len(x)) % 4)
		return x

### ACE Types ###
# https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/628ebb1d-c509-4ea0-a10f-77ef97ca4586

class SE_OBJECT_TYPE(enum.Enum):
	SE_UNKNOWN_OBJECT_TYPE = 0 # Unknown object type.
	SE_FILE_OBJECT = 1 # Indicates a file or directory.
	SE_SERVICE = 2 # Indicates a Windows service
	SE_PRINTER = 3 # Indicates a printer.
	SE_REGISTRY_KEY = 4 # Indicates a registry key.
	SE_LMSHARE = 5 # Indicates a network share.
	SE_KERNEL_OBJECT = 6 # Indicates a local 
	SE_WINDOW_OBJECT = 7 # Indicates a window station or desktop object on the local computer
	SE_DS_OBJECT = 8 # Indicates a directory service object or a property set or property of a directory service object. 
	SE_DS_OBJECT_ALL = 9 # Indicates a directory service object and all of its property sets and properties.
	SE_PROVIDER_DEFINED_OBJECT = 10 # Indicates a provider-defined object.
	SE_WMIGUID_OBJECT = 11 # Indicates a WMI object.
	SE_REGISTRY_WOW64_32KEY = 12 # Indicates an object for a registry entry under WOW64.
	SE_REGISTRY_WOW64_64KEY = 13 # Indicates an object for a registry entry under WOW64.

class ACCESS_ALLOWED_ACE(ACE):
	def __init__(self):
		self.AceType = ACEType.ACCESS_ALLOWED_ACE_TYPE
		self.AceFlags = None
		self.AceSize = 0
		self.Mask = None
		self.Sid = None
		self.sd_object_type = None
		
	@staticmethod
	def from_buffer(buff, sd_object_type = None):
		ace = ACCESS_ALLOWED_ACE()
		ace.sd_object_type = SE_OBJECT_TYPE(sd_object_type) if sd_object_type else None
		ace.AceType = ACEType(int.from_bytes(buff.read(1), 'little', signed = False))
		ace.AceFlags = ACEFlags(int.from_bytes(buff.read(1), 'little', signed = False))
		ace.AceSize = int.from_bytes(buff.read(2), 'little', signed = False)
		ace.Mask = int.from_bytes(buff.read(4), 'little', signed = False)
		ace.Sid = SID.from_buffer(buff)
		return ace

	def to_buffer(self, buff):
		t = self.Mask.to_bytes(4, 'little', signed = False)
		t += self.Sid.to_bytes()
		t = ACE.add_padding(t)
		self.AceSize = 4 + len(t)
		buff.write(self.AceType.value.to_bytes(1, 'little', signed = False))
		buff.write(self.AceFlags.to_bytes(1, 'little', signed = False))
		buff.write(self.AceSize.to_bytes(2, 'little', signed = False))
		buff.write(t)

	def to_sddl(self, sd_object_type = None):
		# ace_type;ace_flags;rights;object_guid;inherit_object_guid;account_sid;(resource_attribute)
		return '(%s;%s;%s;%s;%s;%s)' % ( 
			ACE_TYPE_TO_SDDL(self.AceType), 
			ACE_FLAGS_TO_SDDL(self.AceFlags), 
			ACE_ACCESS_RIGHTS_TO_SDDL(self.Mask),
			'',
			'', 
			self.Sid.to_sddl()  
		)
		
class ACCESS_DENIED_ACE(ACE):
	def __init__(self):
		self.AceType = ACEType.ACCESS_DENIED_ACE_TYPE
		self.AceFlags = None
		self.AceSize = None
		self.Mask = None
		self.Sid = None

		self.sd_object_type = None
		
	@staticmethod
	def from_buffer(buff, sd_object_type):
		ace = ACCESS_DENIED_ACE()
		ace.sd_object_type = sd_object_type
		ace.AceType = ACEType(int.from_bytes(buff.read(1), 'little', signed = False))
		ace.AceFlags = ACEFlags(int.from_bytes(buff.read(1), 'little', signed = False))
		ace.AceSize = int.from_bytes(buff.read(2), 'little', signed = False)
		ace.Mask = int.from_bytes(buff.read(4), 'little', signed = False)
		ace.Sid = SID.from_buffer(buff)
		return ace
	
	def to_buffer(self, buff):
		t = self.Mask.to_bytes(4, 'little', signed = False)
		t += self.Sid.to_bytes()
		t = ACE.add_padding(t)
		self.AceSize = 4 + len(t)
		buff.write(self.AceType.value.to_bytes(1, 'little', signed = False))
		buff.write(self.AceFlags.to_bytes(1, 'little', signed = False))
		buff.write(self.AceSize.to_bytes(2, 'little', signed = False))
		buff.write(t)
	
	def to_sddl(self, sd_object_type = None):
		# ace_type;ace_flags;rights;object_guid;inherit_object_guid;account_sid;(resource_attribute)
		return '(%s;%s;%s;%s;%s;%s)' % ( 
			ACE_TYPE_TO_SDDL(self.AceType), 
			ACE_FLAGS_TO_SDDL(self.AceFlags), 
			ACE_ACCESS_RIGHTS_TO_SDDL(self.Mask),
			'',
			'', 
			self.Sid.to_sddl()  
		)
		
class SYSTEM_AUDIT_ACE(ACE):
	def __init__(self):
		self.AceType = ACEType.SYSTEM_AUDIT_ACE_TYPE
		self.AceFlags = None
		self.AceSize = None
		self.Mask = None
		self.Sid = None

		self.sd_object_type = None
		
	@staticmethod
	def from_buffer(buff, sd_object_type):
		ace = SYSTEM_AUDIT_ACE()
		ace.sd_object_type = sd_object_type
		ace.AceType = ACEType(int.from_bytes(buff.read(1), 'little', signed = False))
		ace.AceFlags = ACEFlags(int.from_bytes(buff.read(1), 'little', signed = False))
		ace.AceSize = int.from_bytes(buff.read(2), 'little', signed = False)
		ace.Mask = int.from_bytes(buff.read(4), 'little', signed = False)
		ace.Sid = SID.from_buffer(buff)
		return ace

	def to_buffer(self, buff):
		t = self.Mask.to_bytes(4, 'little', signed = False)
		t += self.Sid.to_bytes()
		t = ACE.add_padding(t)
		self.AceSize = 4 + len(t)
		buff.write(self.AceType.value.to_bytes(1, 'little', signed = False))
		buff.write(self.AceFlags.to_bytes(1, 'little', signed = False))
		buff.write(self.AceSize.to_bytes(2, 'little', signed = False))
		buff.write(t)
	

	def to_sddl(self, sd_object_type = None):
		# ace_type;ace_flags;rights;object_guid;inherit_object_guid;account_sid;(resource_attribute)
		return '(%s;%s;%s;%s;%s;%s)' % ( 
			ACE_TYPE_TO_SDDL(self.AceType), 
			ACE_FLAGS_TO_SDDL(self.AceFlags), 
			ACE_ACCESS_RIGHTS_TO_SDDL(self.Mask),
			'',
			'', 
			self.Sid.to_sddl()  
		)
		
class SYSTEM_ALARM_ACE(ACE):
	def __init__(self):
		self.AceType = ACEType.SYSTEM_ALARM_ACE_TYPE
		self.AceFlags = None
		self.AceSize = None
		self.Mask = None
		self.Sid = None

		self.sd_object_type = None
		
	@staticmethod
	def from_buffer(buff, sd_object_type):
		ace = SYSTEM_ALARM_ACE()
		ace.sd_object_type = sd_object_type
		ace.AceType = ACEType(int.from_bytes(buff.read(1), 'little', signed = False))
		ace.AceFlags = ACEFlags(int.from_bytes(buff.read(1), 'little', signed = False))
		ace.AceSize = int.from_bytes(buff.read(2), 'little', signed = False)
		ace.Mask = int.from_bytes(buff.read(4), 'little', signed = False)
		ace.Sid = SID.from_buffer(buff)
		return ace
	
	def to_buffer(self, buff):
		t = self.Mask.to_bytes(4, 'little', signed = False)
		t += self.Sid.to_bytes()
		t = ACE.add_padding(t)
		self.AceSize = 4 + len(t)
		buff.write(self.AceType.value.to_bytes(1, 'little', signed = False))
		buff.write(self.AceFlags.to_bytes(1, 'little', signed = False))
		buff.write(self.AceSize.to_bytes(2, 'little', signed = False))
		buff.write(t)

	def to_sddl(self, sd_object_type = None):
		# ace_type;ace_flags;rights;object_guid;inherit_object_guid;account_sid;(resource_attribute)
		return '(%s;%s;%s;%s;%s;%s)' % ( 
			ACE_TYPE_TO_SDDL(self.AceType), 
			ACE_FLAGS_TO_SDDL(self.AceFlags), 
			ACE_ACCESS_RIGHTS_TO_SDDL(self.Mask),
			'',
			'', 
			self.Sid.to_sddl()  
		)

class ACCESS_ALLOWED_OBJECT_ACE:
	def __init__(self):
		self.AceType = ACEType.ACCESS_ALLOWED_OBJECT_ACE_TYPE
		self.AceFlags = None
		self.AceSize = None
		self.Mask = None
		self.Flags = None
		self.ObjectType = None
		self.InheritedObjectType = None
		self.Sid = None

		self.sd_object_type = None
		
	@staticmethod
	def from_buffer(buff, sd_object_type):
		ace = ACCESS_ALLOWED_OBJECT_ACE()
		ace.sd_object_type = sd_object_type
		ace.AceType = ACEType(int.from_bytes(buff.read(1), 'little', signed = False))
		ace.AceFlags = ACEFlags(int.from_bytes(buff.read(1), 'little', signed = False))
		ace.AceSize = int.from_bytes(buff.read(2), 'little', signed = False)
		ace.Mask = int.from_bytes(buff.read(4), 'little', signed = False)
		ace.Flags = ACE_OBJECT_PRESENCE(int.from_bytes(buff.read(4), 'little', signed = False))
		if ace.Flags & ACE_OBJECT_PRESENCE.ACE_OBJECT_TYPE_PRESENT:
			ace.ObjectType = GUID.from_buffer(buff)
		if ace.Flags & ACE_OBJECT_PRESENCE.ACE_INHERITED_OBJECT_TYPE_PRESENT:
			ace.InheritedObjectType = GUID.from_buffer(buff)
		ace.Sid = SID.from_buffer(buff)
		return ace

	def to_buffer(self, buff):
		if self.ObjectType is not None:
			if self.Flags is None:
				self.Flags = 0
			self.Flags |= ACE_OBJECT_PRESENCE.ACE_OBJECT_TYPE_PRESENT
		if self.InheritedObjectType is not None:
			if self.Flags is None:
				self.Flags = 0
			self.Flags |= ACE_OBJECT_PRESENCE.ACE_INHERITED_OBJECT_TYPE_PRESENT

		t = self.Mask.to_bytes(4, 'little', signed = False)
		t += self.Flags.to_bytes(4, 'little', signed = False)
		if self.Flags & ACE_OBJECT_PRESENCE.ACE_OBJECT_TYPE_PRESENT:
			t += self.ObjectType.to_bytes()
		if self.Flags & ACE_OBJECT_PRESENCE.ACE_INHERITED_OBJECT_TYPE_PRESENT:
			t += self.InheritedObjectType.to_bytes()
		
		t += self.Sid.to_bytes()
		t = ACE.add_padding(t)
		self.AceSize = 4 + len(t)
		buff.write(self.AceType.value.to_bytes(1, 'little', signed = False))
		buff.write(self.AceFlags.to_bytes(1, 'little', signed = False))
		buff.write(self.AceSize.to_bytes(2, 'little', signed = False))
		buff.write(t)

	def to_sddl(self, sd_object_type = None):
		# ace_type;ace_flags;rights;object_guid;inherit_object_guid;account_sid;(resource_attribute)
		return '(%s;%s;%s;%s;%s;%s)' % ( 
			ACE_TYPE_TO_SDDL(self.AceType), 
			ACE_FLAGS_TO_SDDL(self.AceFlags), 
			ACE_ACCESS_RIGHTS_TO_SDDL(self.Mask),
			str(self.ObjectType) if self.Flags & ACE_OBJECT_PRESENCE.ACE_OBJECT_TYPE_PRESENT else '' ,
			str(self.InheritedObjectType) if self.Flags & ACE_OBJECT_PRESENCE.ACE_INHERITED_OBJECT_TYPE_PRESENT else '', 
			self.Sid.to_sddl()  
		)
		
class ACCESS_DENIED_OBJECT_ACE:
	def __init__(self):
		self.AceType = ACEType.ACCESS_DENIED_OBJECT_ACE_TYPE
		self.AceFlags = None
		self.AceSize = None
		self.Mask = None
		self.Flags = None
		self.ObjectType = None
		self.InheritedObjectType = None
		self.Sid = None

		self.sd_object_type = None
		
	@staticmethod
	def from_buffer(buff, sd_object_type):
		ace = ACCESS_DENIED_OBJECT_ACE()
		ace.sd_object_type = sd_object_type
		ace.AceType = ACEType(int.from_bytes(buff.read(1), 'little', signed = False))
		ace.AceFlags = ACEFlags(int.from_bytes(buff.read(1), 'little', signed = False))
		ace.AceSize = int.from_bytes(buff.read(2), 'little', signed = False)
		ace.Mask = int.from_bytes(buff.read(4), 'little', signed = False)
		ace.Flags = ACE_OBJECT_PRESENCE(int.from_bytes(buff.read(4), 'little', signed = False))
		if ace.Flags & ACE_OBJECT_PRESENCE.ACE_OBJECT_TYPE_PRESENT:
			ace.ObjectType = GUID.from_buffer(buff)
		if ace.Flags & ACE_OBJECT_PRESENCE.ACE_INHERITED_OBJECT_TYPE_PRESENT:
			ace.InheritedObjectType = GUID.from_buffer(buff)
		ace.Sid = SID.from_buffer(buff)
		return ace
	
	def to_buffer(self, buff):
		if self.ObjectType is not None:
			if self.Flags is None:
				self.Flags = 0
			self.Flags |= ACE_OBJECT_PRESENCE.ACE_OBJECT_TYPE_PRESENT
		if self.InheritedObjectType is not None:
			if self.Flags is None:
				self.Flags = 0
			self.Flags |= ACE_OBJECT_PRESENCE.ACE_INHERITED_OBJECT_TYPE_PRESENT

		t = self.Mask.to_bytes(4, 'little', signed = False)
		t += self.Flags.to_bytes(4, 'little', signed = False)
		if self.Flags & ACE_OBJECT_PRESENCE.ACE_OBJECT_TYPE_PRESENT:
			t += self.ObjectType.to_bytes()
		if self.Flags & ACE_OBJECT_PRESENCE.ACE_INHERITED_OBJECT_TYPE_PRESENT:
			t += self.InheritedObjectType.to_bytes()
		
		t += self.Sid.to_bytes()
		t = ACE.add_padding(t)
		self.AceSize = 4 + len(t)
		buff.write(self.AceType.value.to_bytes(1, 'little', signed = False))
		buff.write(self.AceFlags.to_bytes(1, 'little', signed = False))
		buff.write(self.AceSize.to_bytes(2, 'little', signed = False))
		buff.write(t)

	def to_sddl(self, sd_object_type = None):
		# ace_type;ace_flags;rights;object_guid;inherit_object_guid;account_sid;(resource_attribute)
		return '(%s;%s;%s;%s;%s;%s)' % ( 
			ACE_TYPE_TO_SDDL(self.AceType), 
			ACE_FLAGS_TO_SDDL(self.AceFlags), 
			ACE_ACCESS_RIGHTS_TO_SDDL(self.Mask),
			str(self.ObjectType) if self.Flags & ACE_OBJECT_PRESENCE.ACE_OBJECT_TYPE_PRESENT else '' ,
			str(self.InheritedObjectType) if self.Flags & ACE_OBJECT_PRESENCE.ACE_INHERITED_OBJECT_TYPE_PRESENT else '', 
			self.Sid.to_sddl()  
		)
		
class SYSTEM_AUDIT_OBJECT_ACE:
	def __init__(self):
		self.AceType = ACEType.SYSTEM_AUDIT_OBJECT_ACE_TYPE
		self.AceFlags = None
		self.AceSize = None
		self.Mask = None
		self.Flags = None
		self.ObjectType = None
		self.InheritedObjectType = None
		self.Sid = None
		self.ApplicationData = None #must be bytes!
		

		self.sd_object_type = None
	@staticmethod
	def from_buffer(buff, sd_object_type):
		start = buff.tell()
		ace = SYSTEM_AUDIT_OBJECT_ACE()
		ace.sd_object_type  = sd_object_type
		ace.AceType = ACEType(int.from_bytes(buff.read(1), 'little', signed = False))
		ace.AceFlags = ACEFlags(int.from_bytes(buff.read(1), 'little', signed = False))
		ace.AceSize = int.from_bytes(buff.read(2), 'little', signed = False)
		ace.Mask = int.from_bytes(buff.read(4), 'little', signed = False)
		ace.Flags = ACE_OBJECT_PRESENCE(int.from_bytes(buff.read(4), 'little', signed = False))
		if ace.Flags & ACE_OBJECT_PRESENCE.ACE_OBJECT_TYPE_PRESENT:
			ace.ObjectType = GUID.from_buffer(buff)
		if ace.Flags & ACE_OBJECT_PRESENCE.ACE_INHERITED_OBJECT_TYPE_PRESENT:
			ace.InheritedObjectType = GUID.from_buffer(buff)
		ace.Sid = SID.from_buffer(buff)
		ace.ApplicationData = buff.read(ace.AceSize - (buff.tell() - start))
		return ace
	
	def to_buffer(self, buff):
		if self.ObjectType is not None:
			if self.Flags is None:
				self.Flags = 0
			self.Flags |= ACE_OBJECT_PRESENCE.ACE_OBJECT_TYPE_PRESENT
		if self.InheritedObjectType is not None:
			if self.Flags is None:
				self.Flags = 0
			self.Flags |= ACE_OBJECT_PRESENCE.ACE_INHERITED_OBJECT_TYPE_PRESENT

		t = self.Mask.to_bytes(4, 'little', signed = False)
		t += self.Flags.to_bytes(4, 'little', signed = False)
		if self.Flags & ACE_OBJECT_PRESENCE.ACE_OBJECT_TYPE_PRESENT:
			t += self.ObjectType.to_bytes()
		if self.Flags & ACE_OBJECT_PRESENCE.ACE_INHERITED_OBJECT_TYPE_PRESENT:
			t += self.InheritedObjectType.to_bytes()
		
		t += self.Sid.to_bytes()
		t += self.ApplicationData
		t = ACE.add_padding(t)
		self.AceSize = 4 + len(t)
		buff.write(self.AceType.value.to_bytes(1, 'little', signed = False))
		buff.write(self.AceFlags.to_bytes(1, 'little', signed = False))
		buff.write(self.AceSize.to_bytes(2, 'little', signed = False))
		buff.write(t)
		
class ACCESS_ALLOWED_CALLBACK_ACE:
	def __init__(self):
		self.AceType = ACEType.ACCESS_ALLOWED_CALLBACK_ACE_TYPE
		self.AceFlags = None
		self.AceSize = None
		self.Mask = None
		self.Sid = None
		self.ApplicationData = None
		
		self.sd_object_type = None
	
	@staticmethod
	def from_buffer(buff, sd_object_type):
		start = buff.tell()
		ace = ACCESS_ALLOWED_CALLBACK_ACE()
		ace.sd_object_type = sd_object_type
		ace.AceType = ACEType(int.from_bytes(buff.read(1), 'little', signed = False))
		ace.AceFlags = ACEFlags(int.from_bytes(buff.read(1), 'little', signed = False))
		ace.AceSize = int.from_bytes(buff.read(2), 'little', signed = False)
		ace.Mask = int.from_bytes(buff.read(4), 'little', signed = False)
		ace.Sid = SID.from_buffer(buff)
		ace.ApplicationData = buff.read(ace.AceSize - (buff.tell() - start))
		return ace

	def to_buffer(self, buff):
		t = self.Mask.to_bytes(4, 'little', signed = False)		
		t += self.Sid.to_bytes()
		t += self.ApplicationData
		t = ACE.add_padding(t)
		self.AceSize = 4 + len(t)
		buff.write(self.AceType.value.to_bytes(1, 'little', signed = False))
		buff.write(self.AceFlags.to_bytes(1, 'little', signed = False))
		buff.write(self.AceSize.to_bytes(2, 'little', signed = False))
		buff.write(t)
		
class ACCESS_DENIED_CALLBACK_ACE:
	def __init__(self):
		self.AceType = ACEType.ACCESS_DENIED_CALLBACK_ACE_TYPE
		self.AceFlags = None
		self.AceSize = None
		self.Mask = None
		self.Sid = None
		self.ApplicationData = None
		
		self.sd_object_type = None
	
	@staticmethod
	def from_buffer(buff, sd_object_type):
		start = buff.tell()
		ace = ACCESS_DENIED_CALLBACK_ACE()
		ace.sd_object_type = sd_object_type
		ace.AceType = ACEType(int.from_bytes(buff.read(1), 'little', signed = False))
		ace.AceFlags = ACEFlags(int.from_bytes(buff.read(1), 'little', signed = False))
		ace.AceSize = int.from_bytes(buff.read(2), 'little', signed = False)
		ace.Mask = int.from_bytes(buff.read(4), 'little', signed = False)
		ace.Sid = SID.from_buffer(buff)
		ace.ApplicationData = buff.read(ace.AceSize - (buff.tell() - start))
		return ace

	def to_buffer(self, buff):
		t = self.Mask.to_bytes(4, 'little', signed = False)		
		t += self.Sid.to_bytes()
		t += self.ApplicationData
		t = ACE.add_padding(t)
		self.AceSize = 4 + len(t)
		buff.write(self.AceType.value.to_bytes(1, 'little', signed = False))
		buff.write(self.AceFlags.to_bytes(1, 'little', signed = False))
		buff.write(self.AceSize.to_bytes(2, 'little', signed = False))
		buff.write(t)
		
class ACCESS_ALLOWED_CALLBACK_OBJECT_ACE:
	def __init__(self):
		self.AceType = ACEType.ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE
		self.AceFlags = None
		self.AceSize = None
		self.Mask = None
		self.Flags = None
		self.ObjectType = None
		self.InheritedObjectType = None
		self.Sid = None
		self.ApplicationData = None
		
		self.sd_object_type = None
	
	@staticmethod
	def from_buffer(buff, sd_object_type):
		start = buff.tell()
		ace = ACCESS_ALLOWED_CALLBACK_OBJECT_ACE()
		ace.sd_object_type = sd_object_type
		ace.AceType = ACEType(int.from_bytes(buff.read(1), 'little', signed = False))
		ace.AceFlags = ACEFlags(int.from_bytes(buff.read(1), 'little', signed = False))
		ace.AceSize = int.from_bytes(buff.read(2), 'little', signed = False)
		ace.Mask = int.from_bytes(buff.read(4), 'little', signed = False)
		ace.Flags = ACE_OBJECT_PRESENCE(int.from_bytes(buff.read(4), 'little', signed = False))
		if ace.Flags & ACE_OBJECT_PRESENCE.ACE_OBJECT_TYPE_PRESENT:
			ace.ObjectType = GUID.from_buffer(buff)
		if ace.Flags & ACE_OBJECT_PRESENCE.ACE_INHERITED_OBJECT_TYPE_PRESENT:
			ace.InheritedObjectType = GUID.from_buffer(buff)
		ace.Sid = SID.from_buffer(buff)
		ace.ApplicationData = buff.read(ace.AceSize - (buff.tell() - start))
		return ace

	def to_buffer(self, buff):
		if self.ObjectType is not None:
			if self.Flags is None:
				self.Flags = 0
			self.Flags |= ACE_OBJECT_PRESENCE.ACE_OBJECT_TYPE_PRESENT
		if self.InheritedObjectType is not None:
			if self.Flags is None:
				self.Flags = 0
			self.Flags |= ACE_OBJECT_PRESENCE.ACE_INHERITED_OBJECT_TYPE_PRESENT

		t = self.Mask.to_bytes(4, 'little', signed = False)
		t += self.Flags.to_bytes(4, 'little', signed = False)
		if self.Flags & ACE_OBJECT_PRESENCE.ACE_OBJECT_TYPE_PRESENT:
			t += self.ObjectType.to_bytes()
		if self.Flags & ACE_OBJECT_PRESENCE.ACE_INHERITED_OBJECT_TYPE_PRESENT:
			t += self.InheritedObjectType.to_bytes()
		
		t += self.Sid.to_bytes()
		t += self.ApplicationData
		t = ACE.add_padding(t)
		self.AceSize = 4 + len(t)
		buff.write(self.AceType.value.to_bytes(1, 'little', signed = False))
		buff.write(self.AceFlags.to_bytes(1, 'little', signed = False))
		buff.write(self.AceSize.to_bytes(2, 'little', signed = False))
		buff.write(t)
		
class ACCESS_DENIED_CALLBACK_OBJECT_ACE:
	def __init__(self):
		self.AceType = ACEType.ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE
		self.AceFlags = None
		self.AceSize = None
		self.Mask = None
		self.Flags = None
		self.ObjectType = None
		self.InheritedObjectType = None
		self.Sid = None
		self.ApplicationData = None
		
		self.sd_object_type = None
	@staticmethod
	def from_buffer(buff, sd_object_type):
		start = buff.tell()
		ace = ACCESS_DENIED_CALLBACK_OBJECT_ACE()
		ace.sd_object_type = sd_object_type
		ace.AceType = ACEType(int.from_bytes(buff.read(1), 'little', signed = False))
		ace.AceFlags = ACEFlags(int.from_bytes(buff.read(1), 'little', signed = False))
		ace.AceSize = int.from_bytes(buff.read(2), 'little', signed = False)
		ace.Mask = int.from_bytes(buff.read(4), 'little', signed = False)
		ace.Flags = ACE_OBJECT_PRESENCE(int.from_bytes(buff.read(4), 'little', signed = False))
		if ace.Flags & ACE_OBJECT_PRESENCE.ACE_OBJECT_TYPE_PRESENT:
			ace.ObjectType = GUID.from_buffer(buff)
		if ace.Flags & ACE_OBJECT_PRESENCE.ACE_INHERITED_OBJECT_TYPE_PRESENT:
			ace.InheritedObjectType = GUID.from_buffer(buff)
		ace.Sid = SID.from_buffer(buff)
		ace.ApplicationData = buff.read(ace.AceSize - (buff.tell() - start))
		return ace
	
	def to_buffer(self, buff):
		if self.ObjectType is not None:
			if self.Flags is None:
				self.Flags = 0
			self.Flags |= ACE_OBJECT_PRESENCE.ACE_OBJECT_TYPE_PRESENT
		if self.InheritedObjectType is not None:
			if self.Flags is None:
				self.Flags = 0
			self.Flags |= ACE_OBJECT_PRESENCE.ACE_INHERITED_OBJECT_TYPE_PRESENT

		t = self.Mask.to_bytes(4, 'little', signed = False)
		t += self.Flags.to_bytes(4, 'little', signed = False)
		if self.Flags & ACE_OBJECT_PRESENCE.ACE_OBJECT_TYPE_PRESENT:
			t += self.ObjectType.to_bytes()
		if self.Flags & ACE_OBJECT_PRESENCE.ACE_INHERITED_OBJECT_TYPE_PRESENT:
			t += self.InheritedObjectType.to_bytes()
		
		t += self.Sid.to_bytes()
		t += self.ApplicationData
		t = ACE.add_padding(t)
		self.AceSize = 4 + len(t)
		buff.write(self.AceType.value.to_bytes(1, 'little', signed = False))
		buff.write(self.AceFlags.to_bytes(1, 'little', signed = False))
		buff.write(self.AceSize.to_bytes(2, 'little', signed = False))
		buff.write(t)
		
class SYSTEM_AUDIT_CALLBACK_ACE:
	def __init__(self):
		self.AceType = ACEType.SYSTEM_AUDIT_CALLBACK_ACE_TYPE
		self.AceFlags = None
		self.AceSize = None
		self.Mask = None
		self.Sid = None
		self.ApplicationData = None

		self.sd_object_type = None
		
	@staticmethod
	def from_buffer(buff, sd_object_type):
		start = buff.tell()
		ace = SYSTEM_AUDIT_CALLBACK_ACE()
		ace.sd_object_type = sd_object_type
		ace.AceType = ACEType(int.from_bytes(buff.read(1), 'little', signed = False))
		ace.AceFlags = ACEFlags(int.from_bytes(buff.read(1), 'little', signed = False))
		ace.AceSize = int.from_bytes(buff.read(2), 'little', signed = False)
		ace.Mask = int.from_bytes(buff.read(4), 'little', signed = False)
		ace.Sid = SID.from_buffer(buff)
		ace.ApplicationData = buff.read(ace.AceSize - (buff.tell() - start))
		return ace
	
	def to_buffer(self, buff):
		t = self.Mask.to_bytes(4, 'little', signed = False)		
		t += self.Sid.to_bytes()
		t += self.ApplicationData
		t = ACE.add_padding(t)
		self.AceSize = 4 + len(t)
		buff.write(self.AceType.value.to_bytes(1, 'little', signed = False))
		buff.write(self.AceFlags.to_bytes(1, 'little', signed = False))
		buff.write(self.AceSize.to_bytes(2, 'little', signed = False))
		buff.write(t)
		
class SYSTEM_AUDIT_CALLBACK_OBJECT_ACE:
	def __init__(self):
		self.AceType = ACEType.SYSTEM_AUDIT_CALLBACK_OBJECT_ACE_TYPE
		self.AceFlags = None
		self.AceSize = None
		self.Mask = None
		self.Flags = None
		self.ObjectType = None
		self.InheritedObjectType = None
		self.Sid = None
		self.ApplicationData = None
		
		self.sd_object_type = None
	@staticmethod
	def from_buffer(buff, sd_object_type):
		start = buff.tell()
		ace = SYSTEM_AUDIT_CALLBACK_OBJECT_ACE()
		ace.sd_object_type = sd_object_type
		ace.AceType = ACEType(int.from_bytes(buff.read(1), 'little', signed = False))
		ace.AceFlags = ACEFlags(int.from_bytes(buff.read(1), 'little', signed = False))
		ace.AceSize = int.from_bytes(buff.read(2), 'little', signed = False)
		ace.Mask = int.from_bytes(buff.read(4), 'little', signed = False)
		ace.Flags = ACE_OBJECT_PRESENCE(int.from_bytes(buff.read(4), 'little', signed = False))
		if ace.Flags & ACE_OBJECT_PRESENCE.ACE_OBJECT_TYPE_PRESENT:
			ace.ObjectType = GUID.from_buffer(buff)
		if ace.Flags & ACE_OBJECT_PRESENCE.ACE_INHERITED_OBJECT_TYPE_PRESENT:
			ace.InheritedObjectType = GUID.from_buffer(buff)
		ace.Sid = SID.from_buffer(buff)
		ace.ApplicationData = buff.read(ace.AceSize - (buff.tell() - start))
		return ace
	
	def to_buffer(self, buff):
		if self.ObjectType is not None:
			if self.Flags is None:
				self.Flags = 0
			self.Flags |= ACE_OBJECT_PRESENCE.ACE_OBJECT_TYPE_PRESENT
		if self.InheritedObjectType is not None:
			if self.Flags is None:
				self.Flags = 0
			self.Flags |= ACE_OBJECT_PRESENCE.ACE_INHERITED_OBJECT_TYPE_PRESENT

		t = self.Mask.to_bytes(4, 'little', signed = False)
		t += self.Flags.to_bytes(4, 'little', signed = False)
		if self.Flags & ACE_OBJECT_PRESENCE.ACE_OBJECT_TYPE_PRESENT:
			t += self.ObjectType.to_bytes()
		if self.Flags & ACE_OBJECT_PRESENCE.ACE_INHERITED_OBJECT_TYPE_PRESENT:
			t += self.InheritedObjectType.to_bytes()
		
		t += self.Sid.to_bytes()
		t += self.ApplicationData
		t = ACE.add_padding(t)
		self.AceSize = 4 + len(t)
		buff.write(self.AceType.value.to_bytes(1, 'little', signed = False))
		buff.write(self.AceFlags.to_bytes(1, 'little', signed = False))
		buff.write(self.AceSize.to_bytes(2, 'little', signed = False))
		buff.write(t)
		
class SYSTEM_MANDATORY_LABEL_ACE:
	def __init__(self):
		self.AceType = ACEType.SYSTEM_MANDATORY_LABEL_ACE_TYPE
		self.AceFlags = None
		self.AceSize = None
		self.Mask = None
		self.Sid = None

		self.sd_object_type = None
		
	@staticmethod
	def from_buffer(buff, sd_object_type):
		ace = SYSTEM_MANDATORY_LABEL_ACE()
		ace.sd_object_type = sd_object_type
		ace.AceType = ACEType(int.from_bytes(buff.read(1), 'little', signed = False))
		ace.AceFlags = ACEFlags(int.from_bytes(buff.read(1), 'little', signed = False))
		ace.AceSize = int.from_bytes(buff.read(2), 'little', signed = False)
		ace.Mask = int.from_bytes(buff.read(4), 'little', signed = False)
		ace.Sid = SID.from_buffer(buff)
		return ace

	def to_buffer(self, buff):
		t = self.Mask.to_bytes(4, 'little', signed = False)
		t += self.Sid.to_bytes()
		t = ACE.add_padding(t)
		self.AceSize = 4 + len(t)
		buff.write(self.AceType.value.to_bytes(1, 'little', signed = False))
		buff.write(self.AceFlags.to_bytes(1, 'little', signed = False))
		buff.write(self.AceSize.to_bytes(2, 'little', signed = False))
		buff.write(t)
		
class SYSTEM_RESOURCE_ATTRIBUTE_ACE:
	def __init__(self):
		self.AceType = ACEType.SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE
		self.AceFlags = None
		self.AceSize = None
		self.Mask = None
		self.Sid = None
		self.AttributeData = None #must be bytes for now. structure is TODO (see top of file)
		
		self.sd_object_type = None

	@staticmethod
	def from_buffer(buff, sd_object_type):
		start = buff.tell()
		ace = SYSTEM_RESOURCE_ATTRIBUTE_ACE()
		ace.sd_object_type = sd_object_type
		ace.AceType = ACEType(int.from_bytes(buff.read(1), 'little', signed = False))
		ace.AceFlags = ACEFlags(int.from_bytes(buff.read(1), 'little', signed = False))
		ace.AceSize = int.from_bytes(buff.read(2), 'little', signed = False)
		ace.Mask = int.from_bytes(buff.read(4), 'little', signed = False)
		ace.Sid = SID.from_buffer(buff)
		ace.AttributeData = buff.read(ace.AceSize - (buff.tell() - start))
		return ace

	def to_buffer(self, buff):
		t = self.Mask.to_bytes(4, 'little', signed = False)		
		t += self.Sid.to_bytes()
		t += self.AttributeData
		t = ACE.add_padding(t)
		self.AceSize = 4 + len(t)
		buff.write(self.AceType.value.to_bytes(1, 'little', signed = False))
		buff.write(self.AceFlags.to_bytes(1, 'little', signed = False))
		buff.write(self.AceSize.to_bytes(2, 'little', signed = False))
		buff.write(t)
		
class SYSTEM_SCOPED_POLICY_ID_ACE:
	def __init__(self):
		self.AceType = ACEType.SYSTEM_SCOPED_POLICY_ID_ACE_TYPE
		self.AceFlags = None
		self.AceSize = None
		self.Mask = None
		self.Sid = None

		self.sd_object_type = None
		
	@staticmethod
	def from_buffer(buff, sd_object_type):
		ace = SYSTEM_SCOPED_POLICY_ID_ACE()
		ace.sd_object_type = sd_object_type
		ace.AceType = ACEType(int.from_bytes(buff.read(1), 'little', signed = False))
		ace.AceFlags = ACEFlags(int.from_bytes(buff.read(1), 'little', signed = False))
		ace.AceSize = int.from_bytes(buff.read(2), 'little', signed = False)
		ace.Mask = int.from_bytes(buff.read(4), 'little', signed = False)
		ace.Sid = SID.from_buffer(buff)
		return ace

	def to_buffer(self, buff):
		t = self.Mask.to_bytes(4, 'little', signed = False)
		t += self.Sid.to_bytes()
		t = ACE.add_padding(t)
		self.AceSize = 4 + len(t)
		buff.write(self.AceType.value.to_bytes(1, 'little', signed = False))
		buff.write(self.AceFlags.to_bytes(1, 'little', signed = False))
		buff.write(self.AceSize.to_bytes(2, 'little', signed = False))
		buff.write(t)

ACEType2ACE = {
	ACEType.ACCESS_ALLOWED_ACE_TYPE : ACCESS_ALLOWED_ACE,
	ACEType.ACCESS_DENIED_ACE_TYPE : ACCESS_DENIED_ACE,
	ACEType.SYSTEM_AUDIT_ACE_TYPE : SYSTEM_AUDIT_ACE,
	ACEType.SYSTEM_ALARM_ACE_TYPE : SYSTEM_ALARM_ACE,
	ACEType.ACCESS_ALLOWED_OBJECT_ACE_TYPE : ACCESS_ALLOWED_OBJECT_ACE,
	ACEType.ACCESS_DENIED_OBJECT_ACE_TYPE : ACCESS_DENIED_OBJECT_ACE,
	ACEType.SYSTEM_AUDIT_OBJECT_ACE_TYPE : SYSTEM_AUDIT_OBJECT_ACE,
	ACEType.ACCESS_ALLOWED_CALLBACK_ACE_TYPE : ACCESS_ALLOWED_CALLBACK_ACE,
	ACEType.ACCESS_DENIED_CALLBACK_ACE_TYPE : ACCESS_DENIED_CALLBACK_ACE,
	ACEType.ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE : ACCESS_ALLOWED_CALLBACK_OBJECT_ACE,
	ACEType.ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE : ACCESS_DENIED_CALLBACK_OBJECT_ACE,
	ACEType.SYSTEM_AUDIT_CALLBACK_ACE_TYPE : SYSTEM_AUDIT_CALLBACK_ACE,
	ACEType.SYSTEM_AUDIT_CALLBACK_OBJECT_ACE_TYPE : SYSTEM_AUDIT_CALLBACK_OBJECT_ACE,
	ACEType.SYSTEM_MANDATORY_LABEL_ACE_TYPE : SYSTEM_MANDATORY_LABEL_ACE,
	ACEType.SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE : SYSTEM_RESOURCE_ATTRIBUTE_ACE,
	ACEType.SYSTEM_SCOPED_POLICY_ID_ACE_TYPE : SYSTEM_SCOPED_POLICY_ID_ACE,
	# ACEType.ACCESS_ALLOWED_COMPOUND_ACE_TYPE : , # Reserved
	# ACEType.SYSTEM_ALARM_OBJECT_ACE_TYPE : , # Reserved
	# ACEType.SYSTEM_ALARM_CALLBACK_ACE_TYPE : , # Reserved
	# ACEType.SYSTEM_ALARM_CALLBACK_OBJECT_ACE_TYPE : , # Reserved
}

###########
### ACL ###
###########

# https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/20233ed8-a6c6-4097-aafa-dd545ed24428
class ACL_REVISION(enum.Enum):
	NO_DS = 0x02 # When set to 0x02, only AceTypes 0x00, 0x01, 0x02, 0x03, 0x11, 0x12, and 0x13 can be present in the ACL. An AceType of 0x11 is used for SACLs but not for DACLs. For more information about ACE types, see section 2.4.4.1.
	DS = 0x04 # When set to 0x04, AceTypes 0x05, 0x06, 0x07, 0x08, and 0x11 are allowed. ACLs of revision 0x04 are applicable only to directory service objects. An AceType of 0x11 is used for SACLs but not for DACLs.
ACL_REV_NODS_ALLOWED_TYPES = [0x00, 0x01, 0x02, 0x03, 0x11, 0x12, 0x13]
ACL_REV_DS_ALLOWED_TYPES   = [0x05, 0x06, 0x07, 0x08, 0x11]

# https://learn.microsoft.com/fr-fr/windows/win32/api/winnt/ns-winnt-acl
class ACL:
	def __init__(self, sd_object_type = None):
		self.AclRevision = None
		self.Sbz1 = 0
		self.AclSize = None
		self.AceCount = None
		self.Sbz2 = 0

		self.aces = []
		self.sd_object_type = sd_object_type

	@staticmethod
	def from_buffer(buff, sd_object_type = None):
		acl = ACL(sd_object_type)
		acl.AclRevision = int.from_bytes(buff.read(1), 'little', signed = False)
		acl.Sbz1 = int.from_bytes(buff.read(1), 'little', signed = False)
		acl.AclSize = int.from_bytes(buff.read(2), 'little', signed = False)
		acl.AceCount = int.from_bytes(buff.read(2), 'little', signed = False)
		acl.Sbz2 = int.from_bytes(buff.read(2), 'little', signed = False)
		for _ in range(acl.AceCount):
			acl.aces.append(ACE.from_buffer(buff, sd_object_type))
		return acl

	def to_bytes(self):
		buff = io.BytesIO()
		self.to_buffer(buff)
		buff.seek(0)
		return buff.read()

	def to_buffer(self, buff):
		data_buff = io.BytesIO()

		self.AceCount = len(self.aces)
		for ace in self.aces:
			ace.to_buffer(data_buff)

		self.AclSize = 8 + data_buff.tell()

		buff.write(self.AclRevision.to_bytes(1, 'little', signed = False))
		buff.write(self.Sbz1.to_bytes(1, 'little', signed = False))
		buff.write(self.AclSize.to_bytes(2, 'little', signed = False))
		buff.write(self.AceCount.to_bytes(2, 'little', signed = False))
		buff.write(self.Sbz2.to_bytes(2, 'little', signed = False))
		data_buff.seek(0)
		buff.write(data_buff.read())

	def to_sddl(self, object_type = None):
		t = ''
		for ace in self.aces:
			t += ace.to_sddl(object_type)
		return t

	@staticmethod
	def from_sddl(sddl_str, object_type = None, domain_sid = None):
		acl = ACL()
		acl.AclRevision = 2
		acl.AceCount = 0

		for ace_sddl in sddl_str.split(')('):
			ace = ACE.from_sddl(ace_sddl, object_type = object_type, domain_sid = domain_sid)
			acl.aces.append(ace)
			acl.AceCount += 1
			if acl.AclRevision == 2:
				if ace.AceType.value in ACL_REV_DS_ALLOWED_TYPES:
					acl.AclRevision = ACL_REVISION.DS.value

		return acl

###########################
### Security Descriptor ###
###########################

# https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/security-descriptor-control
class SE_SACL(enum.IntFlag):
	SE_DACL_AUTO_INHERIT_REQ = 0x0100 	# Indicates a required security descriptor in which the discretionary access control list (DACL) is set up to support automatic propagation of inheritable access control entries (ACEs) to existing child objects.
										# For access control lists (ACLs) that support auto inheritance, this bit is always set. Protected servers can call the ConvertToAutoInheritPrivateObjectSecurity function to convert a security descriptor and set this flag.
	SE_DACL_AUTO_INHERITED = 0x0400     # Indicates a security descriptor in which the discretionary access control list (DACL) is set up to support automatic propagation of inheritable access control entries (ACEs) to existing child objects.
										# For access control lists (ACLs) that support auto inheritance, this bit is always set. Protected servers can call the ConvertToAutoInheritPrivateObjectSecurity function to convert a security descriptor and set this flag.
	SE_DACL_DEFAULTED = 0x0008			# Indicates a security descriptor with a default DACL. For example, if the creator an object does not specify a DACL, the object receives the default DACL from the access token of the creator. This flag can affect how the system treats the DACL with respect to ACE inheritance. The system ignores this flag if the SE_DACL_PRESENT flag is not set.
										# This flag is used to determine how the final DACL on the object is to be computed and is not stored physically in the security descriptor control of the securable object.
										# To set this flag, use the SetSecurityDescriptorDacl function.
	SE_DACL_PRESENT = 0x0004			# Indicates a security descriptor that has a DACL. If this flag is not set, or if this flag is set and the DACL is NULL, the security descriptor allows full access to everyone.
										# This flag is used to hold the security information specified by a caller until the security descriptor is associated with a securable object. After the security descriptor is associated with a securable object, the SE_DACL_PRESENT flag is always set in the security descriptor control.
										# To set this flag, use the SetSecurityDescriptorDacl function.
	SE_DACL_PROTECTED = 0x1000			# Prevents the DACL of the security descriptor from being modified by inheritable ACEs. To set this flag, use the SetSecurityDescriptorControl function.
	SE_GROUP_DEFAULTED = 0x0002			# Indicates that the security identifier (SID) of the security descriptor group was provided by a default mechanism. This flag can be used by a resource manager to identify objects whose security descriptor group was set by a default mechanism. To set this flag, use the SetSecurityDescriptorGroup function.
	SE_OWNER_DEFAULTED = 0x0001			# Indicates that the SID of the owner of the security descriptor was provided by a default mechanism. This flag can be used by a resource manager to identify objects whose owner was set by a default mechanism. To set this flag, use the SetSecurityDescriptorOwner function.
	SE_RM_CONTROL_VALID = 0x4000		# Indicates that the resource manager control is valid.
	SE_SACL_AUTO_INHERIT_REQ = 0x0200	# Indicates a required security descriptor in which the system access control list (SACL) is set up to support automatic propagation of inheritable ACEs to existing child objects.
										# The system sets this bit when it performs the automatic inheritance algorithm for the object and its existing child objects. To convert a security descriptor and set this flag, protected servers can call the ConvertToAutoInheritPrivateObjectSecurity function.
	SE_SACL_AUTO_INHERITED = 0x0800		# Indicates a security descriptor in which the system access control list (SACL) is set up to support automatic propagation of inheritable ACEs to existing child objects.
										# The system sets this bit when it performs the automatic inheritance algorithm for the object and its existing child objects. To convert a security descriptor and set this flag, protected servers can call the ConvertToAutoInheritPrivateObjectSecurity function.
	SE_SACL_DEFAULTED = 0x0008			# A default mechanism, rather than the original provider of the security descriptor, provided the SACL. This flag can affect how the system treats the SACL, with respect to ACE inheritance. The system ignores this flag if the SE_SACL_PRESENT flag is not set. To set this flag, use the SetSecurityDescriptorSacl function.
	SE_SACL_PRESENT   = 0x0010			# Indicates a security descriptor that has a SACL. To set this flag, use the SetSecurityDescriptorSacl function.
	SE_SACL_PROTECTED = 0x2000			# Prevents the SACL of the security descriptor from being modified by inheritable ACEs. To set this flag, use the SetSecurityDescriptorControl function.
	SE_SELF_RELATIVE  = 0x8000			# Indicates a self-relative security descriptor. If this flag is not set, the security descriptor is in absolute format. For more information, see Absolute and Self-Relative Security Descriptors.
SDDL_ACL_CONTROL_FLAGS = {
	"P"  : SE_SACL.SE_DACL_PROTECTED,
	"AR" : SE_SACL.SE_DACL_AUTO_INHERIT_REQ,
	"AI" : SE_SACL.SE_DACL_AUTO_INHERITED,
	"SR" : SE_SACL.SE_SELF_RELATIVE,
	# "NO_ACCESS_CONTROL" : 0
}
SDDL_ACL_CONTROL_FLAGS_INV = {v: k for k, v in SDDL_ACL_CONTROL_FLAGS.items()}
def SDDL_ACL_CONTROL(flags):
	t = ''
	for x in SDDL_ACL_CONTROL_FLAGS_INV:
		if x == SE_SACL.SE_SELF_RELATIVE:
			continue # This flag is always set implicitly
		if x in flags:
			t += SDDL_ACL_CONTROL_FLAGS_INV[x]
	return t

# https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/7d4dac05-9cef-4563-a058-f108abecce1d
class SECURITY_DESCRIPTOR:
	def __init__(self, object_type = None):
		self.Revision = 1
		self.Sbz1 = 0 # Default value but SDDL doesnt store this info and in some cases this field is nonzero
		self.Control = None
		self.Owner = None
		self.Group = None
		self.Sacl = None
		self.Dacl = None

		self.object_type = object_type # High level info, not part of the struct

	@staticmethod
	def from_bytes(data, object_type = None):
		return SECURITY_DESCRIPTOR.from_buffer(io.BytesIO(data), object_type)

	def to_bytes(self):
		buff = io.BytesIO()
		self.to_buffer(buff)
		buff.seek(0)
		return buff.read()

	def to_buffer(self, buff):
		start = buff.tell()
		buff_data = io.BytesIO()
		OffsetOwner = 0
		OffsetGroup = 0
		OffsetSacl = 0
		OffsetDacl = 0

		if self.Owner is not None:
			buff_data.write(self.Owner.to_bytes())
			OffsetOwner = start + 20

		if self.Group is not None:
			OffsetGroup = start + 20 + buff_data.tell()
			buff_data.write(self.Group.to_bytes())

		if self.Sacl is not None:
			OffsetSacl = start + 20 + buff_data.tell()
			buff_data.write(self.Sacl.to_bytes())

		if self.Dacl is not None:
			OffsetDacl = start + 20 + buff_data.tell()
			buff_data.write(self.Dacl.to_bytes())

		buff.write(self.Revision.to_bytes(1, 'little', signed = False))
		buff.write(self.Sbz1.to_bytes(1, 'little', signed = False))
		buff.write(self.Control.to_bytes(2, 'little', signed = False))
		buff.write(OffsetOwner.to_bytes(4, 'little', signed = False))
		buff.write(OffsetGroup.to_bytes(4, 'little', signed = False))
		buff.write(OffsetSacl.to_bytes(4, 'little', signed = False))
		buff.write(OffsetDacl.to_bytes(4, 'little', signed = False))
		buff_data.seek(0)
		buff.write(buff_data.read())

	@staticmethod
	def from_buffer(buff, object_type = None):
		sd = SECURITY_DESCRIPTOR(object_type)
		sd.Revision = int.from_bytes(buff.read(1), 'little', signed = False)
		sd.Sbz1 =  int.from_bytes(buff.read(1), 'little', signed = False)
		sd.Control = SE_SACL(int.from_bytes(buff.read(2), 'little', signed = False))
		OffsetOwner  = int.from_bytes(buff.read(4), 'little', signed = False)
		OffsetGroup  = int.from_bytes(buff.read(4), 'little', signed = False)
		OffsetSacl  = int.from_bytes(buff.read(4), 'little', signed = False)
		OffsetDacl  = int.from_bytes(buff.read(4), 'little', signed = False)

		if OffsetOwner > 0:
			buff.seek(OffsetOwner)
			sd.Owner = SID.from_buffer(buff)

		if OffsetGroup > 0:
			buff.seek(OffsetGroup)
			sd.Group = SID.from_buffer(buff)

		if OffsetSacl > 0:
			buff.seek(OffsetSacl)
			sd.Sacl = ACL.from_buffer(buff, object_type)

		if OffsetDacl > 0:
			buff.seek(OffsetDacl)
			sd.Dacl = ACL.from_buffer(buff, object_type)

		return sd

	def to_sddl(self, object_type = None):
		t = ''
		if self.Owner is not None:
			t += 'O:' + self.Owner.to_sddl()
		if self.Group is not None:
			t += 'G:' + self.Group.to_sddl()
		if self.Sacl is not None:
			t += 'S:' + SDDL_ACL_CONTROL(self.Control) + self.Sacl.to_sddl(object_type)
		if self.Dacl is not None:
			t += 'D:' + SDDL_ACL_CONTROL(self.Control) + self.Dacl.to_sddl(object_type)
		return t

	@staticmethod
	def from_sddl(sddl:str, object_type = None, domain_sid = None):
		sd = SECURITY_DESCRIPTOR(object_type = object_type)
		params = sddl.split(':')
		np = [params[0]]
		i = 1
		while i < len(params):
			np.append(params[i][:-1])
			np.append(params[i][-1])
			i += 1
		params = {}
		i = 0
		while i < len(np):
			if np[i] == ')':
				break
			params[np[i]] = np[i+1]
			i += 2

		sd.Control = SE_SACL.SE_SELF_RELATIVE
		fk = None
		if 'D' in params:
			fk = 'D'
		elif 'S' in params:
			fk = 'S'

		if fk is not None:
			if '(' in params[fk]:
				flags, acl = params[fk].split('(', 1)
			else:
				flags = params[fk]
			if flags.upper().find('P') != -1:
				sd.Control |= SE_SACL.SE_DACL_PROTECTED
				sd.Control |= SE_SACL.SE_SACL_PROTECTED
				flags = flags.replace('P', '')
			for _ in range(len(flags)):
				x = flags[:2]
				cf = SDDL_ACL_CONTROL_FLAGS[x]
				if cf == SE_SACL.SE_DACL_AUTO_INHERIT_REQ:
					sd.Control |= SE_SACL.SE_DACL_AUTO_INHERIT_REQ
					sd.Control |= SE_SACL.SE_SACL_AUTO_INHERIT_REQ
				elif cf == SE_SACL.SE_DACL_AUTO_INHERITED:
					sd.Control |= SE_SACL.SE_DACL_AUTO_INHERITED
					sd.Control |= SE_SACL.SE_SACL_AUTO_INHERITED
				else:
					sd.Control |= cf

				flags = flags[2:]
				if flags == '':
					break

		if 'O' in params:
			sd.Owner = SID.from_sddl(params['O'], domain_sid = domain_sid)
		if 'G' in params:
			sd.Group = SID.from_sddl(params['G'], domain_sid = domain_sid)
		if 'D' in params:
			sd.Control |= SE_SACL.SE_DACL_PRESENT
			acl = params['D']
			m = acl.find('(')
			if m != -1:
				sd.Dacl = ACL.from_sddl(acl[m:], object_type = object_type, domain_sid = domain_sid)
		if 'S' in params:
			sd.Control |= SE_SACL.SE_SACL_PRESENT
			acl = params['S']
			m = acl.find('(')
			if m != -1:
				sd.Sacl = ACL.from_sddl(acl[m:], object_type = object_type, domain_sid = domain_sid)

		return sd

############
### SDDL ###
############

def parseSDDL(sd, sddl, dn = None, sid_filter = None):
	# Sometimes the SDDL is defined but contain no ACE
	# For example for msDS-AllowedToActOnBehalfOfOtherIdentity
	if (sd.Dacl.AceCount != 0):
		# Remove Owner and Group
		sddl = sddl[sddl.find("(")+1:-1]

		# For each ACE
		for ace in sddl.split(")("):
			# https://learn.microsoft.com/en-us/windows/win32/secauthz/ace-strings
			# ace_type;ace_flags;rights;object_guid;inherit_object_guid;account_sid;(resource_attribute)
			ace_type, ace_flags, rights, object_guid, inherit_object_guid, account_sid = ace.split(";")

			# Type parsing
			type = SDDL_TO_ACE_TYPE_STR(ace_type)

			# Flags parsing
			flags = SDDL_TO_ACE_FLAGS_STR(ace_flags)

			# Rights parsing
			mask = SDDL_TO_ACE_ACCESS_RIGHTS_STR(rights)

			# Object_GUID parsing
			object_guid = SDDL_TO_ACE_OBJECT_GUID_STR(object_guid)

			# Inherit_Object_GUID parsing
			inherit_object_guid = SDDL_TO_ACE_OBJECT_GUID_STR(inherit_object_guid)

			if (sid_filter != None):
				# Is the trustee we search for ?
				if (account_sid == sid_filter):
					print("[+] Found ACE that apply to '{}':".format(dn))
					print(f"\tACE Type = {type}\n\tACE Flags = {flags}\n\tACE Rights = {mask}\n\tACE Object = {object_guid}\n\tACE Inherit Object = {inherit_object_guid}\n\tACE Trustee SID = {account_sid}")
			else:
				print("[+] Found ACE:")
				print(f"\tACE Type = {type}\n\tACE Flags = {flags}\n\tACE Rights = {mask}\n\tACE Object = {object_guid}\n\tACE Inherit Object = {inherit_object_guid}\n\tACE Trustee SID = {account_sid}")
	else:
		print("[-] No ACEs into DACLs")

############################
### nTSecurityDescriptor ###
############################

def buildNTSecurityDescriptor(sddlStr):
	print("-------------------------")
	print("[+] Building nTSecurityDescriptor")
	print("-------------------------")

	# Binary format from SDDL format (https://github.com/skelsec/winacl)
	sd = SECURITY_DESCRIPTOR.from_sddl(sddlStr)
	sdBytes = sd.to_bytes()
	sdB64 = base64.b64encode(sdBytes)

	print(f"[+] nTSecurityDescriptor = {sdB64.decode()}")

def parseNTSecurityDescriptor(sdData, dn, sid_filter = None):
	# Binary format to SDDL format (https://github.com/skelsec/winacl)
	sd = SECURITY_DESCRIPTOR.from_bytes(sdData)
	sddl = sd.to_sddl()

	if (sid_filter == None):
		print(f"[+] SSDL = {sddl}")

	parseSDDL(sd, sddl, dn, sid_filter)

def listACEWithTrusteeSID(conn, domain, sid):
	print("-----------------------------------------------------")
	print("[+] Listing AD objects the provided SID is trusted")
	print("-----------------------------------------------------")
	control_value = b"\x30\x0b\x02\x01\x77\x04\x00\xa0\x04\x30\x02\x04\x00"  # Control value for LDAP Extended Operation
	entry_generator = search(conn, domain, attributes = ["distinguishedName", "nTSecurityDescriptor"], controls = [("1.2.840.113556.1.4.801", True, control_value),])
	for entry in entry_generator:
		if entry["type"] == "searchResEntry":
			NtSecurityDescriptor = entry["raw_attributes"]["nTSecurityDescriptor"]
			if NtSecurityDescriptor != []:
				NtSecurityDescriptor = NtSecurityDescriptor[0]
				parseNTSecurityDescriptor(NtSecurityDescriptor, entry["attributes"]["distinguishedName"], sid)

def getACLForDN(conn, domain, dn):
	print("-----------------------------------------------------")
	print("[+] Listing ACLs for the provided distinguishedName")
	print("-----------------------------------------------------")
	control_value = b"\x30\x0b\x02\x01\x77\x04\x00\xa0\x04\x30\x02\x04\x00"  # Control value for LDAP Extended Operation
	entry_generator = search(conn, domain, filter = f"(distinguishedName={dn})", attributes = ["distinguishedName", "nTSecurityDescriptor"], controls = [("1.2.840.113556.1.4.801", True, control_value),])
	for entry in entry_generator:
		if entry["type"] == "searchResEntry":
			NtSecurityDescriptor = entry["raw_attributes"]["nTSecurityDescriptor"]
			if NtSecurityDescriptor != []:
				NtSecurityDescriptor = NtSecurityDescriptor[0]
				parseNTSecurityDescriptor(NtSecurityDescriptor, entry["attributes"]["distinguishedName"])

################################################
### msDS-AllowedToActOnBehalfOfOtherIdentity ###
################################################

def parseAllowedToActOnBehalfOfOtherIdentity(sdB64):
	print("-----------------------------------------------------")
	print("[+] Parsing msDS-AllowedToActOnBehalfOfOtherIdentity")
	print("-----------------------------------------------------")

	# Base64 Decode
	sdData = base64.b64decode(sdB64) # Base64 Decode

	# Binary format to SDDL format (https://github.com/skelsec/winacl)
	sd = SECURITY_DESCRIPTOR.from_bytes(sdData)
	sddl = sd.to_sddl()
	print(f"[+] SSDL = {sddl}")

	parseSDDL(sd, sddl)

def buildAllowedToActOnBehalfOfOtherIdentity(sddlStr):
	print("-----------------------------------------------------")
	print("[+] Building msDS-AllowedToActOnBehalfOfOtherIdentity")
	print("-----------------------------------------------------")

	# Binary format from SDDL format (https://github.com/skelsec/winacl)
	sd = SECURITY_DESCRIPTOR.from_sddl(sddlStr)
	sdBytes = sd.to_bytes()
	sdB64 = base64.b64encode(sdBytes)

	print(f"[+] msDS-AllowedToActOnBehalfOfOtherIdentity = {sdB64.decode()}")

##########################
### userAccountControl ###
##########################

# https://learn.microsoft.com/en-us/troubleshoot/windows-server/identity/useraccountcontrol-manipulate-account-properties
USER_ACCOUNT_CONTROL_MASK = {
    "SCRIPT": 0x00000001,
    "ACCOUNTDISABLE": 0x00000002,
    "HOMEDIR_REQUIRED": 0x00000008,
    "LOCKOUT": 0x00000010,
    "PASSWD_NOTREQD": 0x00000020,
    "PASSWD_CANT_CHANGE": 0x00000040,
    "ENCRYPTED_TEXT_PWD_ALLOWED": 0x00000080,
    "TEMP_DUPLICATE_ACCOUNT": 0x00000100,
    "NORMAL_ACCOUNT": 0x00000200,
    "INTERDOMAIN_TRUST_ACCOUNT": 0x00000800,
    "WORKSTATION_TRUST_ACCOUNT": 0x00001000,
    "SERVER_TRUST_ACCOUNT": 0x00002000,
    "DONT_EXPIRE_PASSWORD": 0x00010000,
    "MNS_LOGON_ACCOUNT": 0x00020000,
    "SMARTCARD_REQUIRED": 0x00040000,
    "TRUSTED_FOR_DELEGATION": 0x00080000,
    "NOT_DELEGATED": 0x00100000,
    "USE_DES_KEY_ONLY": 0x00200000,
    "DONT_REQ_PREAUTH": 0x00400000,
    "PASSWORD_EXPIRED": 0x00800000,
    "TRUSTED_TO_AUTH_FOR_DELEGATION": 0x01000000,
    "PARTIAL_SECRETS_ACCOUNT": 0x04000000
}
USER_ACCOUNT_CONTROL_MASK_INV = {v: k for k, v in USER_ACCOUNT_CONTROL_MASK.items()}

def parseUserAccountControl(uacVal):
	print("-------------------------")
	print("[+] Parsing userAccountControl")
	print("-------------------------")

	uacStr = "|".join([string for value, string in USER_ACCOUNT_CONTROL_MASK_INV.items() if value & uacVal])

	print(f"[+] userAccountControl = {uacStr}")

def buildUserAccountControl(uacStr):
	print("-------------------------")
	print("[+] Building userAccountControl")
	print("-------------------------")

	properties = uacStr.split("|")
	uacVal = 0
	for property in properties:
		uacVal += USER_ACCOUNT_CONTROL_MASK[property]

	print(f"[+] userAccountControl = {str(uacVal)}")

############
### gMSA ###
############

# https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/a9019740-3d73-46ef-a9ae-3ea8eb86ac2e
class MSDS_MANAGEDPASSWORD_BLOB:
	def __init__(self):
		self.Version = None
		self.Reserved = None
		self.Length = None
		self.CurrentPasswordOffset = None
		self.PreviousPasswordOffset = None
		self.QueryPasswordIntervalOffset = None
		self.UnchangedPasswordIntervalOffset = None
		self.CurrentPassword = None
		self.PreviousPassword = None
		self.QueryPasswordInterval = None
		self.UnchangedPasswordInterval = None

	@staticmethod
	def from_bytes(data):
		format_string = '<HHIHHHH'
		size = struct.calcsize(format_string)
		fields = struct.unpack(format_string, data[:size])

		blob = MSDS_MANAGEDPASSWORD_BLOB()
		blob.Version = fields[0]
		blob.Reserved = fields[1]
		blob.Length = fields[2]
		blob.CurrentPasswordOffset = fields[3]
		blob.PreviousPasswordOffset = fields[4]
		blob.QueryPasswordIntervalOffset = fields[5]
		blob.UnchangedPasswordIntervalOffset = fields[6]

		if blob.PreviousPasswordOffset == 0:
			endData = blob.QueryPasswordIntervalOffset
		else:
			endData = blob.PreviousPasswordOffset

		current_password_size = endData - blob.CurrentPasswordOffset - 2
		blob.CurrentPassword = data[blob.CurrentPasswordOffset:blob.CurrentPasswordOffset + current_password_size]

		if blob.PreviousPasswordOffset != 0:
			previous_password_size = blob.QueryPasswordIntervalOffset - blob.PreviousPasswordOffset
			blob.PreviousPassword = data[blob.PreviousPasswordOffset:blob.PreviousPasswordOffset + previous_password_size]

		query_password_interval_size = blob.UnchangedPasswordIntervalOffset - blob.QueryPasswordIntervalOffset
		blob.QueryPasswordInterval = data[blob.QueryPasswordIntervalOffset:blob.QueryPasswordIntervalOffset + query_password_interval_size]

		blob.UnchangedPasswordInterval = data[blob.UnchangedPasswordIntervalOffset:]

		return blob

# https://github.com/Semperis/GoldenGMSA/blob/main/GoldenGMSA/MsdsManagedPasswordId.cs
class MSDS_MANAGEDPASSWORD_ID:
	def __init__(self):
		self.Version = None
		self.Reserved = None
		self.IsPublicKey = None
		self.L0Index = None
		self.L1Index = None
		self.L2Index = None
		self.RootKeyIdentifier = None
		self.cbUnknown = None
		self.cbDomainName = None
		self.cbForestName = None
		self.Unknown = None
		self.DomainName = None
		self.ForestName = None

	@staticmethod
	def from_bytes(data):
		format_string = '<IIIIII16sIII'
		size = struct.calcsize(format_string)
		fields = struct.unpack(format_string, data[:size])

		ManagedPasswordId = MSDS_MANAGEDPASSWORD_ID()
		ManagedPasswordId.Version = fields[0]
		ManagedPasswordId.Reserved = fields[1]
		ManagedPasswordId.IsPublicKey = fields[2]
		ManagedPasswordId.L0Index = fields[3]
		ManagedPasswordId.L1Index = fields[4]
		ManagedPasswordId.L2Index = fields[5]
		ManagedPasswordId.RootKeyIdentifier = GUID.from_bytes(fields[6])
		ManagedPasswordId.cbUnknown = fields[7]
		ManagedPasswordId.cbDomainName = fields[8]
		ManagedPasswordId.cbForestName = fields[9]

		if ManagedPasswordId.cbUnknown > 0:
			ManagedPasswordId.Unknown = data[size : size + ManagedPasswordId.cbUnknown]
		else:
			ManagedPasswordId.Unknown = None

		domain_name_start = size + ManagedPasswordId.cbUnknown
		domain_name_end = domain_name_start + ManagedPasswordId.cbDomainName
		ManagedPasswordId.DomainName = data[domain_name_start:domain_name_end].decode("utf-16-le")

		forest_name_start = domain_name_end
		forest_name_end = forest_name_start + ManagedPasswordId.cbForestName
		ManagedPasswordId.ForestName = data[forest_name_start:forest_name_end].decode("utf-16-le")

		return ManagedPasswordId

def listGMSA(conn, domain):
	print("-------------------------")
	print("[+] Listing gMSA accounts")
	print("-------------------------")

	entry_generator = search(conn, domain, attributes = ["sAMAccountName", "msDS-ManagedPassword", "msDS-ManagedPasswordId", "msDS-ManagedPasswordInterval", "msDS-GroupMSAMembership"])
	nbentries = 0
	for entry in entry_generator:
		if entry["type"] == "searchResEntry":
			if entry["raw_attributes"]["msDS-ManagedPasswordId"] != []:
				nbentries += 1
				print("[+] Found gMSA account = {}".format(entry["raw_attributes"]["sAMAccountName"][0].decode()))
				if entry["raw_attributes"]["msDS-ManagedPassword"] != []:
					ManagedPasswordBlob = MSDS_MANAGEDPASSWORD_BLOB.from_bytes(entry["raw_attributes"]["msDS-ManagedPassword"][0])
					ManagedPassword = ManagedPasswordBlob.CurrentPassword
					ManagedPasswordNT = hashlib.new ("md4", ManagedPassword).hexdigest()
					# print("\t[+] Managed Password Hex = {}".format(binascii.hexlify(ManagedPassword).decode()))
					print("\t[+] Managed Password NT = {}".format(ManagedPasswordNT))
				else:
					print("\t[-] Current user cannot read msDS-ManagedPassword attribute of gMSA account")

				ManagedPasswordId = MSDS_MANAGEDPASSWORD_ID.from_bytes(entry["raw_attributes"]["msDS-ManagedPasswordId"][0])
				print("\t[+] Managed Password Id")
				print("\t\t[+] Root Key Identifier = {}".format(ManagedPasswordId.RootKeyIdentifier))
				print("\t\t[+] Domain Name = {}".format(ManagedPasswordId.DomainName))
				print("\t\t[+] Domain Name = {}".format(ManagedPasswordId.ForestName))

				if entry["raw_attributes"]["msDS-ManagedPasswordInterval"] != []:
					print("\t[+] Managed Password Interval = {} day(s)".format(entry["raw_attributes"]["msDS-ManagedPasswordInterval"][0].decode()))

				if entry["raw_attributes"]["msDS-GroupMSAMembership"] != []:
					sd = SECURITY_DESCRIPTOR.from_bytes(entry["raw_attributes"]["msDS-GroupMSAMembership"][0])
					sddl = sd.to_sddl()
					print("\t[+] gMSA Membership SDDL = {}".format(sddl))

	if nbentries == 0:
		print("[-] No LDAP encrypted connection used and/or no gMSA accounts")

############
### LAPS ###
############

def windows_timestamp_to_date(timestamp):
    # Windows Filetime epoch starts on January 1, 1601
    windows_epoch = datetime.datetime(1601, 1, 1, 0, 0, 0)

    # Convert 100-nanosecond intervals to seconds
    seconds = timestamp / 10**7

    # Add the seconds to the Windows epoch
    date = windows_epoch + datetime.timedelta(seconds=seconds)

    # Return a formatted date string
    return date.strftime("%Y-%m-%d %H:%M:%S")

def listLAPS(conn, domain):
	print("-------------------------")
	print("[+] Listing LA pwds managed by LAPS")
	print("-------------------------")

	entry_generator = search(conn, domain, attributes = ["sAMAccountName", "ms-Mcs-AdmPwd", "ms-Mcs-AdmPwdExpirationTime"])
	nbentries = 0
	for entry in entry_generator:
		if entry["type"] == "searchResEntry":
			if entry["raw_attributes"]["ms-Mcs-AdmPwd"] != []:
				nbentries += 1
				pwd = entry["raw_attributes"]["ms-Mcs-AdmPwd"][0].decode()
				timestamp = int(entry["raw_attributes"]["ms-Mcs-AdmPwdExpirationTime"][0])
				date = windows_timestamp_to_date(timestamp)
				print("[+] Found LA pwd for computer '{}' = {} (Expiration date = {})".format(entry["raw_attributes"]["sAMAccountName"][0].decode(), pwd, date))

	if nbentries == 0:
		print("[-] No managed LA pwds by LAPS and/or user does not have rights to read pwds")

#################
### Bitlocker ###
#################

def listBitlocker(conn, domain):
	print("-------------------------")
	print("[+] Listing Bitlocker Recovery Keys")
	print("-------------------------")

	entry_generator = search(conn, domain, attributes = ["sAMAccountName", "msFVE-RecoveryPassword"])
	nbentries = 0
	for entry in entry_generator:
		if entry["type"] == "searchResEntry":
			if entry["raw_attributes"]["msFVE-RecoveryPassword"] != []:
				nbentries += 1
				pwd = entry["raw_attributes"]["msFVE-RecoveryPassword"][0].decode()
				print("[+] Found Bitlocker Recovery Key for computer '{}' = {}".format(entry["raw_attributes"]["sAMAccountName"][0].decode(), pwd,))

	if nbentries == 0:
		print("[-] No Bitlocker Recovery Keys and/or user does not have rights to read keys")

######################
### Raw LDAP query ###
######################

def LDAPQuery(conn, domain, filter = "(objectClass=*)", attributes = [ALL_ATTRIBUTES, ALL_OPERATIONAL_ATTRIBUTES], controls = None):
	print("-------------------------")
	print("[+] Sending raw LDAP query")
	print("-------------------------")

	entry_generator = search(conn, domain, filter = filter, attributes = attributes, controls = controls)
	nbentries = 0
	for entry in entry_generator:
		if entry["type"] == "searchResEntry":
			nbentries += 1
			print("[+] Entry {}: {}".format(nbentries, entry["attributes"]))
	print(f"[+] Returned {nbentries} entries")

############
### MAIN ###
############

if __name__ == "__main__":
	parser = argparse.ArgumentParser(description = "LDAP utility tool for parsing/building/searching LDAP attributes")

	auth_group = parser.add_argument_group('Authentication options')
	auth_group.add_argument("--server_url", help = "<ldap[s]/ldap-starttls>://<IP/FQDN>. FQDN is required for Kerberos authentication", required = True)
	auth_group.add_argument("--authentication", choices = ["NTLM", "Kerberos"], help = "Authentication method", required = True)
	auth_group.add_argument("--username", help = "Username for authentication", required = True)
	auth_group.add_argument("--nthash", help = "NT hash for NTLM authentication")
	auth_group.add_argument("--password", help = "Password for NTLM authentication")
	auth_group.add_argument("--domain", help = "Domain for authentication", required = True)
	auth_group.add_argument("--ccache", help = "Path to .ccache file for Kerberos authentication")

	ntsecuritydesc_group = parser.add_argument_group('nTSecurityDescriptor options')
	ntsecuritydesc_group.add_argument("--listACEWithTrusteeSID", help = "List AD objects' ACEs on which that following SID is trusted")
	ntsecuritydesc_group.add_argument("--getACLForDN", help = "Get ACLs for the following distinguishedName")
	ntsecuritydesc_group.add_argument("--buildNtSecurityDescriptor", help = "Build nTSecurityDescriptor in binary format from SDDL string that describe the Owner + Group + DACL for the object")

	allowedToActOnBehalfOfOtherIdentity_group = parser.add_argument_group('msDS-AllowedToActOnBehalfOfOtherIdentity options')
	allowedToActOnBehalfOfOtherIdentity_group.add_argument("--buildAllowedToActOnBehalfOfOtherIdentity", help = "Build msDS-AllowedToActOnBehalfOfOtherIdentity in binary format from SDDL string that describe the object Owner + Group + DACL allowed to act on behalf")
	allowedToActOnBehalfOfOtherIdentity_group.add_argument("--parseAllowedToActOnBehalfOfOtherIdentity", help = "Parse msDS-AllowedToActOnBehalfOfOtherIdentity from SDDL in Base64 that describe the object Owner + Group + DACL allowed to act on behalf")

	objectGUID_group = parser.add_argument_group('objectGUID options')
	objectGUID_group.add_argument("--buildObjectGUID", help = "Build objectGUID in binary format from GUID string that describe the GUID of the object")
	objectGUID_group.add_argument("--parseObjectGUID", help = "Parse objectGUID from GUID in Base64 that describe the GUID of the object")

	objectSID_group = parser.add_argument_group('objectSID options')
	objectSID_group.add_argument("--buildObjectSID", help = "Build objectSid in binary format from SID string that describe the SID of the object")
	objectSID_group.add_argument("--parseObjectSID", help = "Parse objectSid from SID in Base64 that describe the SID of the object")

	userAccountControl_group = parser.add_argument_group('userAccountControl options')
	userAccountControl_group.add_argument("--buildUserAccountControl", help = "Build userAccountControl value from userAccountControl accesses string separated with pipes that describe the object properties. Ex: DONT_REQ_PREAUTH|TRUSTED_FOR_DELEGATION")
	userAccountControl_group.add_argument("--parseUserAccountControl", type = int, help = "Parse userAccountControl from integer value that describe the object properties")

	gMSA_group = parser.add_argument_group('gMSA options')
	gMSA_group.add_argument("--listGMSA", help = "List gMSA accounts. LDAPS or LDAP with StartTLS required for msDS-ManagedPassword", action = "store_true")

	LAPS_group = parser.add_argument_group('LAPS options')
	LAPS_group.add_argument("--listLAPS", help = "List LA pwds managed by LAPS", action = "store_true")

	Bitlocker_group = parser.add_argument_group('Bitlocker options')
	Bitlocker_group.add_argument("--listBitlocker", help = "List Bitlocker Recovery Keys", action = "store_true")

	rawLDAPQuery_group = parser.add_argument_group('Raw LDAP query options')
	rawLDAPQuery_group.add_argument("--rawLDAPQuery", help = "Perform raw LDAP query", action = "store_true")
	rawLDAPQuery_group.add_argument("--LDAPFilter", help = "LDAP filter")
	rawLDAPQuery_group.add_argument("--LDAPAttributes", help = "LDAP attributes to search for. Commas separated list")
	rawLDAPQuery_group.add_argument("--LDAPControls", help = "LDAP additional controls to send in the request")

	args = parser.parse_args()

	conn = connect_ldap(args.server_url, args.username, args.password, args.nthash, args.domain, args.authentication, args.ccache)

	if (args.listACEWithTrusteeSID != None):
		listACEWithTrusteeSID(conn, args.domain, args.listACEWithTrusteeSID)
	if (args.buildNtSecurityDescriptor != None):
		buildNTSecurityDescriptor(args.buildNtSecurityDescriptor)
	if (args.getACLForDN != None):
		getACLForDN(conn, args.domain, args.getACLForDN)
	if (args.buildAllowedToActOnBehalfOfOtherIdentity != None):
		buildAllowedToActOnBehalfOfOtherIdentity(args.buildAllowedToActOnBehalfOfOtherIdentity)
	if (args.parseAllowedToActOnBehalfOfOtherIdentity != None):
		parseAllowedToActOnBehalfOfOtherIdentity(args.parseAllowedToActOnBehalfOfOtherIdentity)
	if (args.buildObjectGUID != None):
		buildObjectGUID(args.buildObjectGUID)
	if (args.parseObjectGUID != None):
		parseObjectGUID(args.parseObjectGUID)
	if (args.buildObjectSID != None):
		buildObjectSID(args.buildObjectSID)
	if (args.parseObjectSID != None):
		parseObjectSID(args.parseObjectSID)
	if (args.buildUserAccountControl != None):
		buildUserAccountControl(args.buildUserAccountControl)
	if (args.parseUserAccountControl != None):
		parseUserAccountControl(args.parseUserAccountControl)
	if (args.listGMSA):
		listGMSA(conn, args.domain)
	if (args.listLAPS):
		listLAPS(conn, args.domain)
	if (args.listBitlocker):
		listBitlocker(conn, args.domain)

	if (args.rawLDAPQuery):
		if (args.LDAPFilter == None):
			filter = "(objectClass=*)"
		else:
			filter = args.LDAPFilter
		if (args.LDAPAttributes == None):
			attributes = [ALL_ATTRIBUTES, ALL_OPERATIONAL_ATTRIBUTES]
		else:
			attributes = args.LDAPAttributes.split(",")
		LDAPQuery(conn, args.domain, filter, attributes, args.LDAPControls)
