# LDAP Attributes

Unpacking various LDAP attributes:
* `objectGUID`: `GUID` that identify the object
* `objectSid`: `SID` that identify the object
* `nTSecurityDescriptor`: Access rights on the object based on a `Security Descriptor`
* `msDS-AllowedToActOnBehalfOfOtherIdentity`: Identify objects allowed to act on behalf of others on this object for `Resource-Based Constrained Delegation (RBCD)`
* `userAccountControl`: User account properties such as
  * `TRUSTED_FOR_DELEGATION`: `Kerberos Unconstrained Delegation (KUD)` enabled for this object
  * `NOT_DELEGATED`: Object is `sensitive and cannot be delegated`
  * `DONT_REQ_PREAUTH`: Kerberos Pre-Authentication not required
  * `TRUSTED_TO_AUTH_FOR_DELEGATION`: 
    `Kerberos Constrained Delegation (KCD)` configured for `any authentication protocol (Kerberos and NTLM)` = with `Protocol Transition`
* `gMSA` attributes with
  * `msDS-GroupMSAMembership`: `Security Descriptor` that describe the trustee that can access the `msds-ManagedPassword` attribute
  * `msds-ManagedPassword`: Structure `MSDS-MANAGEDPASSWORD_BLOB` that contain cleartext password of the gMSA account
  * `msDS-ManagedPasswordId`: Structure `MSDS-MANAGEDPASSWORD_ID` that contain `Root Key Identifier` used for generation of `msds-ManagedPassword`
  * `msDS-ManagedPasswordInterval`: Number of days interval between password changing
* `LAPS` attributes with
  * `ms-Mcs-AdmPwd`: Cleartext password for the RID 500 local administrator (default)
  * `ms-Mcs-AdmPwdExpirationTime`: Windows timestamp that represent the next expiration date for the password
* `msFVE-RecoveryPassword`: Cleartext `Bitlocker Recovery Key`

 All credits to <https://github.com/skelsec/winacl> for Windows `Security Descriptor` parsing.

 # Tools

 * Requirements
```
sudo apt install -y libkrb5-dev libssl-dev
python3 -m pip install gssapi
```
* Howto
```
python3 LDAPUtil.py --help
```

 # TODO

 * Others interesting LDAP attributes ?
 * Adding LDAP attributes writing features. Or not, as there is already plenty of tools for doing so ...
