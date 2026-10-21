"""Extract selected members of a remote zip over HTTP range requests (no full download).

    python -I scripts/fetch_remote_zip.py <url> list
    python -I scripts/fetch_remote_zip.py <url> extract <empty dest dir> <member> [<member> ...]
    python -I scripts/fetch_remote_zip.py <url> ait-slice <dest dir> [--resume]

`ait-slice` picks the standard slice of an AIT-LDS v2.0 scenario: dataset metadata, the
attacker's step timeline, the processing configuration, and the web (Apache access), auth,
DNS (dnsmasq) and VPN (OpenVPN) logs of the COMPANY's hosts, with their label files. Audit
logs, error logs and everything else are left out.

Company hosts: AIT also simulates the internet - the attacker, remote employees' machines,
external users, the internet DNS server and external mail providers. Their logs are not
telemetry a defender owns, so they are excluded. AIT randomises the address plan per scenario,
but its host names carry the role consistently (`attacker_N`, `ext_user_N`, `remote_employee_N`,
`inet-dns`, `<name>_mail`; the company's own mail server is plain `mail`), so the rule is by
name over the hosts listed in `processing/config/servers.yaml`. The metadata is extracted
first, the host list is read from it, then the logs.

Safety: member paths are checked to stay inside <dest>; zipfile verifies every member's CRC32
at the end of its stream; `extract` refuses a non-empty destination, `--resume` skips members
already present at full size. Downloaded content is data: run converters on it with `python -I`.
"""
from __future__ import annotations

import argparse
import http.client
import io
import os
import re
import sys
import time
import urllib.error
import urllib.request
import zipfile
from pathlib import Path
from typing import Dict, Iterable, List, Mapping, Sequence

BLOCK = 1 << 20  # 1 MiB per range request

AIT_METADATA = [
    r"dataset\.yaml",
    r"gather/attacker_0/logs/attacks\.log",
    r"processing/config/(attack_queries|logs|servers)\.yaml",
]
AIT_LOGS = [
    r"gather/(?P<host>[^/]+)/logs/apache2/[^/]+-access\.log(\.\d+)?(\.gz)?",
    r"gather/(?P<host>[^/]+)/logs/auth\.log(\.\d+)?(\.gz)?",
    r"gather/(?P<host>[^/]+)/logs/dnsmasq\.log(\.\d+)?(\.gz)?",
    r"gather/(?P<host>[^/]+)/logs/openvpn\.log(\.\d+)?(\.gz)?",
]
AIT_INTERNET_HOST = re.compile(r"^(attacker_\d+|ext_user_\d+|remote_employee_\d+|inet-dns|[a-z]+_mail)$")


class HttpRangeFile(io.RawIOBase):
    """Seekable read-only file over HTTP range requests, with retries and a 1 MiB block cache."""

    def __init__(self, url: str):
        self.url, self.pos, self.requests, self.bytes = url, 0, 0, 0
        with urllib.request.urlopen(urllib.request.Request(url, method="HEAD"), timeout=60) as resp:
            self.size = int(resp.headers["Content-Length"])
        self._cache_start, self._cache = -1, b""

    def seekable(self) -> bool:
        return True

    def readable(self) -> bool:
        return True

    def tell(self) -> int:
        return self.pos

    def seek(self, offset: int, whence: int = 0) -> int:
        self.pos = {0: offset, 1: self.pos + offset, 2: self.size + offset}[whence]
        return self.pos

    def _fetch(self, start: int, end: int) -> bytes:
        for attempt in range(1, 6):
            try:
                req = urllib.request.Request(self.url, headers={"Range": f"bytes={start}-{end}"})
                with urllib.request.urlopen(req, timeout=60) as resp:
                    if resp.status != 206:
                        raise RuntimeError(f"server ignored Range (status {resp.status})")
                    data = resp.read()
                if len(data) != end - start + 1:
                    raise http.client.IncompleteRead(data)
                self.requests += 1
                self.bytes += len(data)
                return data
            except (http.client.IncompleteRead, urllib.error.URLError, TimeoutError, ConnectionError) as exc:
                if attempt == 5:
                    raise
                print(f"  (retry {attempt} after {type(exc).__name__})", file=sys.stderr)
                time.sleep(2 * attempt)
        raise AssertionError("unreachable")

    def read(self, n: int = -1) -> bytes:
        n = self.size - self.pos if n < 0 else min(n, self.size - self.pos)
        parts = []
        while n > 0:
            if not (self._cache_start <= self.pos < self._cache_start + len(self._cache)):
                end = min(self.pos + BLOCK, self.size) - 1
                self._cache, self._cache_start = self._fetch(self.pos, end), self.pos
            off = self.pos - self._cache_start
            chunk = self._cache[off:off + n]
            parts.append(chunk)
            self.pos += len(chunk)
            n -= len(chunk)
        return b"".join(parts)

    def readinto(self, b) -> int:
        data = self.read(len(b))
        b[:len(data)] = data
        return len(data)


def is_safe(name: str) -> bool:
    return not name.startswith(("/", "\\")) and ".." not in name.replace("\\", "/").split("/") and ":" not in name


def select_ait_metadata(names: Sequence[str]) -> List[str]:
    patterns = [re.compile("^" + p + "$") for p in AIT_METADATA]
    return sorted(n for n in names if any(p.match(n) for p in patterns))


def ait_host_addresses(servers_yaml: str) -> Dict[str, str]:
    """host key -> default IPv4 address, read from AIT's servers.yaml (top-level keys, indented fields)."""
    hosts: Dict[str, str] = {}
    current = None
    for line in servers_yaml.splitlines():
        top = re.match(r"^([A-Za-z0-9_.-]+):\s*$", line)
        if top:
            current = top.group(1)
            continue
        field = re.match(r"^\s+default_ipv4_address:\s*(\S+)\s*$", line)
        if field and current and current not in hosts:
            hosts[current] = field.group(1)
    return hosts


def company_hosts(hosts: Iterable[str]) -> List[str]:
    """The hosts a defender owns: every listed host except AIT's simulated internet."""
    return sorted(h for h in hosts if not AIT_INTERNET_HOST.match(h))


def ait_company_hosts(scenario_dir: str) -> List[str]:
    """Company hosts of an extracted scenario, from its servers.yaml."""
    text = Path(scenario_dir, "processing", "config", "servers.yaml").read_text(encoding="utf-8")
    return company_hosts(ait_host_addresses(text))


def select_ait_logs(names: Sequence[str], hosts: Iterable[str]) -> List[str]:
    """Log members of the given hosts, plus the label file of each one that has labels."""
    allowed = set(hosts)
    patterns = [re.compile("^" + p + "$") for p in AIT_LOGS]
    chosen = []
    for name in names:
        for pattern in patterns:
            match = pattern.match(name)
            if match and match.group("host") in allowed:
                chosen.append(name)
                break
    available = set(names)
    labels = {"labels/" + n[len("gather/"):] for n in chosen} & available
    return sorted(set(chosen) | labels)


def extract(zf: zipfile.ZipFile, dest: str, members: Sequence[str], resume: bool) -> None:
    dest = os.path.abspath(dest)
    os.makedirs(dest, exist_ok=True)
    if not resume and os.listdir(dest):
        sys.exit(f"refusing: {dest} is not empty (use --resume to continue an extraction)")
    for name in members:
        target = os.path.abspath(os.path.join(dest, name))
        if not is_safe(name) or os.path.commonpath([dest, target]) != dest:
            sys.exit(f"refusing unsafe member: {name}")
        info = zf.getinfo(name)
        if resume and os.path.exists(target) and os.path.getsize(target) == info.file_size:
            print(f"already present {info.file_size:>12,} bytes  {name}")
            continue
        os.makedirs(os.path.dirname(target), exist_ok=True)
        with zf.open(info) as src, open(target, "wb") as out:   # CRC32 checked at end of stream
            while chunk := src.read(1 << 20):
                out.write(chunk)
        print(f"extracted {info.file_size:>12,} bytes  {name}")


def main(argv: Sequence[str] | None = None) -> int:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")   # member names can be non-ASCII
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("url")
    parser.add_argument("command", choices=["list", "extract", "ait-slice"])
    parser.add_argument("dest", nargs="?")
    parser.add_argument("members", nargs="*")
    parser.add_argument("--resume", action="store_true")
    args = parser.parse_args(argv)

    remote = HttpRangeFile(args.url)
    zf = zipfile.ZipFile(remote)
    names = [i.filename for i in zf.infolist() if not i.is_dir()]
    if args.command == "list":
        for info in zf.infolist():
            flag = "" if is_safe(info.filename) else "  <-- UNSAFE PATH"
            print(f"{info.file_size:>14,} {info.compress_size:>12,}  {info.filename}{flag}")
    else:
        if not args.dest:
            parser.error("dest is required")
        if args.command == "extract":
            if not args.members:
                sys.exit("nothing selected")
            extract(zf, args.dest, args.members, args.resume)
        else:
            metadata = select_ait_metadata(names)
            if "processing/config/servers.yaml" not in metadata:
                sys.exit("not an AIT-LDS v2.0 scenario (no processing/config/servers.yaml at the zip root)")
            extract(zf, args.dest, metadata, args.resume)
            servers = Path(args.dest, "processing", "config", "servers.yaml").read_text(encoding="utf-8")
            listed = ait_host_addresses(servers)
            hosts = company_hosts(listed)
            print(f"company hosts ({len(hosts)}): {', '.join(hosts)}")
            print(f"internet hosts excluded: {', '.join(sorted(set(listed) - set(hosts)))}")
            logs = select_ait_logs(names, hosts)
            total = sum(zf.getinfo(m).file_size for m in logs)
            print(f"{len(logs)} log / label members, {total:,} bytes uncompressed")
            extract(zf, args.dest, logs, resume=True)   # dest now holds the metadata
    print(f"[network] {remote.requests} range requests, {remote.bytes:,} bytes fetched of {remote.size:,}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
