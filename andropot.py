#!/usr/bin/env python3
"""
AndroPOT - Professional Reconnaissance Framework for Android/Linux
================================================================

A modular, stealth-aware reconnaissance engine that chains the standard
ProjectDiscovery toolchain into a single fault-tolerant pipeline.

Modules
-------
SubdomainModule   - passive subdomain enumeration (subfinder + crt.sh)
PortModule        - fast top-100 port sweep (naabu)
HttpModule        - live host probing with randomised User-Agents (httpx)
UrlModule         - passive + active URL harvesting (waybackurls + katana)
LeakModule        - public code leak lookup (GitHub code search)
VulnModule        - template-based vulnerability scanning (nuclei)

Usage
-----
    python3 andropot.py -d example.com
    python3 andropot.py -d example.com --deep
    python3 andropot.py -d example.com --deep --stealth
    python3 andropot.py -d example.com --modules sub,port,http

Configuration is resolved in this order:
    1. CLI flags
    2. Environment variables (ANDROPOT_BIN_PATH, ANDROPOT_LOG, ...)
    3. Built-in defaults

License: MIT. For authorised security testing only.
"""

import argparse
import json
import logging
import os
import random
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

# --------------------------------------------------------------------------
# Configuration
# --------------------------------------------------------------------------

DEFAULT_BIN_PATH = os.environ.get("ANDROPOT_BIN_PATH", "/root/go/bin")
DEFAULT_LOG_FILE = os.environ.get("ANDROPOT_LOG", "andropot.log")
DEFAULT_ANALYZER = os.environ.get(
    "ANDROPOT_ANALYZER", os.path.join(os.path.dirname(os.path.abspath(__file__)), "analyzer.py")
)

# Certificate transparency can return tens of thousands of junk names for a domain.
# Bound the active sweeps so a noisy target cannot hang the run.
DEFAULT_PORT_SCAN_LIMIT = int(os.environ.get("ANDROPOT_PORT_SCAN_LIMIT", "200"))
DEFAULT_HTTP_PROBE_LIMIT = int(os.environ.get("ANDROPOT_HTTP_PROBE_LIMIT", "500"))
# waybackurls queries a remote index per host, so it is the slowest step: keep it tight.
DEFAULT_URL_HARVEST_LIMIT = int(os.environ.get("ANDROPOT_URL_HARVEST_LIMIT", "100"))

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:122.0) Gecko/20100101 Firefox/122.0",
]

BROWSER_HEADERS = {
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "Accept-Language": "de-DE,de;q=0.9,en-US;q=0.8,en;q=0.7",
    "Accept-Encoding": "gzip, deflate, br",
    "Connection": "keep-alive",
    "Upgrade-Insecure-Requests": "1",
}

# Module registry: name -> class name. Modules with hard prerequisites are
# marked so the runner can skip them cleanly instead of erroring out.
MODULE_REGISTRY = {
    "sub": "SubdomainModule",
    "port": "PortModule",
    "http": "HttpModule",
    "url": "UrlModule",
    "leak": "LeakModule",
    "vuln": "VulnModule",
}

logger = logging.getLogger("AndroPOT")


# --------------------------------------------------------------------------
# State
# --------------------------------------------------------------------------

class ReconState:
    """Central result container, serialisable to state.json after every module."""

    def __init__(self, domain, output_dir):
        self.domain = domain
        self.output_dir = output_dir
        self.data = {
            "domain": domain,
            "started_at": datetime.now().isoformat(timespec="seconds"),
            "subdomains": [],
            "live_hosts": [],
            "open_ports": [],
            "urls": [],
            "api_endpoints": [],
            "vulns": [],
            "leaks": [],
            "errors": [],
        }
        os.makedirs(output_dir, exist_ok=True)

    # -- typed setters (dedupe automatically) ------------------------------
    def add(self, key, values):
        bucket = self.data.setdefault(key, [])
        if not isinstance(bucket, list):
            bucket = self.data[key] = list(bucket)
        for value in values:
            if value and value not in bucket:
                bucket.append(value)

    def extend(self, key, values):
        bucket = self.data.setdefault(key, [])
        if not isinstance(bucket, list):
            bucket = self.data[key] = list(bucket)
        bucket.extend([v for v in values if v])

    def count(self, key):
        return len(self.data.get(key, []))

    def save(self):
        path = os.path.join(self.output_dir, "state.json")
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(self.data, fh, indent=2)
        os.replace(tmp, path)
        return path


# --------------------------------------------------------------------------
# Command execution
# --------------------------------------------------------------------------

class Runner:
    """Executes shell commands with timeout, logging and captured output."""

    def __init__(self, timeout=300):
        self.timeout = timeout

    def run(self, cmd):
        logger.info("exec: %s", cmd)
        try:
            proc = subprocess.run(
                cmd,
                shell=True,
                capture_output=True,
                text=True,
                timeout=self.timeout,
            )
        except subprocess.TimeoutExpired:
            logger.error("timeout after %ss: %s", self.timeout, cmd)
            return ""
        except Exception as exc:  # noqa: BLE001 - runner must never crash the pipeline
            logger.error("exec failed (%s): %s", exc, cmd)
            return ""

        if proc.returncode != 0:
            # Tools write usage/hint text to stderr; log at debug to keep noise down.
            logger.debug("non-zero exit (%s) for %s :: %s", proc.returncode, cmd, proc.stderr.strip()[:300])
        return proc.stdout or ""

    def run_to_file(self, cmd, path):
        logger.info("exec -> %s : %s", path, cmd)
        try:
            with open(path, "w", encoding="utf-8") as fh:
                proc = subprocess.run(cmd, shell=True, stdout=fh, stderr=subprocess.DEVNULL, timeout=self.timeout)
            return proc.returncode == 0
        except Exception as exc:  # noqa: BLE001
            logger.error("exec->file failed (%s): %s", exc, cmd)
            return False

    @staticmethod
    def read_lines(path):
        if not os.path.exists(path):
            return []
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            return [line.strip() for line in fh if line.strip()]

    @staticmethod
    def write_lines(path, lines):
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("\n".join(sorted(set(lines))) + ("\n" if lines else ""))


# --------------------------------------------------------------------------
# Modules
# --------------------------------------------------------------------------

class BaseModule:
    name = "base"
    requires = ()  # keys that must be non-empty before this module runs

    def __init__(self, state, runner):
        self.state = state
        self.runner = runner

    def ready(self):
        for key in self.requires:
            if not self.state.data.get(key):
                logger.info("[%s] skipped: no '%s' data", self.name, key)
                return False
        return True

    def run(self):
        raise NotImplementedError


class SubdomainModule(BaseModule):
    name = "sub"

    def run(self):
        if not self.ready():
            return
        target = self.state.domain
        out = self.state.output_dir

        subs = []
        subs += self.runner.read_lines(
            os.path.join(out, "subfinder.txt")
        ) if self.runner.run_to_file(
            f"{DEFAULT_BIN_PATH}/subfinder -d {target} -silent",
            os.path.join(out, "subfinder.txt"),
        ) else []

        # crt.sh certificate transparency lookup (raw JSON -> common_name)
        self.runner.run_to_file(
            f"curl -s --max-time 45 'https://crt.sh/?q={target}&output=json'",
            os.path.join(out, "crt_raw.json"),
        )
        subs.extend(self._parse_crt(os.path.join(out, "crt_raw.json")))

        # The apex domain is never a "subdomain" but must be probed too.
        subs.append(target)
        self.state.add("subdomains", subs)
        self.runner.write_lines(os.path.join(out, "subdomains.txt"), self.state.data["subdomains"])
        logger.info("[sub] %d subdomains", self.state.count("subdomains"))

    @staticmethod
    def _parse_crt(path):
        """crt.sh returns a JSON array; tolerate HTML/empty fallbacks."""
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                payload = fh.read().strip()
        except OSError:
            return []
        if not payload or not payload.startswith("["):
            return []
        try:
            records = json.loads(payload)
        except json.JSONDecodeError:
            return []
        names = set()
        for record in records:
            if not isinstance(record, dict):
                continue
            common = record.get("common_name") or ""
            names.update(part for part in common.split("\n") if part)
            names.update(record.get("name_value", "").split("\n"))
        return [n.strip().lower() for n in names if n and "*" not in n]


class PortModule(BaseModule):
    name = "port"
    requires = ("subdomains",)

    # Common service ports worth sweeping when a fast scanner is unavailable.
    FALLBACK_PORTS = (
        21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995,
        1433, 1521, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 8888, 9200, 27017,
    )

    def run(self):
        if not self.ready():
            return
        out = self.state.output_dir

        # Bound the input list before handing it to any scanner - certificate
        # transparency can return tens of thousands of junk names.
        targets = self._scan_targets()
        scan_path = os.path.join(out, "port_scan_targets.txt")
        self.runner.write_lines(scan_path, targets)

        raw_path = os.path.join(out, "ports_raw.txt")

        # naabu's SYN scan needs raw sockets, which proot does not grant. Try it,
        # then fall back to a pure-Python connect scan so the module still yields data.
        self.runner.run_to_file(
            f"{DEFAULT_BIN_PATH}/naabu -list {scan_path} -top-ports 100 -scan-type CONNECT -silent",
            raw_path,
        )
        lines = self.runner.read_lines(raw_path)

        if not lines:
            logger.info("[port] naabu produced nothing (raw sockets unavailable) - using python connect scan")
            lines = self._connect_scan(targets)

        self.state.add("open_ports", lines)
        logger.info("[port] %d open port entries (scanned %d hosts)", self.state.count("open_ports"), len(targets))

    def _scan_targets(self):
        """Cap the sweep so wildcard noise cannot hang the run.

        Certificate-transparency sources return thousands of junk names for some
        domains; scanning all of them would take hours. Prefer the apex domain and
        the first N names, which keeps the sweep bounded and useful.
        """
        hosts = list(self.state.data["subdomains"])
        apex = self.state.domain
        ordered = ([apex] if apex in hosts else []) + [h for h in hosts if h != apex]
        return ordered[:getattr(self, "limit", DEFAULT_PORT_SCAN_LIMIT)]

    def _connect_scan(self, hosts, timeout=3):
        import socket
        from concurrent.futures import ThreadPoolExecutor

        results = []

        def probe(host):
            found = []
            for port in self.FALLBACK_PORTS:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(timeout)
                    if sock.connect_ex((host, port)) == 0:
                        found.append(f"{host}:{port}")
                    sock.close()
                except Exception:  # noqa: BLE001 - DNS failures are expected for dead subdomains
                    continue
            return found

        with ThreadPoolExecutor(max_workers=64) as pool:
            for found in pool.map(probe, hosts):
                results.extend(found)
        return results


class HttpModule(BaseModule):
    name = "http"
    requires = ("subdomains",)

    def run(self):
        if not self.ready():
            return
        out = self.state.output_dir
        # Write the bounded probe set to its own file so the full subdomain
        # list (and the port module's input) stays intact.
        probe_path = os.path.join(out, "probe_targets.txt")
        targets = self._probe_targets()
        self.runner.write_lines(probe_path, targets)

        ua = random.choice(USER_AGENTS)
        out_path = os.path.join(out, "live.txt")

        # httpx v1.6+ has no -ua/-user-agent flag; pass the identity as a header.
        headers = " ".join(f"-H '{k}: {v}'" for k, v in {**BROWSER_HEADERS, "User-Agent": ua}.items())
        self.runner.run_to_file(
            f"{DEFAULT_BIN_PATH}/httpx -list {probe_path} {headers} -silent -status-code -title -tech-detect",
            out_path,
        )
        lines = self.runner.read_lines(out_path)
        # Keep the URL (first token) so downstream tools stay happy.
        hosts = [line.split()[0] for line in lines if line]
        self.state.add("live_hosts", hosts)
        self.runner.write_lines(out_path, hosts)
        logger.info("[http] %d live hosts (probed %d)", self.state.count("live_hosts"), len(targets))

    def _probe_targets(self):
        """Same bounding rule as the port module, applied to HTTP probing."""
        hosts = list(self.state.data["subdomains"])
        apex = self.state.domain
        ordered = ([apex] if apex in hosts else []) + [h for h in hosts if h != apex]
        return ordered[:getattr(self, "limit", DEFAULT_HTTP_PROBE_LIMIT)]


class UrlModule(BaseModule):
    name = "url"
    requires = ("subdomains",)

    def __init__(self, state, runner, deep=False):
        super().__init__(state, runner)
        self.deep = deep

    def run(self):
        if not self.ready():
            return
        out = self.state.output_dir

        # Bound the passive harvest too - waybackurls queries per host, so the
        # full certificate-transparency list would take far too long.
        targets = self._harvest_targets()
        harvest_path = os.path.join(out, "url_harvest_targets.txt")
        self.runner.write_lines(harvest_path, targets)

        self.runner.run_to_file(
            f"cat {harvest_path} | timeout 180 {DEFAULT_BIN_PATH}/waybackurls",
            os.path.join(out, "urls_passive.txt"),
        )
        if not self.runner.read_lines(os.path.join(out, "urls_passive.txt")):
            logger.warning("[url] waybackurls returned nothing - some index hosts may be unreachable")
        urls = self.runner.read_lines(os.path.join(out, "urls_passive.txt"))

        if self.deep and self.state.data.get("live_hosts"):
            live_path = os.path.join(out, "live.txt")
            ua = random.choice(USER_AGENTS)
            headers = " ".join(f"-H '{k}: {v}'" for k, v in {**BROWSER_HEADERS, "User-Agent": ua}.items())
            self.runner.run_to_file(
                f"{DEFAULT_BIN_PATH}/katana -list {live_path} -silent -jc {headers}",
                os.path.join(out, "urls_active.txt"),
            )
            urls += self.runner.read_lines(os.path.join(out, "urls_active.txt"))

        self.state.add("urls", urls)

        api_pattern = ("/api/", "/v1/", "/v2/", "/graphql", "/rest/")
        apis = [u for u in self.state.data["urls"] if any(p in u for p in api_pattern)]
        self.state.add("api_endpoints", apis)
        self.runner.write_lines(os.path.join(out, "urls.txt"), self.state.data["urls"])
        self.runner.write_lines(os.path.join(out, "api_endpoints.txt"), self.state.data["api_endpoints"])
        logger.info(
            "[url] %d urls, %d api endpoints (harvested %d hosts)",
            self.state.count("urls"),
            self.state.count("api_endpoints"),
            len(targets),
        )

    def _harvest_targets(self):
        hosts = list(self.state.data["subdomains"])
        apex = self.state.domain
        ordered = ([apex] if apex in hosts else []) + [h for h in hosts if h != apex]
        return ordered[:getattr(self, "limit", DEFAULT_URL_HARVEST_LIMIT)]


class LeakModule(BaseModule):
    name = "leak"

    def run(self):
        if not self.ready():
            return
        target = self.state.domain
        raw = self.runner.run(
            f"curl -s --max-time 30 -H 'Accept: application/vnd.github+json' "
            f"'https://api.github.com/search/code?q=%22{target}%22'"
        )
        # Unauthenticated GitHub code search returns a message object; extract
        # whatever repository URLs are present so the report stays honest.
        found = []
        try:
            payload = json.loads(raw) if raw.strip().startswith("{") else {}
        except json.JSONDecodeError:
            payload = {}
        for item in payload.get("items", []) or []:
            html = item.get("html_url")
            if html:
                found.append(html)
        self.state.add("leaks", found)
        self.runner.write_lines(os.path.join(self.state.output_dir, "leaks.txt"), found)
        logger.info("[leak] %d code references", self.state.count("leaks"))


class VulnModule(BaseModule):
    name = "vuln"
    requires = ("live_hosts",)

    def __init__(self, state, runner, stealth=False):
        super().__init__(state, runner)
        self.stealth = stealth

    def run(self):
        if not self.ready():
            return
        rate_limit = "10" if self.stealth else "50"
        live_path = os.path.join(self.state.output_dir, "live.txt")
        out_path = os.path.join(self.state.output_dir, "vulns.txt")
        ua = random.choice(USER_AGENTS)
        # nuclei also takes custom headers via -H (no -ua flag in v3).
        self.runner.run_to_file(
            f"{DEFAULT_BIN_PATH}/nuclei -l {live_path} -silent -rl {rate_limit} "
            f"-H 'User-Agent: {ua}' -stats",
            out_path,
        )
        lines = self.runner.read_lines(out_path)
        self.state.add("vulns", lines)
        logger.info("[vuln] %d findings", self.state.count("vulns"))


MODULES = {
    "sub": SubdomainModule,
    "port": PortModule,
    "http": HttpModule,
    "url": UrlModule,
    "leak": LeakModule,
    "vuln": VulnModule,
}

# Fixed execution order - later modules depend on earlier keys.
EXECUTION_ORDER = ["sub", "port", "http", "url", "leak", "vuln"]


# --------------------------------------------------------------------------
# Pipeline
# --------------------------------------------------------------------------

def build_pipeline(selected, state, runner, deep, stealth, port_limit, http_limit, url_limit):
    instances = []
    for name in EXECUTION_ORDER:
        if selected and name not in selected:
            continue
        cls = MODULES[name]
        if name == "url":
            instance = cls(state, runner, deep=deep)
            instance.limit = url_limit
            instances.append(instance)
        elif name == "vuln":
            instances.append(cls(state, runner, stealth=stealth))
        elif name == "port":
            instance = cls(state, runner)
            instance.limit = port_limit
            instances.append(instance)
        elif name == "http":
            instance = cls(state, runner)
            instance.limit = http_limit
            instances.append(instance)
        else:
            instances.append(cls(state, runner))
    return instances


def run_pipeline(instances, state, parallel=False):
    if not parallel:
        for module in instances:
            try:
                module.run()
            except Exception as exc:  # noqa: BLE001 - a module must never kill the run
                logger.error("[%s] crashed: %s", module.name, exc)
                state.data["errors"].append(f"{module.name}: {exc}")
            state.save()
        return

    # Parallel mode: independent branches run together. `port`/`http`/`url`/`leak`
    # only need `subdomains`, so they are safe to fan out once `sub` completes.
    with ThreadPoolExecutor(max_workers=4) as pool:
        futures = {pool.submit(_guarded, module, state): module.name for module in instances}
        for future in as_completed(futures):
            name = futures[future]
            try:
                future.result()
            except Exception as exc:  # noqa: BLE001
                logger.error("[%s] crashed: %s", name, exc)
                state.data["errors"].append(f"{name}: {exc}")
            state.save()


def _guarded(module, state):
    module.run()


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def setup_logging(log_file, verbose):
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(message)s",
        handlers=[
            logging.FileHandler(log_file, encoding="utf-8"),
            logging.StreamHandler(sys.stdout),
        ],
        force=True,
    )


def parse_args():
    parser = argparse.ArgumentParser(
        prog="andropot",
        description="AndroPOT - modular reconnaissance framework for Android/Linux",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "examples:\n"
            "  python3 andropot.py -d example.com\n"
            "  python3 andropot.py -d example.com --deep --stealth\n"
            "  python3 andropot.py -d example.com --modules sub,http,vuln\n"
        ),
    )
    parser.add_argument("-d", "--domain", required=True, help="target domain")
    parser.add_argument("-o", "--output", default=None, help="output directory")
    parser.add_argument("--deep", action="store_true", help="enable active crawling + API extraction")
    parser.add_argument("--stealth", action="store_true", help="rate-limit and rotate identities")
    parser.add_argument("--modules", default=None, help="comma list: sub,port,http,url,leak,vuln")
    parser.add_argument("--parallel", action="store_true", help="fan out independent modules")
    parser.add_argument("--timeout", type=int, default=300, help="per-command timeout (s)")
    parser.add_argument("--port-limit", type=int, default=DEFAULT_PORT_SCAN_LIMIT,
                        help="max hosts to port-scan (default 200)")
    parser.add_argument("--http-limit", type=int, default=DEFAULT_HTTP_PROBE_LIMIT,
                        help="max hosts to probe over HTTP (default 500)")
    parser.add_argument("--url-limit", type=int, default=DEFAULT_URL_HARVEST_LIMIT,
                        help="max hosts to harvest URLs from (default 100)")
    parser.add_argument("--log", default=DEFAULT_LOG_FILE, help="log file path")
    parser.add_argument("--no-analyzer", action="store_true", help="skip the post-scan analyzer")
    parser.add_argument("-v", "--verbose", action="store_true", help="debug logging")
    return parser.parse_args()


def main():
    args = parse_args()
    setup_logging(args.log, args.verbose)

    output_dir = args.output or os.path.join("recon_results", args.domain)
    state = ReconState(args.domain, output_dir)
    runner = Runner(timeout=args.timeout)

    selected = {m.strip() for m in args.modules.split(",")} if args.modules else None
    if selected:
        unknown = selected - set(MODULES)
        if unknown:
            logger.error("unknown modules: %s (valid: %s)", ", ".join(sorted(unknown)), ", ".join(EXECUTION_ORDER))
            sys.exit(2)

    logger.info("AndroPOT :: target=%s out=%s deep=%s stealth=%s",
                args.domain, output_dir, args.deep, args.stealth)

    pipeline = build_pipeline(
        selected, state, runner, args.deep, args.stealth,
        args.port_limit, args.http_limit, args.url_limit,
    )
    run_pipeline(pipeline, state, parallel=args.parallel)

    summary = {k: state.count(k) for k in
               ("subdomains", "live_hosts", "open_ports", "urls", "api_endpoints", "vulns", "leaks")}
    logger.info("done :: %s", json.dumps(summary))
    state.save()

    print("\n" + "=" * 62)
    print(f"  AndroPOT recon finished :: {args.domain}")
    print("=" * 62)
    for key, value in summary.items():
        print(f"  {key:<14} {value}")
    if state.data["errors"]:
        print(f"  {'errors':<14} {len(state.data['errors'])}")
    print(f"\n  artifacts : {output_dir}/")
    print(f"  state     : {output_dir}/state.json")
    print(f"  log       : {args.log}")

    analyzer = os.environ.get("ANDROPOT_ANALYZER", DEFAULT_ANALYZER)
    if not args.no_analyzer and os.path.exists(analyzer) and os.path.isfile(analyzer):
        logger.info("running analyzer: %s", analyzer)
        subprocess.run([sys.executable, analyzer, "-d", args.domain, "-o", output_dir])


if __name__ == "__main__":
    main()
