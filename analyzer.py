#!/usr/bin/env python3
"""
AndroPOT Analyzer - turns raw recon artifacts into a prioritised report.

Reads the JSON state produced by andropot.py, ranks the findings, and emits
an Obsidian-friendly Markdown report. An optional LLM step (Ollama or Gemini)
adds a short triage note; when no model is configured the analyzer degrades
gracefully to a deterministic summary.

Usage
-----
    python3 analyzer.py -d example.com -o recon_results/example.com
    ANDROPOT_VAULT=/path/to/vault python3 analyzer.py -d example.com -o out
"""

import argparse
import json
import os
import subprocess
import sys
from datetime import datetime

DEFAULT_VAULT = os.environ.get("ANDROPOT_VAULT", "/mnt/sdcard/Documents/Ki-Brain")
REPORT_SUBFOLDER = "Recon_Reports"

# Severity ranking for the deterministic triage note.
SEVERITY_KEYWORDS = {
    "critical": ("critical", "rce", "remote code", "sql injection", "sqli", "unauth", "authentication bypass"),
    "high": ("high", "xss", "ssrf", "lfi", "rfi", "xxe", "deserial", "default credential", "exposure"),
    "medium": ("medium", "csrf", "open redirect", "clickjack", "cors", "header", "information disclosure"),
    "low": ("low", "info", "version", "banner", "debug", "listing"),
}


def load_state(output_dir):
    path = os.path.join(output_dir, "state.json")
    if not os.path.exists(path):
        return None
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except json.JSONDecodeError:
        return None


def read_lines(path):
    if not os.path.exists(path):
        return []
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        return [line.strip() for line in fh if line.strip()]


def rank_finding(text):
    lowered = text.lower()
    for severity, needles in SEVERITY_KEYWORDS.items():
        if any(needle in lowered for needle in needles):
            return severity
    return "info"


def group_vulns(vulns):
    buckets = {}
    for item in vulns:
        severity = rank_finding(item)
        buckets.setdefault(severity, []).append(item)
    return buckets


def summarise(state):
    lines = []
    lines.append(f"Domain under test : {state.get('domain')}")
    lines.append("")
    lines.append("Asset counts")
    lines.append(f"  subdomains     : {len(state.get('subdomains', []))}")
    lines.append(f"  live hosts     : {len(state.get('live_hosts', []))}")
    lines.append(f"  open port rows : {len(state.get('open_ports', []))}")
    lines.append(f"  harvested urls : {len(state.get('urls', []))}")
    lines.append(f"  api endpoints  : {len(state.get('api_endpoints', []))}")
    lines.append(f"  leak refs      : {len(state.get('leaks', []))}")
    lines.append(f"  nuclei rows    : {len(state.get('vulns', []))}")
    buckets = group_vulns(state.get("vulns", []))
    if buckets:
        lines.append("")
        lines.append("Severity breakdown")
        for severity in ("critical", "high", "medium", "low", "info"):
            if buckets.get(severity):
                lines.append(f"  {severity:<8} : {len(buckets[severity])}")
    if state.get("errors"):
        lines.append("")
        lines.append("Module errors")
        lines.extend(f"  - {err}" for err in state["errors"][:10])
    return "\n".join(lines)


def build_triage_note(state):
    """Deterministic triage text - always available, no external service needed."""
    live = state.get("live_hosts", [])
    apis = state.get("api_endpoints", [])
    vuln_buckets = group_vulns(state.get("vulns", []))

    notes = []
    if live:
        notes.append(
            f"{len(live)} live hosts confirmed. Prioritise the hosts that expose "
            "authentication surfaces or non-standard ports."
        )
    if apis:
        notes.append(
            f"{len(apis)} API-looking endpoints were extracted. Check them for "
            "broken object-level authorisation (BOLA) and unauthenticated reads."
        )
    if vuln_buckets.get("critical") or vuln_buckets.get("high"):
        notes.append(
            "High/critical template matches are present. Re-verify each one manually "
            "before reporting - nuclei templates can false-positive on custom stacks."
        )
    else:
        notes.append(
            "No high-severity template matches. Treat the target as hardened at the "
            "template level; move to parameter-level testing on the extracted endpoints."
        )
    if state.get("leaks"):
        notes.append(
            f"{len(state['leaks'])} public code references mention this domain. "
            "Search those repositories for credentials and internal hostnames."
        )
    return " ".join(notes) if notes else "No actionable findings in this pass."


def llm_triage(state, timeout=90):
    """Optional: ask a local Ollama model for triage. Returns '' when unavailable."""
    model = os.environ.get("ANDROPOT_LLM_MODEL", "qwen2.5-coder:14b")
    base = os.environ.get("ANDROPOT_LLM_URL", "http://127.0.0.1:11434/api/generate")

    payload = {
        "model": model,
        "prompt": (
            "You are a bug-bounty triage analyst. Given this reconnaissance summary, "
            "list the three highest-value next actions, one line each, no preamble.\n\n"
            + summarise(state)
        ),
        "stream": False,
    }
    try:
        proc = subprocess.run(
            ["curl", "-s", "--max-time", str(timeout), "-X", "POST", base,
             "-H", "Content-Type: application/json", "-d", json.dumps(payload)],
            capture_output=True, text=True, timeout=timeout + 10,
        )
        if proc.returncode != 0 or not proc.stdout.strip():
            return ""
        data = json.loads(proc.stdout)
        return (data.get("response") or "").strip()
    except Exception as exc:  # noqa: BLE001 - LLM is an optional enhancement
        return f"(LLM triage unavailable: {exc})"


def render_markdown(domain, state, triage_note, llm_note):
    now = datetime.now().strftime("%Y-%m-%d %H:%M")
    vuln_buckets = group_vulns(state.get("vulns", []))

    def code_block(items, limit=None):
        if not items:
            return "_(none)_"
        shown = items if limit is None else items[:limit]
        body = "\n".join(shown)
        if limit and len(items) > limit:
            body += f"\n... and {len(items) - limit} more"
        return f"```\n{body}\n```"

    parts = []
    parts.append(f"# Recon Report: {domain}")
    parts.append(f"**Generated:** {now}  ")
    parts.append(f"**Tool:** AndroPOT  ")
    parts.append(f"**Artifacts:** `{state.get('_output_dir', '')}`")
    parts.append("")
    parts.append("## Triage")
    parts.append(f"> {triage_note}")
    if llm_note:
        parts.append("")
        parts.append("### LLM assessment")
        parts.append(llm_note)
    parts.append("")
    parts.append("## Summary")
    parts.append(f"- **Subdomains:** {len(state.get('subdomains', []))}")
    parts.append(f"- **Live hosts:** {len(state.get('live_hosts', []))}")
    parts.append(f"- **Open port rows:** {len(state.get('open_ports', []))}")
    parts.append(f"- **Harvested URLs:** {len(state.get('urls', []))}")
    parts.append(f"- **API endpoints:** {len(state.get('api_endpoints', []))}")
    parts.append(f"- **Code leak refs:** {len(state.get('leaks', []))}")
    parts.append(f"- **Nuclei rows:** {len(state.get('vulns', []))}")
    parts.append("")
    parts.append("## Findings")
    parts.append("### Live hosts")
    parts.append(code_block(state.get("live_hosts", []), limit=60))
    parts.append("")
    parts.append("### API endpoints")
    parts.append(code_block(state.get("api_endpoints", []), limit=60))
    parts.append("")
    parts.append("### Vulnerabilities by severity")
    for severity in ("critical", "high", "medium", "low", "info"):
        items = vuln_buckets.get(severity)
        if not items:
            continue
        parts.append(f"**{severity.upper()}**")
        parts.append(code_block(items, limit=40))
        parts.append("")
    parts.append("### Open ports")
    parts.append(code_block(state.get("open_ports", []), limit=60))
    parts.append("")
    parts.append("### Public code references")
    parts.append(code_block(state.get("leaks", []), limit=30))
    parts.append("")
    if state.get("errors"):
        parts.append("## Module errors")
        parts.append(code_block(state["errors"], limit=20))
        parts.append("")
    parts.append("---")
    parts.append("*Generated by AndroPOT Analyzer*")

    return "\n".join(parts)


def main():
    parser = argparse.ArgumentParser(description="AndroPOT analyzer")
    parser.add_argument("-d", "--domain", required=True)
    parser.add_argument("-o", "--output", required=True, help="recon output directory")
    parser.add_argument("--vault", default=DEFAULT_VAULT, help="Obsidian vault root")
    parser.add_argument("--no-llm", action="store_true", help="skip the optional LLM triage")
    args = parser.parse_args()

    state = load_state(args.output)
    if state is None:
        print(f"[!] no state.json found in {args.output} - run andropot.py first")
        sys.exit(1)

    state["_output_dir"] = args.output

    triage_note = build_triage_note(state)
    llm_note = "" if args.no_llm else llm_triage(state)

    report = render_markdown(args.domain, state, triage_note, llm_note)

    report_dir = os.path.join(args.vault, REPORT_SUBFOLDER)
    os.makedirs(report_dir, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d")
    report_path = os.path.join(report_dir, f"{args.domain}_{stamp}.md")

    with open(report_path, "w", encoding="utf-8") as fh:
        fh.write(report)

    print(f"[+] triage   : {triage_note[:100]}")
    print(f"[+] report   : {report_path}")
    if llm_note:
        print(f"[+] llm      : {llm_note[:100]}")


if __name__ == "__main__":
    main()
