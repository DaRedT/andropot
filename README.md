# AndroPOT

**A modular, stealth-aware reconnaissance framework that runs on Android.**

AndroPOT chains the standard ProjectDiscovery toolchain into a single fault-tolerant
pipeline, adds identity rotation and rate limiting, and writes structured JSON state
after every module so a run can survive a crash and be analysed later.

It was built to run on a tablet: proot/Ubuntu on Android, no root, no raw sockets.

---

## Why this exists

Kali-native recon wrappers assume root, raw sockets and a desktop CPU. On Android
under proot none of that is true, and the naive version of this tool silently produced
empty reports because each tool failed in a different way. AndroPOT fixes the plumbing:

- Every command runs under a timeout and is logged; a failure never kills the pipeline.
- Each module declares its prerequisites and is skipped cleanly when they are missing.
- `naabu` needs raw sockets that proot refuses, so the port module falls back to a
  pure-Python connect scan.
- `httpx` and `nuclei` have no `-ua` flag in current releases, so identities are passed
  as `-H` headers instead.

---

## Features

| Module | Tool | What it does |
|---|---|---|
| `sub` | subfinder + crt.sh | passive subdomain enumeration + certificate transparency |
| `port` | naabu / python fallback | top-100 port sweep |
| `http` | httpx | live host probing with rotated User-Agents |
| `url` | waybackurls + katana | passive URL history + active crawl, API endpoint extraction |
| `leak` | GitHub code search | public code references mentioning the domain |
| `vuln` | nuclei | template-based vulnerability scanning |

Plus:

- **Stealth mode** — rate limiting and identity rotation to reduce WAF flagging.
- **JSON state** — `state.json` is written after every module, so partial runs are usable.
- **Analyzer** — ranks findings by severity and emits an Obsidian-friendly Markdown report.
- **Optional LLM triage** — calls a local Ollama model when `ANDROPOT_LLM_MODEL` is set.

---

## Install

Requirements: Python 3.9+, Go 1.21+, and the ProjectDiscovery tools.

```bash
# 1. Go toolchain
sudo apt update && sudo apt install -y golang git curl

# 2. Recon tools
export GOPATH=$HOME/go
export PATH=$PATH:$GOPATH/bin
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/tomnomnom/waybackurls@latest
go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
```

On Android under proot, point the tool at the binaries:

```bash
export ANDROPOT_BIN_PATH=$HOME/go/bin
```

---

## Usage

```bash
# Basic pass
python3 andropot.py -d example.com

# Active crawl + API extraction, rate-limited
python3 andropot.py -d example.com --deep --stealth

# Run only specific modules
python3 andropot.py -d example.com --modules sub,http,vuln

# Fan out independent modules
python3 andropot.py -d example.com --parallel

# Skip the report step
python3 andropot.py -d example.com --no-analyzer
```

### Flags

| Flag | Meaning |
|---|---|
| `-d, --domain` | target domain (required) |
| `-o, --output` | output directory (default `recon_results/<domain>`) |
| `--deep` | active crawling and API endpoint extraction |
| `--stealth` | rate-limit requests and rotate identities |
| `--modules` | comma list: `sub,port,http,url,leak,vuln` |
| `--parallel` | run independent modules concurrently |
| `--timeout` | per-command timeout in seconds (default 300) |
| `--log` | log file path |
| `--quick` | fast pass: sub+http only, small limits (Android-friendly) |
| `--no-resume` | ignore existing state.json and start fresh |
| `--wayback-timeout` | hard timeout for waybackurls (default 180s) |
| `--no-analyzer` | skip report generation |
| `-v` | debug logging |

### Environment variables

| Variable | Default | Purpose |
|---|---|---|
| `ANDROPOT_BIN_PATH` | `/root/go/bin` | directory holding the Go tools |
| `ANDROPOT_LOG` | `andropot.log` | log file |
| `ANDROPOT_ANALYZER` | `analyzer.py` next to the script | analyzer path |
| `ANDROPOT_VAULT` | `/mnt/sdcard/Documents/Ki-Brain` | Obsidian vault root for reports |
| `ANDROPOT_LLM_MODEL` | `qwen2.5-coder:14b` | Ollama model for triage (optional) |
| `ANDROPOT_LLM_URL` | `http://127.0.0.1:11434/api/generate` | Ollama endpoint |

---

## Output

```
recon_results/example.com/
  state.json          structured results, rewritten after each module
  subdomains.txt      deduplicated host list (apex included)
  live.txt            responding URLs
  ports_raw.txt       open port rows
  urls.txt            harvested URLs
  api_endpoints.txt   URLs matching API patterns
  vulns.txt           nuclei findings
  leaks.txt           public code references
  andropot.log        full command log
```

The analyzer writes a Markdown report to `<vault>/Recon_Reports/<domain>_<date>.md`.

---

## Troubleshooting

**Everything returns zero.**
Check the log: `python3 andropot.py -d <domain> -v`. The most common cause is the Go
tools not being on the path expected by `ANDROPOT_BIN_PATH`.

**Port scan yields nothing.**
`naabu` requires raw sockets. Proot does not grant them, so the module falls back to a
Python connect scan. On a real Linux host, install `naabu` and it will be used directly.

**Live hosts are zero but subdomains exist.**
Verify the target resolves: `curl -sI https://<domain>`. A dead or firewalled target
produces a legitimate zero.

---

## Legal

This tool is for **authorised security testing only** — your own infrastructure, or
targets you have written permission to assess (bug bounty programs, pentest engagements).

Reconnaissance against systems you do not own or are not authorised to test is illegal
in most jurisdictions. The authors accept no responsibility for misuse.

---

## License

MIT
