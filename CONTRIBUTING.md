# Contributing to Nightcrawler

Thanks for your interest in contributing! Nightcrawler is an autonomous penetration testing agent that runs on a phone — contributions from both security professionals and general software engineers are welcome.

## Getting Started

### No hardware needed

You can develop and test without a phone or any pentest hardware:

```bash
git clone https://github.com/garagehq/nightcrawler.git
cd nightcrawler

# Dry-run mode: uses a mock Kali server, no real commands executed
NC_DRY_RUN=1 python3 main.py
```

### Running tests

```bash
pip3 install pytest playwright
python3 -m playwright install chromium

# Unit and API tests
python3 -m pytest tests/

# UI tests (requires the webui to be running)
python3 tests/test_webui.py
```

## Areas Where Help is Needed

### Beginner-friendly

- **Documentation** — tutorials, setup guides for different phones, better inline comments
- **CVE database** — adding entries to `data/cve_exploits.json` (just JSON editing)
- **Test coverage** — more unit tests, especially edge cases in `agent/output_parser.py`

### Intermediate

- **New playbooks** — multi-step attack chains in `data/playbooks.json` (see [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md#adding-a-new-playbook) for the format)
- **Output parser** — teaching the parser to extract data from new tool outputs
- **Web UI** — dashboard improvements, new visualizations, mobile UX
- **Adapter support** — testing with more USB WiFi chipsets, documenting what works

### Advanced

- **Model fine-tuning** — using captured training data to improve command format compliance
- **New inference backends** — Vulkan, NNAPI, or other mobile GPU APIs
- **Scope proxy hardening** — additional validation rules, fuzzing
- **Kernel modules** — WiFi driver support for more chipsets

## How to Contribute

1. **Fork the repo** and create a feature branch
2. **Make your changes** — keep commits focused and well-described
3. **Test** — run `NC_DRY_RUN=1 python3 main.py` at minimum, add tests if applicable
4. **Open a PR** — describe what you changed and why

### Code Style

- Python 3.9+ with standard library preferred (runs on a phone — minimize dependencies)
- No type annotations required (but welcomed on new code)
- Keep functions short and focused
- No external linters enforced — just be consistent with surrounding code

### Commit Messages

- Use conventional prefixes: `feat:`, `fix:`, `docs:`, `refactor:`, `test:`
- Keep the first line under 72 characters
- Explain *why*, not just *what*

## Key Files for Contributors

| File | What it does | Good first contribution |
|------|-------------|----------------------|
| `data/cve_exploits.json` | CVE-to-command mappings | Add entries for new services |
| `data/playbooks.json` | Multi-step attack chains | Add playbooks for new services |
| `agent/output_parser.py` | Extracts data from tool output | Handle new tool output formats |
| `prompts/*.md` | LLM prompt templates | Improve prompt wording |
| `webui/templates/index.html` | Dashboard UI | UI improvements |
| `tests/` | Test suites | More coverage |

## Important Notes

- **Safety first** — all playbooks must be non-destructive (enumeration and credential testing only, nothing that crashes hosts)
- **Stealth matters** — never use aggressive scan timing (nmap -T3 or above)
- **Scope enforcement** — never bypass or weaken the scope proxy
- **Legal** — this tool is for authorized penetration testing only. Don't include capabilities designed for unauthorized access.

## Questions?

Open an issue on GitHub. There's no formal code of conduct yet — just be respectful and constructive.
