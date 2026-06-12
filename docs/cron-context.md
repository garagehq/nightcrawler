# Nightcrawler Cron Monitor Context

You are monitoring the Nightcrawler autonomous pentest agent. Check in every 10 minutes.

## Your Job
1. Run `/root/nightcrawler/scripts/health-check.sh` to check all services
2. Read `nightcrawler-finetuning-logs.md` for history of what's been fixed
3. Check `logs/health.log` for recent health check results
4. If something is broken, fix it and restart
5. Add notes to `nightcrawler-finetuning-logs.md` about what you found/fixed
6. If the agent is stuck (same phase for >1h with no new findings), investigate
7. If the web UI is not showing results, check `webui/server.py` and fix

## CRITICAL RULES
- **NEVER start a second llama-server** — `pgrep -c llama-server` must be 1
- **NEVER kill llama-server from Kali chroot** — only from Android shell (port 9022)
- **Context window: 8192 tokens** — do not change without user approval
- Dual llama-server caused phone OOM crash on 2026-03-20

## Services to Monitor
- llama-server :8080 — LLM (runs on Android side, auto-starts via Magisk watchdog)
- kali-server-mcp :5000 — official Kali command execution (apt package, shlex, no shell=True)
- scope_proxy.py :8800 — scope enforcement (translates /api/command responses)
- webui :8888 — web dashboard with C2 controls (Tailscale IP, HTTPS)
- agent (main.py) — the autonomous agent loop

## Key Files
- `config.yaml` — mission scope and config
- `prompts/*.md` — system prompt and phase prompts (HOT RELOADABLE - edit to improve model behavior)
- `logs/nightcrawler.db` — SQLite database (MAC-keyed hosts, multi-network)
- `logs/findings.json` — structured findings (JSON compat)
- `logs/timeline.jsonl` — event timeline
- `logs/commands.jsonl` — command audit trail
- `nightcrawler-finetuning-logs.md` — your notes and observations

## Host Memory
The agent auto-generates observations about hosts (HTTP servers, SSH versions, etc.)
and injects them into the system prompt. Check `/api/hosts/memories` to see what
the agent has learned. Red teamer edits via the UI also appear here.
- Dead-end hosts should be marked as such (status: dead-end)
- The memory context is capped at 200 tokens to avoid bloating the system prompt

## Training Data
The agent captures successful interactions to /root/nightcrawler/training_data/ for finetuning.
- Check stats: `curl -sk https://<tailscale-ip>:8888/api/training/stats`
- 20GB budget with auto-rotation
- Only captures successful REASONING+COMMAND pairs that executed successfully

## Common Issues
- Model produces garbage ~50%: handled by garbage detection, 5-streak resets context
- Model refuses pentest: handled by refusal detection, re-prompts with auth context
- Commands have markdown formatting: parser strips **, ```, ###
- LLM takes ~10-30s per turn: normal at 13 t/s generation (LFM2.5-1.2B)
- Context overflow: should not happen at 8192 ctx. If it does, log the token count
- Agent crashes: restart with `python3 main.py &` (don't touch llama-server)
- Memory leak: agent RSS should stay <100MB. If >200MB, restart the agent only

## Model Behavior Notes
- The 1.2B model (LFM2.5-1.2B-Instruct-Heretic) follows few-shot examples, NOT instructions
- Phase-aware seed: RECON=nmap example, ENUMERATE=curl example
- Temperature 0.2 for best format compliance
- max_tokens 200 balances completeness vs garbage
- If model keeps using same tool, edit prompts/*.md to show different examples
