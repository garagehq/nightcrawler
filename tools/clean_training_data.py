#!/usr/bin/env python3
"""Curate training_data/ into a deduped, quality-filtered, finetune-ready set.

Non-destructive: reads training_data/*.jsonl, writes a curated dataset to
training_data_clean/ and leaves the originals untouched (the agent keeps
appending live captures to training_data/). Re-run any time before finetuning.

Output format is template-agnostic "messages" JSONL — each line is
{"messages": [{"role","content"}...], "meta": {...}} — so a finetuning tool
applies the model's OWN chat template (the raw capture's `chatml` field is
Qwen-style `<|im_start|>` and is WRONG for LFM2, so it is dropped here).

Filters (each dropped record is counted and reported):
  - duplicate: same command + output signature already kept
  - placeholder_cmd: command still contains <ip>/<port>/bare IP token
  - no_real_ip: command has no dotted-quad IP
  - tiny_output: command_output < 5 chars (no useful ground truth)
  - malformed_flags: repeated scan flags (e.g. -sZ -sZ)
  - loud_nmap: nmap without -T0/-T1/-T2 (would teach non-stealth scanning)

Usage: python3 tools/clean_training_data.py [--src DIR] [--out DIR]
"""
import argparse, json, os, re, hashlib, collections

PLACEHOLDER = re.compile(r"<\s*(ip|port|ports|target|bssid|ch|client_mac|essid|password)\s*>", re.I)
BARE_TOK = re.compile(r"(?<![A-Za-z0-9/])(IP|IP_OF_INTEREST|DISCOVERED_HOST|CLIENT_MAC)(?![A-Za-z0-9])")
IP = re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")
NMAP_STEALTH = re.compile(r"-T[0-2]\b")
REPEAT_FLAG = re.compile(r"(-s[A-Z])(?:\s+\1){2,}")


# Keep at most this many examples per unique command. Repeated commands (the
# agent runs some scans dozens of times) over-represent themselves in a small
# SFT set; capping keeps a few varied-reasoning examples of each and drops the
# rest. Reasoning wording varies per run, so we cap on the command, not the
# full response.
DUP_CAP = 5


def _norm(s):
    return re.sub(r"\s+", " ", (s or "").strip().lower())


def reject_reason(d, seen):
    cmd = (d.get("command") or "").strip()
    out = d.get("command_output", "") or ""
    if PLACEHOLDER.search(cmd) or BARE_TOK.search(cmd):
        return "placeholder_cmd"
    if not IP.search(cmd):
        return "no_real_ip"
    if len(out.strip()) < 5:
        return "tiny_output"
    if REPEAT_FLAG.search(cmd) or cmd.count("-sZ") >= 2:
        return "malformed_flags"
    # Match nmap as the tool even under "sudo " (the agent's bare-command
    # recovery can emit `sudo nmap ...`). startswith("nmap") let those
    # commands bypass the stealth filter entirely.
    if re.search(r"(?:^|\s)(?:sudo\s+)?nmap\b", cmd) and not NMAP_STEALTH.search(cmd):
        return "loud_nmap"
    # Cap per unique command (normalized). Output-based dedup fails because nmap
    # output embeds a timestamp; command-level capping is what curbs the real
    # over-representation.
    key = _norm(cmd)
    seen[key] = seen.get(key, 0) + 1
    if seen[key] > DUP_CAP:
        return "over_cap"
    return None


def to_lfm2_text(system_prompt, messages, response):
    """Render a full conversation in LFM2.5's chat template.

    Verified against llama-server /apply-template: LFM2.5 uses ChatML markers
    `<|im_start|>{role}\\n{content}<|im_end|>\\n`. The BOS token
    `<|startoftext|>` is prepended by the tokenizer at train time, so it is NOT
    embedded here (embedding it risks a double-BOS). The final assistant turn
    keeps its trailing `<|im_end|>` so the model learns to stop.
    """
    out = []
    if system_prompt:
        out.append(f"<|im_start|>system\n{system_prompt}<|im_end|>\n")
    for m in messages:
        r = m.get("role", "user")
        if r == "system":
            continue
        out.append(f"<|im_start|>{r}\n{m.get('content','')}<|im_end|>\n")
    out.append(f"<|im_start|>assistant\n{response}<|im_end|>\n")
    return "".join(out)


def to_messages(d):
    """Training record: messages list (template-agnostic) + LFM2-formatted text."""
    msgs = []
    sp = d.get("system_prompt", "")
    if sp:
        msgs.append({"role": "system", "content": sp})
    prior = [m for m in d.get("messages", []) if m.get("role") != "system"]
    for m in prior:
        msgs.append({"role": m.get("role", "user"), "content": m.get("content", "")})
    resp = d.get("assistant_response", "")
    msgs.append({"role": "assistant", "content": resp})
    return {
        "messages": msgs,
        "text": to_lfm2_text(sp, prior, resp),
        "meta": {
            "command": d.get("command", ""),
            "phase": d.get("phase", ""),
            "timestamp": d.get("timestamp", ""),
            "return_code": d.get("return_code", 0),
        },
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--src", default="training_data")
    ap.add_argument("--out", default="training_data_clean")
    args = ap.parse_args()
    os.makedirs(args.out, exist_ok=True)

    seen = {}
    kept = 0
    total = 0
    rejects = collections.Counter()
    out_path = os.path.join(args.out, "train_clean.jsonl")

    with open(out_path, "w") as w:
        for fn in sorted(os.listdir(args.src)):
            if not fn.endswith(".jsonl"):
                continue
            for line in open(os.path.join(args.src, fn), errors="replace"):
                line = line.strip()
                if not line:
                    continue
                total += 1
                try:
                    d = json.loads(line)
                except Exception:
                    rejects["unparseable"] += 1
                    continue
                reason = reject_reason(d, seen)
                if reason:
                    rejects[reason] += 1
                    continue
                w.write(json.dumps(to_messages(d)) + "\n")
                kept += 1

    print(f"source: {args.src} | total records: {total}")
    print(f"unique commands: {len(seen)} | per-command cap: {DUP_CAP}")
    print(f"KEPT (curated): {kept} ({100*kept//total if total else 0}%) -> {out_path}")
    print("dropped:")
    for k, v in rejects.most_common():
        print(f"  {k}: {v}")
    # manifest
    with open(os.path.join(args.out, "MANIFEST.txt"), "w") as m:
        m.write(f"curated from {args.src}\ntotal={total} kept={kept}\n")
        for k, v in rejects.most_common():
            m.write(f"dropped {k}={v}\n")


if __name__ == "__main__":
    main()
