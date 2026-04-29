"""Training data capture for model finetuning.

Captures successful agent interactions in formats ready for finetuning:
- ChatML format (for llama.cpp / Qwen finetuning)
- JSON conversation pairs
- Segmented by phase for targeted finetuning

Only captures SUCCESSFUL interactions where:
1. The model produced valid REASONING + COMMAND
2. The command executed successfully (not blocked, not error)
3. The output was meaningful (not empty)

Storage: /root/nightcrawler/training_data/
Budget: 20GB max, auto-rotates oldest files
"""

import json
import os
import time

TRAINING_DIR = "/root/nightcrawler/training_data"
MAX_SIZE_BYTES = 20 * 1024 * 1024 * 1024  # 20GB


def _ts():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _ensure_dir():
    os.makedirs(TRAINING_DIR, exist_ok=True)


def capture_successful_interaction(
    system_prompt: str,
    messages: list,
    response: str,
    reasoning: str,
    command: str,
    result: dict,
    phase: str = "",
    network_id: str = "",
):
    """Capture a successful interaction for finetuning.

    Only call this when:
    - reasoning and command were both parsed successfully
    - result.status == "success"
    - result.output is non-empty
    """
    _ensure_dir()

    output = result.get("output", "")
    if not output.strip() or result.get("status") != "success":
        return  # Skip unsuccessful interactions

    # Build the training example
    example = {
        "timestamp": _ts(),
        "phase": phase,
        "network_id": network_id,

        # The conversation that produced a good result
        "system_prompt": system_prompt,
        "messages": messages,
        "assistant_response": response,

        # Parsed output
        "reasoning": reasoning,
        "command": command,

        # What happened (ground truth)
        "command_output": output[:4000],  # cap output
        "return_code": result.get("return_code", 0),

        # ChatML format (ready for finetuning)
        "chatml": _to_chatml(system_prompt, messages, response),
    }

    # Write to JSONL file (one per day, segmented by phase)
    date = time.strftime("%Y-%m-%d")
    phase_tag = phase.lower().replace(" ", "_").replace("&", "").strip("_") or "unknown"
    filename = f"train_{date}_{phase_tag}.jsonl"
    filepath = os.path.join(TRAINING_DIR, filename)

    with open(filepath, "a") as f:
        f.write(json.dumps(example) + "\n")

    # Check total size and rotate if needed
    _check_rotation()


def _to_chatml(system_prompt: str, messages: list, response: str) -> str:
    """Convert to ChatML format for Qwen finetuning."""
    parts = []
    if system_prompt:
        parts.append(f"<|im_start|>system\n{system_prompt}<|im_end|>")
    for msg in messages:
        role = msg.get("role", "user")
        content = msg.get("content", "")
        parts.append(f"<|im_start|>{role}\n{content}<|im_end|>")
    parts.append(f"<|im_start|>assistant\n{response}<|im_end|>")
    return "\n".join(parts)


def _check_rotation():
    """Delete oldest files if total size exceeds budget."""
    total = 0
    files = []
    for f in os.listdir(TRAINING_DIR):
        if f.endswith(".jsonl"):
            path = os.path.join(TRAINING_DIR, f)
            size = os.path.getsize(path)
            total += size
            files.append((os.path.getmtime(path), path, size))

    if total > MAX_SIZE_BYTES:
        files.sort()  # oldest first
        while total > MAX_SIZE_BYTES and files:
            _, path, size = files.pop(0)
            os.remove(path)
            total -= size


def get_stats() -> dict:
    """Get training data statistics."""
    _ensure_dir()
    total_size = 0
    total_examples = 0
    files = {}

    for f in sorted(os.listdir(TRAINING_DIR)):
        if f.endswith(".jsonl"):
            path = os.path.join(TRAINING_DIR, f)
            size = os.path.getsize(path)
            with open(path) as fh:
                count = sum(1 for _ in fh)
            total_size += size
            total_examples += count
            files[f] = {"size_kb": size // 1024, "examples": count}

    return {
        "total_examples": total_examples,
        "total_size_mb": total_size // (1024 * 1024),
        "budget_mb": MAX_SIZE_BYTES // (1024 * 1024),
        "files": files,
    }


def export_for_finetuning(format: str = "chatml") -> str:
    """Export all training data in a single file for finetuning.

    Formats:
    - chatml: ChatML format (one conversation per line)
    - jsonl: Full JSON examples
    - conversations: OpenAI-style conversation format
    """
    _ensure_dir()
    output_path = os.path.join(TRAINING_DIR, f"export_{format}_{time.strftime('%Y%m%d')}.jsonl")

    count = 0
    with open(output_path, "w") as out:
        for f in sorted(os.listdir(TRAINING_DIR)):
            if f.startswith("train_") and f.endswith(".jsonl"):
                with open(os.path.join(TRAINING_DIR, f)) as fh:
                    for line in fh:
                        try:
                            example = json.loads(line.strip())
                            if format == "chatml":
                                out.write(json.dumps({"text": example["chatml"]}) + "\n")
                            elif format == "conversations":
                                conv = []
                                conv.append({"role": "system", "content": example.get("system_prompt", "")})
                                for m in example.get("messages", []):
                                    conv.append(m)
                                conv.append({"role": "assistant", "content": example.get("assistant_response", "")})
                                out.write(json.dumps({"conversations": conv}) + "\n")
                            else:
                                out.write(line)
                            count += 1
                        except json.JSONDecodeError:
                            pass

    return output_path, count
