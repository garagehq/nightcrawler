"""Context window manager for the agent loop.

Manages the sliding window of messages sent to the LLM,
keeping recent tool results verbatim and summarizing older ones.
"""


class ContextManager:
    """Manages conversation context within token budget."""

    def __init__(self, max_tokens: int = 3400):
        self.max_tokens = max_tokens
        self.messages = []
        self._char_budget = max_tokens * 4  # rough chars-to-tokens

    def append_user(self, content: str):
        self.messages.append({"role": "user", "content": content})
        self._trim()

    def append_assistant(self, content: str):
        self.messages.append({"role": "assistant", "content": content})
        self._trim()

    def append_tool_result(self, command: str, result: dict):
        output = result.get("output", "")
        status = result.get("status", "unknown")
        # Truncate very long outputs
        if len(output) > 2000:
            output = output[:1800] + f"\n... [truncated, {len(output)} chars total]"
        content = f"[COMMAND]: {command}\n[STATUS]: {status}\n[OUTPUT]:\n{output}"
        self.messages.append({"role": "user", "content": content})
        self._trim()

    def get_messages(self) -> list:
        return list(self.messages)

    def get_summary(self) -> str:
        """Return a compact summary of mission state for the LLM."""
        findings = []
        for msg in self.messages:
            if msg["role"] == "user" and msg["content"].startswith("[COMMAND]"):
                findings.append(msg["content"][:200])
        return "\n---\n".join(findings[-5:])  # last 5 exchanges

    def _trim(self):
        """Remove oldest messages if we exceed budget."""
        total = sum(len(m["content"]) for m in self.messages)
        while total > self._char_budget and len(self.messages) > 2:
            removed = self.messages.pop(0)
            total -= len(removed["content"])

    def clear(self):
        self.messages.clear()
