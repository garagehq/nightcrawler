"""LLM client with local llama.cpp and Thor API fallback."""

import asyncio
import json
import httpx


class LLMClient:
    """Talks to llama.cpp locally, falls back to Thor when available."""

    def __init__(self, config: dict):
        self.local_port = config["local"]["port"]
        self.local_url = f"http://127.0.0.1:{self.local_port}/v1"
        self.local_health_url = f"http://127.0.0.1:{self.local_port}/health"
        self.local_ctx = config["local"]["ctx_size"]
        self.fallback_ctx = config.get("fallback", {}).get("ctx_size", 2048)

        thor = config.get("thor", {})
        self.thor_url = thor.get("endpoint")
        self.thor_model = thor.get("model", "qwen3.5-27b")
        self.thor_enabled = thor.get("enabled", False)

        self.use_thor = False
        self._client = httpx.AsyncClient(timeout=300)

    async def chat(self, system_prompt: str, messages: list) -> str:
        """Send chat completion request. Uses Thor if available, else local."""
        api_messages = [{"role": "system", "content": system_prompt}] + messages

        if self.use_thor and self.thor_url:
            try:
                return await self._call(self.thor_url, api_messages,
                                        model=self.thor_model)
            except Exception:
                # Thor unreachable, fall back to local
                self.use_thor = False

        return await self._call(self.local_url, api_messages)

    async def _call(self, base_url: str, messages: list,
                    model: str = None) -> str:
        payload = {
            "messages": messages,
            "temperature": 0.2,
            "max_tokens": 200,
        }
        if model:
            payload["model"] = model

        resp = await self._client.post(
            f"{base_url}/chat/completions",
            json=payload,
        )
        if resp.status_code != 200:
            error_text = resp.text[:500]
            raise RuntimeError(
                f"LLM returned {resp.status_code}: {error_text}"
            )
        data = resp.json()
        return data["choices"][0]["message"]["content"]

    async def health_check(self) -> dict:
        """Check which backends are reachable."""
        status = {"local": False, "thor": False}
        try:
            r = await self._client.get(self.local_health_url, timeout=5)
            status["local"] = r.status_code == 200
        except Exception:
            pass

        if self.thor_enabled and self.thor_url:
            try:
                r = await self._client.get(
                    f"{self.thor_url}/models", timeout=5,
                )
                status["thor"] = r.status_code == 200
                if status["thor"]:
                    self.use_thor = True
            except Exception:
                pass

        return status

    def notify_wifi_connected(self):
        """Called when WiFi comes up — start trying Thor."""
        self.thor_enabled = True

    async def close(self):
        await self._client.aclose()
