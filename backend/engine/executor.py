import requests

from backend.config import Config


class ExecutionResult:
    def __init__(
        self,
        success=False,
        response="",
        status_code=None,
        error=None,
        latency_ms=0,
    ):
        self.success = success
        self.response = response
        self.status_code = status_code
        self.error = error
        self.latency_ms = latency_ms

    def to_dict(self):
        return {
            "success": self.success,
            "response": self.response,
            "status_code": self.status_code,
            "error": self.error,
            "latency_ms": self.latency_ms,
        }


class AIExecutor:
    """
    Model-agnostic execution layer.

    Supported providers:
        - generic
        - ollama
        - openai
        - gemini
        - anthropic
    """

    def __init__(
        self,
        provider="generic",
        endpoint=None,
        model=None,
        headers=None,
        api_key=None,
        timeout=None,
    ):
        self.provider = provider.lower()
        self.endpoint = endpoint
        self.model = model
        self.headers = headers or {}
        self.api_key = api_key
        self.timeout = timeout or Config.MAX_TIMEOUT

    def execute(self, prompt):
        try:
            if self.provider == "generic":
                return self._generic(prompt)

            if self.provider == "ollama":
                return self._ollama(prompt)

            if self.provider == "openai":
                return self._openai(prompt)

            if self.provider == "gemini":
                return self._gemini(prompt)

            if self.provider == "anthropic":
                return self._anthropic(prompt)

            return ExecutionResult(
                success=False,
                error=f"Unsupported provider: {self.provider}",
            )

        except requests.exceptions.Timeout:
            return ExecutionResult(
                success=False,
                error="Target request timed out.",
            )

        except requests.exceptions.ConnectionError:
            return ExecutionResult(
                success=False,
                error="Unable to connect to target.",
            )

        except requests.exceptions.RequestException as exc:
            return ExecutionResult(
                success=False,
                error=str(exc),
            )

        except Exception as exc:
            return ExecutionResult(
                success=False,
                error=f"Unexpected execution error: {exc}",
            )

    # ---------------------------------------------------------
    # GENERIC HTTP ENDPOINT
    # ---------------------------------------------------------

    def _generic(self, prompt):
        import time

        payload = {
            "prompt": prompt
        }

        start = time.perf_counter()

        response = requests.post(
            self.endpoint,
            json=payload,
            headers=self.headers,
            timeout=self.timeout,
        )

        latency = int(
            (time.perf_counter() - start) * 1000
        )

        text = self._extract_generic_response(
            response
        )

        return ExecutionResult(
            success=response.ok,
            response=text,
            status_code=response.status_code,
            error=None if response.ok else response.text[:500],
            latency_ms=latency,
        )

    # ---------------------------------------------------------
    # OLLAMA
    # ---------------------------------------------------------

    def _ollama(self, prompt):
        import time

        endpoint = self.endpoint or (
            f"{Config.AI_BASE_URL.rstrip('/')}/api/chat"
        )

        payload = {
            "model": self.model or Config.AI_MODEL,
            "messages": [
                {
                    "role": "user",
                    "content": prompt,
                }
            ],
            "stream": False,
        }

        start = time.perf_counter()

        response = requests.post(
            endpoint,
            json=payload,
            headers=self.headers,
            timeout=self.timeout,
        )

        latency = int(
            (time.perf_counter() - start) * 1000
        )

        data = response.json()

        text = (
            data.get("message", {})
            .get("content", "")
        )

        return ExecutionResult(
            success=response.ok,
            response=text,
            status_code=response.status_code,
            error=None if response.ok else str(data),
            latency_ms=latency,
        )

    # ---------------------------------------------------------
    # OPENAI
    # ---------------------------------------------------------

    def _openai(self, prompt):
        import time

        endpoint = self.endpoint or (
            "https://api.openai.com/v1/responses"
        )

        headers = dict(self.headers)

        if self.api_key:
            headers["Authorization"] = (
                f"Bearer {self.api_key}"
            )

        headers["Content-Type"] = "application/json"

        payload = {
            "model": self.model or Config.DEFAULT_MODEL,
            "input": prompt,
        }

        start = time.perf_counter()

        response = requests.post(
            endpoint,
            json=payload,
            headers=headers,
            timeout=self.timeout,
        )

        latency = int(
            (time.perf_counter() - start) * 1000
        )

        data = response.json()

        text = self._extract_openai_response(data)

        return ExecutionResult(
            success=response.ok,
            response=text,
            status_code=response.status_code,
            error=None if response.ok else str(data),
            latency_ms=latency,
        )

    # ---------------------------------------------------------
    # GEMINI
    # ---------------------------------------------------------

    def _gemini(self, prompt):
        import time

        model = self.model or "gemini-2.5-flash"

        endpoint = self.endpoint

        if not endpoint:
            if not self.api_key:
                return ExecutionResult(
                    success=False,
                    error="Gemini API key is required.",
                )

            endpoint = (
                "https://generativelanguage.googleapis.com/"
                f"v1beta/models/{model}:generateContent"
                f"?key={self.api_key}"
            )

        payload = {
            "contents": [
                {
                    "parts": [
                        {
                            "text": prompt
                        }
                    ]
                }
            ]
        }

        start = time.perf_counter()

        response = requests.post(
            endpoint,
            json=payload,
            headers=self.headers,
            timeout=self.timeout,
        )

        latency = int(
            (time.perf_counter() - start) * 1000
        )

        data = response.json()

        text = ""

        candidates = data.get(
            "candidates",
            []
        )

        if candidates:
            content = candidates[0].get(
                "content",
                {}
            )

            parts = content.get(
                "parts",
                []
            )

            text = "".join(
                part.get("text", "")
                for part in parts
            )

        return ExecutionResult(
            success=response.ok,
            response=text,
            status_code=response.status_code,
            error=None if response.ok else str(data),
            latency_ms=latency,
        )

    # ---------------------------------------------------------
    # ANTHROPIC
    # ---------------------------------------------------------

    def _anthropic(self, prompt):
        import time

        endpoint = self.endpoint or (
            "https://api.anthropic.com/v1/messages"
        )

        headers = dict(self.headers)

        if self.api_key:
            headers["x-api-key"] = self.api_key

        headers["Content-Type"] = "application/json"
        headers["anthropic-version"] = "2023-06-01"

        payload = {
            "model": self.model or "claude-sonnet-4-5",
            "max_tokens": 1024,
            "messages": [
                {
                    "role": "user",
                    "content": prompt,
                }
            ],
        }

        start = time.perf_counter()

        response = requests.post(
            endpoint,
            json=payload,
            headers=headers,
            timeout=self.timeout,
        )

        latency = int(
            (time.perf_counter() - start) * 1000
        )

        data = response.json()

        text = ""

        for block in data.get("content", []):
            if block.get("type") == "text":
                text += block.get("text", "")

        return ExecutionResult(
            success=response.ok,
            response=text,
            status_code=response.status_code,
            error=None if response.ok else str(data),
            latency_ms=latency,
        )

    # ---------------------------------------------------------
    # RESPONSE EXTRACTION
    # ---------------------------------------------------------

    @staticmethod
    def _extract_generic_response(response):
        try:
            data = response.json()
        except ValueError:
            return response.text

        if isinstance(data, str):
            return data

        for key in (
            "response",
            "message",
            "output",
            "text",
            "content",
            "answer",
        ):
            value = data.get(key)

            if isinstance(value, str):
                return value

            if isinstance(value, dict):
                content = value.get("content")

                if isinstance(content, str):
                    return content

        return response.text

    @staticmethod
    def _extract_openai_response(data):
        output_text = data.get("output_text")

        if isinstance(output_text, str):
            return output_text

        outputs = data.get("output", [])

        text_parts = []

        for item in outputs:
            for content in item.get(
                "content",
                []
            ):
                text = content.get("text")

                if isinstance(text, str):
                    text_parts.append(text)

        if text_parts:
            return "".join(text_parts)

        choices = data.get("choices", [])

        if choices:
            message = choices[0].get(
                "message",
                {}
            )

            content = message.get("content")

            if isinstance(content, str):
                return content

        return ""