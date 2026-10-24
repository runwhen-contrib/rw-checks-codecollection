"""The one error type a tool raises for a failure the caller can act on."""

from __future__ import annotations


class ToolError(Exception):
    """A refusal with a stable `code` a caller can match on. Renders as "CODE: message"."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(code, message)
        self.code = code
        self.message = message

    def __str__(self) -> str:
        return f"{self.code}: {self.message}"
