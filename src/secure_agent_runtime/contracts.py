"""Tool contracts: what a tool accepts, what it may return, and what it can affect.

A tool is registered with a pydantic model for its input and one for its output, and a
declared ``Effect``. The runtime validates input before policy runs and validates output
before anything is handed back to the model. Nothing about a tool's effect or safety is
taken from the model or from tool metadata supplied by a remote server: the registry
entry written by the operator is the only source of truth.
"""

from __future__ import annotations

import enum
import hashlib
import inspect
import json
import threading
from dataclasses import dataclass, field
from typing import Any, Callable

from pydantic import BaseModel, ValidationError


class Effect(str, enum.Enum):
    """What a tool can change. Policy keys off this, never off the tool's description."""

    READ = "read"          # observes local state only
    WRITE = "write"        # changes local state
    EXTERNAL = "external"  # acts outside the process (network, email, payments, ...)


@dataclass(frozen=True)
class ToolSpec:
    name: str
    input_model: type[BaseModel]
    output_model: type[BaseModel]
    fn: Callable[..., Any]
    effect: Effect
    timeout_s: float = 10.0
    description: str = ""
    # Whether running the same call twice is harmless. Only idempotent tools are retried.
    idempotent: bool = False
    max_retries: int = 0
    # Receives a threading.Event that is set when the call is cancelled or times out.
    accepts_cancel: bool = False

    def __post_init__(self) -> None:
        if self.max_retries and not self.idempotent:
            raise ValueError(f"{self.name}: only idempotent tools may be retried")
        if self.timeout_s <= 0:
            raise ValueError(f"{self.name}: timeout_s must be positive")

    def json_schema(self) -> dict[str, Any]:
        """The input schema in the shape most tool-calling APIs accept."""
        schema = self.input_model.model_json_schema()
        schema.pop("title", None)
        return {"name": self.name, "description": self.description, "input_schema": schema}


class ToolRegistry:
    def __init__(self) -> None:
        self._tools: dict[str, ToolSpec] = {}

    def register(self, spec: ToolSpec) -> ToolSpec:
        if spec.name in self._tools:
            raise ValueError(f"tool {spec.name!r} is already registered")
        self._tools[spec.name] = spec
        return spec

    def tool(self, *, name: str | None = None, input: type[BaseModel], output: type[BaseModel],
             effect: Effect, timeout_s: float = 10.0, idempotent: bool = False,
             max_retries: int = 0) -> Callable[[Callable[..., Any]], ToolSpec]:
        """Decorator form of :meth:`register`."""

        def wrap(fn: Callable[..., Any]) -> ToolSpec:
            params = inspect.signature(fn).parameters
            return self.register(ToolSpec(
                name=name or fn.__name__, input_model=input, output_model=output, fn=fn,
                effect=effect, timeout_s=timeout_s, description=inspect.getdoc(fn) or "",
                idempotent=idempotent, max_retries=max_retries,
                accepts_cancel="cancel" in params,
            ))

        return wrap

    def get(self, name: str) -> ToolSpec | None:
        return self._tools.get(name)

    def names(self) -> list[str]:
        return sorted(self._tools)

    def schemas(self, allowed: set[str] | None = None) -> list[dict[str, Any]]:
        return [t.json_schema() for n, t in sorted(self._tools.items()) if allowed is None or n in allowed]


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)


def args_hash(tool: str, args: dict[str, Any]) -> str:
    """Identity of a request's content. An approval is bound to exactly this hash."""
    return hashlib.sha256(canonical_json({"tool": tool, "args": args}).encode()).hexdigest()


@dataclass
class ValidatedInput:
    args: dict[str, Any] = field(default_factory=dict)
    error: str | None = None


def validate_input(spec: ToolSpec, raw: Any) -> ValidatedInput:
    if not isinstance(raw, dict):
        return ValidatedInput(error="arguments must be a JSON object")
    try:
        return ValidatedInput(args=spec.input_model.model_validate(raw).model_dump(mode="json"))
    except ValidationError as exc:
        return ValidatedInput(error=_short(exc))


def validate_output(spec: ToolSpec, raw: Any) -> tuple[dict[str, Any] | None, str | None]:
    try:
        if isinstance(raw, spec.output_model):
            return raw.model_dump(mode="json"), None
        return spec.output_model.model_validate(raw).model_dump(mode="json"), None
    except ValidationError as exc:
        return None, _short(exc)


def _short(exc: ValidationError) -> str:
    return "; ".join(f"{'.'.join(map(str, e['loc'])) or '(root)'}: {e['msg']}" for e in exc.errors())[:500]


def call_tool(spec: ToolSpec, args: dict[str, Any], cancel: threading.Event) -> Any:
    model = spec.input_model.model_validate(args)
    return spec.fn(model, cancel=cancel) if spec.accepts_cancel else spec.fn(model)
