"""Tool contracts: what a tool accepts, what it may return, and what it can affect.

A tool is registered with a pydantic model for its input and one for its output, and a
declared ``Effect``. The runtime validates input before policy runs and validates output
before anything is handed back to the model. Nothing about a tool's effect or safety is
taken from the model or from tool metadata supplied by a remote server: the registry
entry written by the operator is the only source of truth.

Validation is deliberately strict:

* Both models must set ``extra="forbid"``, so unknown fields are rejected rather than
  silently dropped.
* Input is validated in pydantic's strict JSON mode, so ``"1"`` is not coerced to ``1``
  and ``"true"`` is not coerced to ``True``.
* Output must be JSON-serialisable without any fallback conversion; an arbitrary object
  is rejected rather than stringified into something that happens to validate.
"""

from __future__ import annotations

import enum
import hashlib
import inspect
import json
import math
import re
import threading
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from pydantic import BaseModel, ValidationError


class Effect(str, enum.Enum):
    """What a tool can change. Policy keys off this, never off the tool's description."""

    READ = "read"          # observes local state only
    WRITE = "write"        # changes local state
    EXTERNAL = "external"  # acts outside the process (network, email, payments, ...)


class ContractError(ValueError):
    """A tool spec is unsafe or inconsistent. Raised at registration, never at run time."""


def _forbids_extra(model: type[BaseModel]) -> bool:
    return model.model_config.get("extra") == "forbid"


@dataclass(frozen=True)
class ToolSpec:
    name: str
    input_model: type[BaseModel]
    output_model: type[BaseModel]
    fn: Callable[..., Any]
    effect: Effect
    timeout_s: float = 10.0
    description: str = ""
    # Receives a threading.Event that is set when the call times out.
    accepts_cancel: bool = False

    def __post_init__(self) -> None:
        if not self.name or not self.name.replace("_", "").replace("-", "").isalnum():
            raise ContractError(f"invalid tool name {self.name!r}")
        if not isinstance(self.effect, Effect):
            raise ContractError(f"{self.name}: effect must be an Effect")
        for label, model in (("input", self.input_model), ("output", self.output_model)):
            if not (isinstance(model, type) and issubclass(model, BaseModel)):
                raise ContractError(f"{self.name}: {label} model must be a pydantic BaseModel")
            if not _forbids_extra(model):
                raise ContractError(f"{self.name}: {label} model must set extra='forbid'")
        if not (isinstance(self.timeout_s, (int, float)) and math.isfinite(self.timeout_s)
                and self.timeout_s > 0):
            raise ContractError(f"{self.name}: timeout_s must be a positive finite number")

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
            raise ContractError(f"tool {spec.name!r} is already registered")
        self._tools[spec.name] = spec
        return spec

    def tool(self, *, name: str | None = None, input: type[BaseModel], output: type[BaseModel],
             effect: Effect, timeout_s: float = 10.0) -> Callable[[Callable[..., Any]], ToolSpec]:
        """Decorator form of :meth:`register`."""

        def wrap(fn: Callable[..., Any]) -> ToolSpec:
            params = inspect.signature(fn).parameters
            return self.register(ToolSpec(
                name=name or fn.__name__, input_model=input, output_model=output, fn=fn,
                effect=effect, timeout_s=timeout_s, description=inspect.getdoc(fn) or "",
                accepts_cancel="cancel" in params,
            ))

        return wrap

    def get(self, name: str) -> ToolSpec | None:
        return self._tools.get(name)

    def names(self) -> list[str]:
        return sorted(self._tools)

    def schemas(self, allowed: set[str] | frozenset[str] | None = None) -> list[dict[str, Any]]:
        return [t.json_schema() for n, t in sorted(self._tools.items())
                if allowed is None or n in allowed]


def canonical_json(value: Any) -> str:
    """Deterministic JSON. Raises on anything that is not plain JSON (no silent str())."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                      allow_nan=False)


def args_hash(tool: str, args: dict[str, Any]) -> str:
    """Identity of a request's content. An approval is bound to exactly this hash."""
    return hashlib.sha256(canonical_json({"tool": tool, "args": args}).encode()).hexdigest()


def request_hash(tool: Any, raw_args: Any) -> str:
    """Identity of a *raw* proposal, used to detect replay divergence.

    It must work for malformed proposals too, so anything not serialisable is hashed by
    its type name and repr. It is never used to authorise anything.
    """
    try:
        body = canonical_json({"tool": tool, "args": raw_args})
    except (TypeError, ValueError):
        body = canonical_json({"tool": repr(tool), "unserialisable": type(raw_args).__name__,
                               "repr": repr(raw_args)})
    return hashlib.sha256(body.encode()).hexdigest()


def validate_input(spec: ToolSpec, raw: Any) -> tuple[dict[str, Any] | None, str | None]:
    """Returns (validated JSON-mode args, None) or (None, reason)."""
    if not isinstance(raw, dict):
        return None, "arguments must be a JSON object"
    try:
        text = canonical_json(raw)
    except (TypeError, ValueError):
        return None, "arguments are not plain JSON"
    try:
        model = spec.input_model.model_validate_json(text, strict=True)
    except ValidationError as exc:
        return None, _short(exc)
    return model.model_dump(mode="json"), None


def validate_output(spec: ToolSpec, raw: Any) -> tuple[dict[str, Any] | None, str | None]:
    """Returns (validated JSON-mode output, None) or (None, reason)."""
    if isinstance(raw, BaseModel):  # dumped, then validated like any other value
        raw = raw.model_dump(mode="json")
    try:
        text = canonical_json(raw)
    except (TypeError, ValueError):
        return None, "output is not plain JSON"
    try:
        return spec.output_model.model_validate_json(text, strict=True).model_dump(mode="json"), None
    except ValidationError as exc:
        return None, _short(exc)


_SAFE_LOC = re.compile(r"^[A-Za-z0-9_]{1,64}$")


def _loc(parts: tuple[Any, ...]) -> str:
    # Unknown keys are chosen by whoever produced the input; echo only identifier-like ones.
    return ".".join(str(p) if _SAFE_LOC.match(str(p)) else "<field>" for p in parts) or "(root)"


def _short(exc: ValidationError) -> str:
    # Field locations and pydantic's messages only; never echo the offending input back.
    return "; ".join(f"{_loc(e['loc'])}: {e['msg']}" for e in exc.errors(include_input=False))[:500]


def invoke(spec: ToolSpec, args: dict[str, Any], cancel: threading.Event) -> Any:
    """Call the tool with a freshly validated model built from already-validated args."""
    model = spec.input_model.model_validate_json(canonical_json(args), strict=True)
    return spec.fn(model, cancel=cancel) if spec.accepts_cancel else spec.fn(model)
