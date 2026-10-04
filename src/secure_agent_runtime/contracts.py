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

import dataclasses
import enum
import hashlib
import inspect
import json
import math
import pickle
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


class EffectNotApplied(Exception):  # noqa: N818 - it is an outcome, not only an error
    """Raised by a tool that knows for certain its side effect did not happen.

    Any other exception from a WRITE or EXTERNAL tool leaves the effect unknown.
    """


@dataclass(frozen=True)
class ToolContext:
    """What a tool may learn about the action it is executing."""

    action_id: str
    idempotency_key: str
    attempt: int
    cancel: threading.Event


@dataclass(frozen=True)
class Applied:
    """Reconciliation found that the effect happened; ``result`` is the tool's output."""

    result: Any


@dataclass(frozen=True)
class NotApplied:
    """Reconciliation established that the effect did not happen."""


@dataclass(frozen=True)
class Unknown:
    """Reconciliation could not decide."""

    reason: str = ""


Reconciliation = Applied | NotApplied | Unknown


def _forbids_extra(model: type[BaseModel]) -> bool:
    return model.model_config.get("extra") == "forbid"


@dataclass(frozen=True)
class ToolSpec:
    """An operator-registered tool. Everything the runtime trusts about a tool lives here.

    ``fn(args)`` or ``fn(args, ctx)`` performs the effect. ``reconciler(args, ctx)``, if
    given, answers "did this action's effect happen?" after an uncertain execution.
    ``observer`` snapshots the state the tool may change, and ``frame(args)`` declares
    which changes are required, allowed and forbidden for one call (see ``effects``).
    """

    name: str
    input_model: type[BaseModel]
    output_model: type[BaseModel]
    fn: Callable[..., Any]
    effect: Effect
    version: str = "1"
    timeout_s: float = 10.0
    description: str = ""
    takes_ctx: bool = False
    reconciler: Callable[[Any, ToolContext], Reconciliation] | None = None
    observer: Any = None  # an effects.Observer
    frame: Callable[[Any], Any] | None = None  # args model -> effects.FrameSpec
    # "thread": run in-process (a timed-out tool cannot be stopped). "process": run each
    # dispatch in a fresh worker process that is killed on timeout; fn and both models
    # must then be importable (module-level), because they are pickled by reference.
    isolation: str = "thread"

    def __post_init__(self) -> None:
        if not self.name or not self.name.replace("_", "").replace("-", "").isalnum():
            raise ContractError(f"invalid tool name {self.name!r}")
        if not isinstance(self.effect, Effect):
            raise ContractError(f"{self.name}: effect must be an Effect")
        if not (isinstance(self.version, str) and self.version):
            raise ContractError(f"{self.name}: version must be a non-empty string")
        for label, model in (("input", self.input_model), ("output", self.output_model)):
            if not (isinstance(model, type) and issubclass(model, BaseModel)):
                raise ContractError(f"{self.name}: {label} model must be a pydantic BaseModel")
            if not _forbids_extra(model):
                raise ContractError(f"{self.name}: {label} model must set extra='forbid'")
        if not (isinstance(self.timeout_s, (int, float)) and math.isfinite(self.timeout_s)
                and self.timeout_s > 0):
            raise ContractError(f"{self.name}: timeout_s must be a positive finite number")
        if self.reconciler is not None and self.effect is Effect.READ:
            raise ContractError(f"{self.name}: a READ tool has no effect to reconcile")
        if (self.frame is None) != (self.observer is None):
            raise ContractError(f"{self.name}: frame and observer must be given together")
        if self.isolation not in ("thread", "process"):
            raise ContractError(f"{self.name}: isolation must be 'thread' or 'process'")
        if self.isolation == "process":
            for label, obj in (("fn", self.fn), ("input model", self.input_model),
                               ("output model", self.output_model)):
                try:
                    pickle.dumps(obj)
                except Exception as exc:
                    raise ContractError(f"{self.name}: process isolation needs an importable {label} "
                                        f"(module-level, not a closure): {type(exc).__name__}") from exc

    @property
    def schema_digest(self) -> str:
        """Identity of the input and output contracts; part of every action's digest."""
        return "sha256:" + _sha256(canonical_json({"input": self.input_model.model_json_schema(),
                                                   "output": self.output_model.model_json_schema()}))

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

    def replace(self, spec: ToolSpec) -> ToolSpec:
        """Swap in a new definition of a registered tool (a redeploy). Pending actions are
        re-checked against it, and its version and schema are part of their digest."""
        if spec.name not in self._tools:
            raise ContractError(f"tool {spec.name!r} is not registered")
        self._tools[spec.name] = spec
        return spec

    def tool(self, *, name: str | None = None, input: type[BaseModel], output: type[BaseModel],
             effect: Effect, version: str = "1", timeout_s: float = 10.0, observer: Any = None,
             frame: Callable[[Any], Any] | None = None,
             isolation: str = "thread") -> Callable[[Callable[..., Any]], ToolSpec]:
        """Decorator form of :meth:`register`. The tool gets a ``ToolContext`` if its second
        parameter is named ``ctx``."""

        def wrap(fn: Callable[..., Any]) -> ToolSpec:
            params = inspect.signature(fn).parameters
            return self.register(ToolSpec(
                name=name or fn.__name__, input_model=input, output_model=output, fn=fn,
                effect=effect, version=version, timeout_s=timeout_s,
                description=inspect.getdoc(fn) or "", takes_ctx="ctx" in params,
                observer=observer, frame=frame, isolation=isolation,
            ))

        return wrap

    def reconciler(self, name: str) -> Callable[[Callable[..., Reconciliation]], ToolSpec]:
        """Attach a reconciler to a registered tool: ``fn(args, ctx) -> Applied | NotApplied | Unknown``."""

        def wrap(fn: Callable[..., Reconciliation]) -> ToolSpec:
            spec = self._tools.get(name)
            if spec is None:
                raise ContractError(f"tool {name!r} is not registered")
            self._tools[name] = dataclasses.replace(spec, reconciler=fn)
            return self._tools[name]

        return wrap

    def get(self, name: str) -> ToolSpec | None:
        return self._tools.get(name)

    def names(self) -> list[str]:
        return sorted(self._tools)

    def schemas(self, allowed: set[str] | frozenset[str] | None = None) -> list[dict[str, Any]]:
        return [t.json_schema() for n, t in sorted(self._tools.items())
                if allowed is None or n in allowed]


MAX_JSON_BYTES = 64 * 1024  # per argument object or tool output


def canonical_json(value: Any) -> str:
    """Deterministic JSON. Raises on anything that is not plain JSON (no silent str())."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                      allow_nan=False)


def plain_json(value: Any) -> str | None:
    """Canonical JSON of ``value`` if it is plain, bounded, UTF-8-encodable JSON; else None.

    Hostile input can make serialisation fail in many ways (lone surrogates, integers
    beyond the int-to-str limit, nesting deep enough to hit the recursion limit), so any
    exception means "not plain JSON".
    """
    try:
        text = canonical_json(value)
        size = len(text.encode("utf-8"))
    except Exception:
        return None
    return text if size <= MAX_JSON_BYTES else None


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def request_hash(tool: Any, raw_args: Any, extra: dict[str, Any] | None = None) -> str:
    """Identity of a *raw* proposal, used to detect replay divergence.

    It must work for malformed proposals too, so anything that is not plain JSON is
    hashed by its type name only. It is never used to authorise anything.
    """
    body = plain_json({"tool": tool, "args": raw_args, "extra": extra})
    if body is None:
        body = canonical_json({"tool": type(tool).__name__, "unserialisable": type(raw_args).__name__,
                               "extra": extra})
    return _sha256(body)


def parse_input(spec: ToolSpec, raw: Any) -> tuple[BaseModel | None, str | None]:
    """Validate raw arguments into the tool's input model. Returns (model, None) or (None, reason).

    The model is accepted only if its JSON dump validates back to the same dump, so the
    arguments that are hashed, approved and stored are exactly what the tool receives
    (a validator that rewrites its value on every pass is refused).
    """
    if not isinstance(raw, dict):
        return None, "arguments must be a JSON object"
    text = plain_json(raw)
    if text is None:
        return None, f"arguments are not plain JSON or exceed {MAX_JSON_BYTES} bytes"
    try:
        model = spec.input_model.model_validate_json(text, strict=True)
        dumped = model.model_dump(mode="json")
        again = spec.input_model.model_validate_json(canonical_json(dumped), strict=True)
        stable = again.model_dump(mode="json") == dumped
    except ValidationError as exc:
        return None, _short(exc)
    except Exception as exc:  # a validator that raises something else fails closed
        return None, f"input validation raised {type(exc).__name__}"
    if not stable:
        return None, "input model does not round-trip; refusing to hash unstable arguments"
    return model, None


def validate_input(spec: ToolSpec, raw: Any) -> tuple[dict[str, Any] | None, str | None]:
    """Returns (validated JSON-mode args, None) or (None, reason)."""
    model, error = parse_input(spec, raw)
    return (model.model_dump(mode="json"), None) if model is not None else (None, error)


def validate_output(spec: ToolSpec, raw: Any) -> tuple[dict[str, Any] | None, str | None]:
    """Returns (validated JSON-mode output, None) or (None, reason). Never raises."""
    try:
        if isinstance(raw, BaseModel):  # dumped, then validated like any other value
            raw = raw.model_dump(mode="json")
        text = plain_json(raw)
        if text is None:
            return None, f"output is not plain JSON or exceeds {MAX_JSON_BYTES} bytes"
        return spec.output_model.model_validate_json(text, strict=True).model_dump(mode="json"), None
    except ValidationError as exc:
        return None, _short(exc)
    except Exception as exc:
        return None, f"output validation raised {type(exc).__name__}"


_SAFE_LOC = re.compile(r"^[A-Za-z0-9_]{1,64}$")


def _loc(parts: tuple[Any, ...]) -> str:
    # Unknown keys are chosen by whoever produced the input; echo only identifier-like ones.
    return ".".join(str(p) if _SAFE_LOC.match(str(p)) else "<field>" for p in parts) or "(root)"


# Error types whose message is written by the operator's validator and may quote the input
# (``ValueError(f"bad card {x}")``); their text is never echoed.
_OPAQUE = frozenset({"value_error", "assertion_error"})


def _short(exc: ValidationError) -> str:
    # Field locations and pydantic's own messages only; never echo the offending input back.
    return "; ".join(f"{_loc(e['loc'])}: {'rejected by validator' if e['type'] in _OPAQUE else e['msg']}"
                     for e in exc.errors(include_input=False))[:500]


def invoke(spec: ToolSpec, model: BaseModel, ctx: ToolContext) -> Any:
    """Call the tool with the validated input model."""
    return spec.fn(model, ctx) if spec.takes_ctx else spec.fn(model)
