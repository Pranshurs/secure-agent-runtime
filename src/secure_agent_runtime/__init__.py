"""Secure Agent Runtime: transactional execution and verifiable receipts for AI agents.

Models propose actions. The runtime decides whether they may execute, makes retries
safe, reconciles uncertain outcomes, and records what each action changed.
"""

import logging

from .action import Action
from .agent import Agent, RunResult
from .contracts import (
    Applied,
    ContractError,
    Effect,
    EffectNotApplied,
    NotApplied,
    ToolContext,
    ToolRegistry,
    ToolSpec,
    Unknown,
)
from .effects import FileTreeObserver, FrameSpec, MappingObserver, Required, check_frame
from .policy import Decision, Policy, Principal, Verdict
from .receipts import build_receipt, receipt_json_schema, verify_receipt
from .runtime import ApprovalRefused, MalformedProposal, Outcome, ReplayDivergence, Runtime, SARError
from .store import IllegalTransition, Store

__all__ = [
    "Action", "Agent", "Applied", "ApprovalRefused", "ContractError", "Decision", "Effect",
    "EffectNotApplied", "FileTreeObserver", "FrameSpec", "IllegalTransition", "MalformedProposal",
    "MappingObserver", "NotApplied", "Outcome", "Policy", "Principal", "ReplayDivergence", "Required",
    "RunResult", "Runtime", "SARError", "Store", "ToolContext", "ToolRegistry", "ToolSpec", "Unknown",
    "Verdict", "build_receipt", "check_frame", "receipt_json_schema", "verify_receipt",
]
# A library must not print log records unless the application configures logging.
logging.getLogger(__name__).addHandler(logging.NullHandler())
__version__ = "0.2.0"
