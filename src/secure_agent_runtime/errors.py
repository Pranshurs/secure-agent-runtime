"""Exception types. Every error SAR raises on purpose derives from :class:`SARError`."""

from __future__ import annotations


class SARError(Exception):
    pass


class StoreError(SARError):
    """The database could not be read or written. Nothing was half-applied: every state
    change and its audit event share one transaction."""


class CredentialReused(SARError):
    """An approval credential was presented a second time."""


class StoreLocked(StoreError):
    """Another process (or another Runtime in this process) already owns this database.

    SAR's at-most-once-per-approval guarantee is established for exactly one owner per
    database file; a second owner could recover and re-dispatch actions the first one is
    still executing, so it is refused.
    """
