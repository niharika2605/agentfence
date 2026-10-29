"""Shared error for all canonicalizers (invariant I4: when unsure, deny)."""
from agentfence.models import Decision, ReasonCode


class CanonicalizationError(Exception):
    """A value could not be turned into one safe canonical form.

    The message is a fixed phrase. It never repeats the raw value.
    """


def block_for(call_id: str, field: str, error: CanonicalizationError) -> Decision:
    """The block Decision the pipeline returns when canonicalization fails."""
    return Decision.block(
        call_id,
        ReasonCode.CANONICALIZATION_FAILED,
        f"argument '{field}' could not be made safe: {error}",
    )