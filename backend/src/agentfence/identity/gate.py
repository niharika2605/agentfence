"""The identity step of the pipeline (Day 13).

Turns a request from the agent plus its token into a ToolCall, or a block Decision.
Who the caller is, and which role they have, come only from the verified token.
Nothing in the request can change them (invariant I7).
"""
from uuid import uuid4

from agentfence.identity.roles import role_allows_tool
from agentfence.identity.tokens import IdentityError, TokenService
from agentfence.models import Decision, ReasonCode, ToolCall, ToolCallRequest


def authorize_call(
    service: TokenService, token: object, request: ToolCallRequest
) -> ToolCall | Decision:
    try:
        identity = service.verify(token, session_id=request.session_id)
    except IdentityError:
        return Decision.block(
            uuid4().hex, ReasonCode.IDENTITY_INVALID, "identity could not be verified"
        )

    call = ToolCall.from_request(
        request, user_id=identity.user_id, agent_id=identity.agent_id, role=identity.role
    )
    if not identity.allows_tool(request.tool):
        return Decision.block(
            call.call_id, ReasonCode.ROLE_DENIED, "tool is outside the scope of this session"
        )
    if not role_allows_tool(identity.role, request.tool):
        return Decision.block(
            call.call_id, ReasonCode.ROLE_DENIED, "role is not allowed to use this tool"
        )
    return call