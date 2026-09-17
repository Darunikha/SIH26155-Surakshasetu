class AIUnavailableError(Exception):
    """Raised whenever the local LLM cannot be reached or returns an error.
    Callers surface this as ErrorCode.AI_UNAVAILABLE -- the API/UI must show
    an explicit "AI not connected" state, never a fabricated response."""
