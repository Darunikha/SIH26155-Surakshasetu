class BlockchainUnavailableError(Exception):
    """Raised when the Fabric gateway sidecar cannot be reached or the
    network rejects the transaction. Callers must catch this and fall back
    to the PENDING queue -- an audit must never fail just because the
    blockchain is temporarily down (spec section 34)."""


class IntegrityViolationError(Exception):
    """Raised by the verifier when a recomputed hash does not match the
    hash recorded on-chain."""
