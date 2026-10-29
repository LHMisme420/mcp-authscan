"""Egress control and authorization errors."""

class EgressRefusalError(Exception):
    """Raised when a fetch targets a host outside the authorized set."""
