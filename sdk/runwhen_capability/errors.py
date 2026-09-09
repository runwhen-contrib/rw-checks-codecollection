"""Exceptions the SDK raises. All of them are ordinary Python exceptions --
the task host (see host.py) catches anything a setup/task function raises and
turns it into a failed setup/task result entry; it never needs to special-case
these types.
"""


class CredentialNotFoundError(KeyError):
    """Raised by Context.credential() when the named credential was not
    resolved for this request."""


class CapabilityLoadError(RuntimeError):
    """Raised when a capability directory's manifest.yaml or tasks.py cannot
    be loaded."""


class UnknownTaskError(RuntimeError):
    """Raised when a request names a setup/task that is not registered by the
    capability's tasks.py."""
