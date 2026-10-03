"""SEC-MODEL-01: model allowlist per principal (concept §7.1, §10 layer 2).

A request for a model, alias or skill the principal may not use is blocked (final): 1A turns that
into HTTP 403 + an incident. Sensitive data going to a model whose data classes do not allow it is
handled by the router (`route_local`), not here.
"""

from acl.controls.model_access.control import ModelAccessControl

__all__ = ["ModelAccessControl"]
