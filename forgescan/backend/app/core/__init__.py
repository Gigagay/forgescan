# app/core/__init__.py
"""Compatibility shims for core package.

This module applies runtime compatibility patches (minimal and safe) so that
3rd-party libraries with small API mismatches do not break tests or local dev.
"""

# Monkeypatch pydantic's email validator import to provide a small compatibility
# layer: older pydantic expected `parts.normalized` but current
# `email_validator` exposes `.email` on the ValidatedEmail result.
try:
    import types
    import pydantic.networks as _networks
    from email_validator import validate_email as _validate_email

    def _import_email_validator():
        """Provide a minimal module-like object with a `validate_email`
        function that returns a 'parts'-like object that matches pydantic's
        expectations (has `.normalized` and `.local_part`)."""
        mod = types.SimpleNamespace()

        def validate_email(email, check_deliverability=False, *args, **kwargs):
            # Call the real email-validator and adapt its return to a simple
            # object that pydantic expects.
            try:
                validated = _validate_email(email, check_deliverability=check_deliverability)
            except TypeError:
                # Fallback for older email-validator signatures
                validated = _validate_email(email)

            # If we already have a parts-like object (tuple/list with parts at idx 1)
            if isinstance(validated, (tuple, list)) and len(validated) >= 2:
                parts = validated[1]
                return parts

            # For ValidatedEmail objects, create a compatible parts object
            if hasattr(validated, "email"):
                return types.SimpleNamespace(normalized=validated.email, local_part=getattr(validated, "local_part", None))

            # Fallback: return what we got (best effort)
            return validated

        mod.validate_email = validate_email
        # Install our shim into pydantic's module so future calls use it
        _networks.email_validator = mod
        return None

    # Apply the shim so pydantic uses our compatibility wrapper
    _networks.import_email_validator = _import_email_validator

    # Call it immediately to replace any already-imported module with our shim
    try:
        _import_email_validator()
    except Exception:
        # If anything goes wrong, fall back to leaving pydantic's behavior unchanged
        pass

    # Wrap pydantic's validate_email helper so it calls the email-validator
    # implementation and always returns a parts-like object (not a tuple).
    def _validate_email_wrapper(value: str, *args, **kwargs):
        try:
            res = _validate_email(value, *args, **kwargs)
        except TypeError:
            res = _validate_email(value)

        # If validator returns tuple/list with parts at index 1, return that parts
        if isinstance(res, (tuple, list)) and len(res) >= 2:
            parts = res[1]
            if hasattr(parts, "normalized"):
                return parts

        # If it's a ValidatedEmail object, adapt it to have `.normalized` and `.local_part`
        if hasattr(res, "email"):
            return types.SimpleNamespace(normalized=res.email, local_part=getattr(res, "local_part", None))

        # If already parts-like, return as-is
        if hasattr(res, "normalized"):
            return res

        # Fallback: return res (may raise later in pydantic if incompatible)
        return res

    _networks.validate_email = _validate_email_wrapper
except Exception:
    # If anything goes wrong (missing packages), silently skip the shim so tests
    # will continue to raise the original error when appropriate.
    pass
