"""Redact configuration values before displaying them in diagnostics or bot replies."""


def redact_configuration(value):
    if isinstance(value, dict):
        return {
            key: ("[configured]" if item else item)
            if any(part in key.lower() for part in ("token", "password", "secret", "api_key", "proxy"))
            else redact_configuration(item)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [redact_configuration(item) for item in value]
    return value
