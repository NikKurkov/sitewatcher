"""Compatibility exports for shared domain parsing."""
from ..utils.domains import DOMAIN_RE, _PERMISSIVE_DOMAIN_RE, normalize_domain, parse_domains

__all__ = ["DOMAIN_RE", "_PERMISSIVE_DOMAIN_RE", "normalize_domain", "parse_domains"]
