from __future__ import annotations

from typing import Iterable, List
from urllib.parse import urlparse

import requests

from . import UnauthorizedDomainError


class SecureHTTPClient:
    """Very small wrapper around requests enforcing allowed domains."""

    def __init__(self, allowed_domains: Iterable[str]):
        self.allowed_domains: List[str] = [d.lower() for d in allowed_domains]
        self.session = requests.Session()

    def _check_url(self, url: str) -> None:
        hostname = urlparse(url).hostname or ""
        if hostname.lower() not in self.allowed_domains:
            raise UnauthorizedDomainError(
                f"Domain '{hostname}' is not allowed (allowed: {self.allowed_domains})"
            )

    def get(self, url: str, **kwargs):
        self._check_url(url)
        return self.session.get(url, **kwargs)

    def post(self, url: str, **kwargs):
        self._check_url(url)
        return self.session.post(url, **kwargs)

    def request(self, method: str, url: str, **kwargs):
        self._check_url(url)
        return self.session.request(method, url, **kwargs)


def create_secure_session(allowed_domains: Iterable[str]) -> requests.Session:
    client = SecureHTTPClient(allowed_domains)
    return client.session


__all__ = ["SecureHTTPClient", "create_secure_session"]
