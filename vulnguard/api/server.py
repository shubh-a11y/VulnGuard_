"""Compatibility entry point for the maintained dashboard API."""

from vulnguard.ui.server import create_app

app = create_app()

__all__ = ["app", "create_app"]
