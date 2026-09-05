"""Report-Erzeugung: JSON (schema-versioniert), Text, curl-Repro."""

from .curl import to_curl
from .json_out import RunMeta, write_json
from .text_out import render_text

__all__ = ["write_json", "render_text", "to_curl", "RunMeta"]
