"""The definition of what counts as "critical content" on a page.

This is the policy layer: it is rendered into the model prompt and can be
replaced wholesale with ``--categories-file`` so each team can encode its own
definition of sensitive exposure.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .models import Severity


@dataclass(frozen=True)
class Category:
    id: str
    title: str
    description: str
    default_severity: Severity

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "description": self.description,
            "default_severity": self.default_severity.value,
        }


DEFAULT_CATEGORIES: tuple[Category, ...] = (
    Category(
        "exposed_credentials",
        "Exposed credentials or secrets",
        "Passwords, API keys, bearer tokens, private keys, connection strings or "
        "session identifiers rendered in the page.",
        Severity.CRITICAL,
    ),
    Category(
        "unauthenticated_admin",
        "Unauthenticated administrative interface",
        "An admin panel, management console, CMS backend or configuration UI that is "
        "reachable without any login step, or that shows authenticated content.",
        Severity.CRITICAL,
    ),
    Category(
        "database_or_ops_console",
        "Database or operations console",
        "phpMyAdmin, Adminer, Kibana, Grafana, Jenkins, RabbitMQ, Elasticsearch, "
        "Prometheus, Consul or similar infrastructure tooling exposed to the visitor.",
        Severity.CRITICAL,
    ),
    Category(
        "personal_data",
        "Personal or sensitive data",
        "Names paired with contact details, national IDs, payment or bank details, "
        "health records, HR data, or customer lists visible without authentication.",
        Severity.HIGH,
    ),
    Category(
        "internal_documents",
        "Internal or confidential documents",
        "Content marked internal/confidential/restricted, contracts, invoices, "
        "meeting minutes, or internal wikis and runbooks.",
        Severity.HIGH,
    ),
    Category(
        "directory_listing",
        "Directory listing",
        "An auto-generated file index such as 'Index of /' exposing the contents of a "
        "directory.",
        Severity.HIGH,
    ),
    Category(
        "backup_or_source_disclosure",
        "Backup files or source code disclosure",
        "Downloadable archives, database dumps, .env files, version-control metadata, "
        "or raw application source rendered in the browser.",
        Severity.HIGH,
    ),
    Category(
        "debug_output",
        "Debug output or stack trace",
        "Framework debug pages, stack traces, phpinfo(), environment variable dumps or "
        "verbose error pages revealing application internals.",
        Severity.HIGH,
    ),
    Category(
        "malicious_or_defaced",
        "Defacement, phishing or injected content",
        "Defacement messages, crypto/gambling spam, SEO injection, or a login form "
        "impersonating another brand.",
        Severity.CRITICAL,
    ),
    Category(
        "infrastructure_disclosure",
        "Infrastructure disclosure",
        "Internal hostnames, private IP addresses, software versions, server banners, "
        "cloud metadata or network topology shown to the visitor.",
        Severity.MEDIUM,
    ),
    Category(
        "open_api_surface",
        "Exposed API documentation or console",
        "Swagger/OpenAPI UI, GraphQL playground or similar interactive API explorer "
        "that allows live calls against the service.",
        Severity.MEDIUM,
    ),
    Category(
        "default_or_placeholder_page",
        "Default, placeholder or setup page",
        "Untouched web-server default pages, installation wizards, 'it works' pages or "
        "parked-domain placeholders indicating an unmaintained host.",
        Severity.LOW,
    ),
    Category(
        "error_page",
        "Error page",
        "A generic 4xx/5xx error page with no sensitive detail.",
        Severity.INFO,
    ),
)


def load_categories(path: str | Path | None = None) -> list[Category]:
    """Return the default categories, or the custom set defined in a JSON file.

    The file must contain a list of objects with ``id``, ``title``,
    ``description`` and ``default_severity``.
    """
    if path is None:
        return list(DEFAULT_CATEGORIES)

    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if isinstance(data, dict) and "categories" in data:
        data = data["categories"]
    if not isinstance(data, list) or not data:
        raise ValueError(f"{path}: expected a non-empty list of category objects")

    categories: list[Category] = []
    for index, entry in enumerate(data):
        if not isinstance(entry, dict):
            raise ValueError(f"{path}: entry {index} is not an object")
        missing = [k for k in ("id", "title", "description") if not entry.get(k)]
        if missing:
            raise ValueError(f"{path}: entry {index} is missing {', '.join(missing)}")
        categories.append(
            Category(
                id=str(entry["id"]),
                title=str(entry["title"]),
                description=str(entry["description"]),
                default_severity=Severity.parse(
                    entry.get("default_severity"), Severity.MEDIUM
                ),
            )
        )
    return categories
