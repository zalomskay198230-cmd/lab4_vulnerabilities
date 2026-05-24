#!/usr/bin/env python3
"""
Задание 2.
Проверка зависимостей через GitHub Security Advisory GraphQL API.

Перед запуском задайте переменную окружения:
Windows PowerShell:
  $env:GITHUB_TOKEN="ghp_..."
Linux/macOS:
  export GITHUB_TOKEN="ghp_..."
"""

from __future__ import annotations

import argparse
import json
import os
import re
import time
from functools import lru_cache
from pathlib import Path
from typing import Any, Optional

import requests
from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.version import InvalidVersion, Version

GITHUB_GRAPHQL_URL = "https://api.github.com/graphql"

ECOSYSTEM_TO_GHSA = {
    "pypi": "PIP",
    "pip": "PIP",
    "npm": "NPM",
    "maven": "MAVEN",
    "rubygems": "RUBYGEMS",
    "composer": "COMPOSER",
    "nuget": "NUGET",
    "go": "GO",
    "golang": "GO",
    "rust": "RUST",
    "cargo": "RUST",
    "erlang": "ERLANG",
    "actions": "ACTIONS",
    "pub": "PUB",
    "swift": "SWIFT",
}

QUERY = """
query($ecosystem: SecurityAdvisoryEcosystem!, $package: String!, $after: String) {
  securityVulnerabilities(first: 100, ecosystem: $ecosystem, package: $package, after: $after) {
    pageInfo {
      hasNextPage
      endCursor
    }
    nodes {
      package {
        name
        ecosystem
      }
      vulnerableVersionRange
      firstPatchedVersion {
        identifier
      }
      advisory {
        ghsaId
        summary
        severity
        permalink
        identifiers {
          type
          value
        }
      }
    }
  }
}
"""


def normalize_name(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower().strip()


def normalize_specifier(raw: str) -> str:
    """Чистим диапазон версий до формата, который понимает packaging."""
    value = raw.strip()
    value = value.replace(" ", "")
    value = value.replace(",<", ",<")
    value = value.replace(",>", ",>")
    return value


def is_exact_version(value: str) -> bool:
    if not value or value in {"not-pinned", "not specified"}:
        return False
    return not value.strip().startswith(("<", ">", "=", "!", "~"))


def parse_specifier(raw: str) -> Optional[SpecifierSet]:
    if not raw or raw in {"not-pinned", "not specified"}:
        return None
    try:
        if is_exact_version(raw):
            return SpecifierSet(f"=={raw}")
        return SpecifierSet(normalize_specifier(raw))
    except InvalidSpecifier:
        return None


def extract_versions_from_text(text: str) -> list[Version]:
    versions: list[Version] = []
    for item in re.findall(r"\d+(?:\.\d+){0,4}(?:[a-zA-Z0-9_.+-]*)?", text):
        try:
            versions.append(Version(item.rstrip(".,")))
        except InvalidVersion:
            continue
    return versions


def bump_patch(version: Version) -> Optional[Version]:
    parts = list(version.release)
    if not parts:
        return None
    while len(parts) < 3:
        parts.append(0)
    parts[-1] += 1
    try:
        return Version(".".join(map(str, parts)))
    except InvalidVersion:
        return None


def bump_minor(version: Version) -> Optional[Version]:
    parts = list(version.release)
    if not parts:
        return None
    while len(parts) < 2:
        parts.append(0)
    parts[1] += 1
    if len(parts) >= 3:
        parts[2] = 0
    try:
        return Version(".".join(map(str, parts[:3])))
    except InvalidVersion:
        return None


def specifiers_may_intersect(dep_version_or_range: str, vuln_range: str) -> bool:
    """
    Проверяем применимость уязвимости.

    Если версия точная — проверяем попадание в vulnerable_range.
    Если у зависимости диапазон — приблизительно проверяем пересечение диапазонов.
    Если данных недостаточно, возвращаем True, чтобы не потерять потенциальную уязвимость.
    """
    if not dep_version_or_range or dep_version_or_range in {"not-pinned", "not specified"}:
        return True

    dep_spec = parse_specifier(dep_version_or_range)
    vuln_spec = parse_specifier(vuln_range)
    if vuln_spec is None:
        return True
    if dep_spec is None:
        return True

    # Точная версия.
    if is_exact_version(dep_version_or_range):
        try:
            return Version(dep_version_or_range) in vuln_spec
        except InvalidVersion:
            return True

    # Диапазон: проверяем набор характерных точек.
    candidates: set[Version] = set()
    for version in extract_versions_from_text(dep_version_or_range + "," + vuln_range):
        candidates.add(version)
        patch = bump_patch(version)
        minor = bump_minor(version)
        if patch:
            candidates.add(patch)
        if minor:
            candidates.add(minor)

    for base in ["0", "0.0.1", "1", "1.0.0", "2.0.0", "3.0.0", "10.0.0"]:
        try:
            candidates.add(Version(base))
        except InvalidVersion:
            pass

    for candidate in candidates:
        if candidate in dep_spec and candidate in vuln_spec:
            return True

    return False


@lru_cache(maxsize=512)
def fetch_security_vulnerabilities(package_name: str, ecosystem: str, token: str) -> list[dict[str, Any]]:
    """Получаем все GHSA-уязвимости для пакета."""
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
    }
    variables: dict[str, Any] = {
        "ecosystem": ecosystem,
        "package": package_name,
        "after": None,
    }

    vulnerabilities: list[dict[str, Any]] = []
    while True:
        response = requests.post(
            GITHUB_GRAPHQL_URL,
            json={"query": QUERY, "variables": variables},
            headers=headers,
            timeout=30,
        )
        if response.status_code == 403 and "rate limit" in response.text.lower():
            raise RuntimeError("GitHub API rate limit exceeded. Повторите позже или используйте другой token.")
        response.raise_for_status()
        payload = response.json()
        if "errors" in payload:
            raise RuntimeError(json.dumps(payload["errors"], ensure_ascii=False, indent=2))

        connection = payload["data"]["securityVulnerabilities"]
        vulnerabilities.extend(connection.get("nodes") or [])
        page_info = connection.get("pageInfo") or {}
        if not page_info.get("hasNextPage"):
            break
        variables["after"] = page_info.get("endCursor")
        time.sleep(0.2)

    return vulnerabilities


def convert_vulnerability(node: dict[str, Any]) -> dict[str, Any]:
    advisory = node.get("advisory") or {}
    first_patched = node.get("firstPatchedVersion") or {}
    identifiers = advisory.get("identifiers") or []
    cve_ids = [item.get("value") for item in identifiers if item.get("type") == "CVE"]

    return {
        "name": advisory.get("ghsaId"),
        "summary": advisory.get("summary"),
        "severity": str(advisory.get("severity", "UNKNOWN")).lower(),
        "vulnerable_range": node.get("vulnerableVersionRange"),
        "first_patched_version": first_patched.get("identifier"),
        "url": advisory.get("permalink"),
        "cve": cve_ids,
    }


def choose_secure_version(current_version: str, vulnerabilities: list[dict[str, Any]]) -> str:
    """Выбираем рекомендуемую безопасную версию по максимальной first_patched_version."""
    patched_versions: list[Version] = []
    raw_versions: list[str] = []

    for vuln in vulnerabilities:
        patched = vuln.get("first_patched_version")
        if not patched:
            continue
        raw_versions.append(str(patched))
        try:
            patched_versions.append(Version(str(patched)))
        except InvalidVersion:
            continue

    if patched_versions:
        return str(max(patched_versions))
    if raw_versions:
        return sorted(raw_versions)[-1]
    if vulnerabilities:
        return "manual-review-required"
    return current_version


def check_dependencies(input_path: Path, output_path: Path, token: str) -> None:
    source = json.loads(input_path.read_text(encoding="utf-8"))
    dependencies = source.get("dependencies", source if isinstance(source, list) else [])

    checked: list[dict[str, Any]] = []
    total_vulnerabilities = 0

    for dep in dependencies:
        dep_name = normalize_name(dep.get("name", ""))
        ecosystem = str(dep.get("ecosystem", "")).lower()
        ghsa_ecosystem = ECOSYSTEM_TO_GHSA.get(ecosystem)

        enriched = dict(dep)
        enriched["vulnerabilities"] = []
        enriched["secure_version"] = dep.get("version", "not specified")

        if not dep_name or not ghsa_ecosystem:
            enriched["scan_note"] = f"Unsupported ecosystem for GHSA: {ecosystem}"
            checked.append(enriched)
            continue

        try:
            nodes = fetch_security_vulnerabilities(dep_name, ghsa_ecosystem, token)
        except Exception as exc:  # noqa: BLE001
            enriched["scan_error"] = str(exc)
            checked.append(enriched)
            continue

        applicable = []
        for node in nodes:
            vuln_range = node.get("vulnerableVersionRange") or ""
            if specifiers_may_intersect(str(dep.get("version", "")), vuln_range):
                applicable.append(convert_vulnerability(node))

        enriched["vulnerabilities"] = applicable
        enriched["secure_version"] = choose_secure_version(str(dep.get("version", "not specified")), applicable)
        total_vulnerabilities += len(applicable)
        checked.append(enriched)

        print(f"[OK] {dep_name}: {len(applicable)} applicable vulnerabilities")
        time.sleep(0.1)

    summary = {
        "total_dependencies": len(checked),
        "vulnerable_dependencies": sum(1 for dep in checked if dep.get("vulnerabilities")),
        "total_applicable_vulnerabilities": total_vulnerabilities,
    }

    payload = {
        "project": source.get("project", {}),
        "summary": summary,
        "dependencies": checked,
    }
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"[OK] GHSA scan saved to: {output_path}")
    print(f"[OK] Summary: {summary}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Check dependencies using GitHub Security Advisory GraphQL API")
    parser.add_argument("--input", default="results/result_task_1.json", help="Input JSON from task 1")
    parser.add_argument("--output", default="results/result_task_2.json", help="Output JSON path")
    args = parser.parse_args()

    token = os.environ.get("GITHUB_TOKEN")
    if not token:
        raise SystemExit("Set GITHUB_TOKEN environment variable before running this script.")

    check_dependencies(Path(args.input).resolve(), Path(args.output).resolve(), token)


if __name__ == "__main__":
    main()
