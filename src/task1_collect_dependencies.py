#!/usr/bin/env python3
"""
Задание 1.
Сбор зависимостей проекта в единый JSON-файл.

Скрипт ищет типовые файлы зависимостей Python-проекта:
- pyproject.toml
- setup.cfg
- setup.py
- requirements*.txt

Для Django 3.2 основная экосистема — PyPI, поэтому ecosystem = "pypi".
"""

from __future__ import annotations

import argparse
import configparser
import json
import re
from pathlib import Path
from typing import Iterable, Optional

from packaging.requirements import InvalidRequirement, Requirement

try:
    import tomllib  # Python 3.11+
except ModuleNotFoundError:  # pragma: no cover
    import tomli as tomllib  # type: ignore


DEPENDENCY_FILE_PATTERNS = (
    "pyproject.toml",
    "setup.cfg",
    "setup.py",
    "requirements*.txt",
)

SKIP_DIRS = {
    ".git",
    ".hg",
    ".svn",
    ".tox",
    ".venv",
    "venv",
    "env",
    "node_modules",
    "__pycache__",
    "dist",
    "build",
}


def normalize_name(name: str) -> str:
    """Приводим имя пакета к каноничному виду для сравнения."""
    return re.sub(r"[-_.]+", "-", name).lower().strip()


def build_pypi_url(name: str) -> str:
    return f"https://pypi.org/project/{normalize_name(name)}/"


def build_purl(name: str, version: str) -> str:
    """Формируем Package URL для PyPI-пакета."""
    safe_name = normalize_name(name)
    if version and version not in {"not-pinned", "not specified"}:
        return f"pkg:pypi/{safe_name}@{version}"
    return f"pkg:pypi/{safe_name}"


def extract_version(requirement: Requirement) -> str:
    """
    Извлекаем версию из Requirement.

    Если зависимость зафиксирована строго через ==, сохраняем точную версию.
    Если версия задана диапазоном, сохраняем диапазон, так как это тоже важная
    информация для дальнейшей проверки уязвимости.
    """
    specs = list(requirement.specifier)
    exact_versions = [spec.version for spec in specs if spec.operator in {"==", "==="}]
    if exact_versions:
        return exact_versions[0]
    if str(requirement.specifier):
        return str(requirement.specifier)
    return "not-pinned"


def requirement_to_record(raw: str, source_file: Path, project_path: Path) -> Optional[dict]:
    """Преобразуем строку зависимости в JSON-объект."""
    cleaned = raw.strip()
    if not cleaned or cleaned.startswith("#"):
        return None

    # Убираем inline-комментарии в requirements.txt.
    cleaned = re.split(r"\s+#", cleaned, maxsplit=1)[0].strip()

    # Пропускаем опции pip: -r, --index-url, -e и подобные.
    if cleaned.startswith(("-", "--")):
        return None

    # Убираем environment marker не будем, Requirement умеет его читать.
    try:
        req = Requirement(cleaned)
    except InvalidRequirement:
        return None

    version = extract_version(req)
    name = normalize_name(req.name)
    return {
        "name": name,
        "version": version,
        "ecosystem": "pypi",
        "url": build_pypi_url(name),
        "purl": build_purl(name, version),
        "source_file": str(source_file.relative_to(project_path)),
        "requirement": cleaned,
    }


def iter_dependency_files(project_path: Path) -> Iterable[Path]:
    """Ищем файлы зависимостей без обхода служебных директорий."""
    for path in project_path.rglob("*"):
        if path.is_dir():
            continue
        relative_parts = set(path.relative_to(project_path).parts)
        if relative_parts & SKIP_DIRS:
            continue
        if path.name == "pyproject.toml":
            yield path
        elif path.name == "setup.cfg":
            yield path
        elif path.name == "setup.py":
            yield path
        elif re.fullmatch(r"requirements.*\.txt", path.name):
            yield path


def parse_requirements_txt(path: Path, project_path: Path) -> list[dict]:
    records: list[dict] = []
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        rec = requirement_to_record(line, path, project_path)
        if rec:
            records.append(rec)
    return records


def parse_setup_cfg(path: Path, project_path: Path) -> list[dict]:
    records: list[dict] = []
    parser = configparser.ConfigParser()
    parser.read(path, encoding="utf-8")

    candidates: list[str] = []

    if parser.has_section("options") and parser.has_option("options", "install_requires"):
        candidates.extend(parser.get("options", "install_requires").splitlines())

    if parser.has_section("options.extras_require"):
        for _, value in parser.items("options.extras_require"):
            candidates.extend(value.splitlines())

    for line in candidates:
        rec = requirement_to_record(line, path, project_path)
        if rec:
            records.append(rec)

    return records


def parse_pyproject_toml(path: Path, project_path: Path) -> list[dict]:
    records: list[dict] = []
    data = tomllib.loads(path.read_text(encoding="utf-8", errors="ignore"))

    project = data.get("project", {})
    for dep in project.get("dependencies", []) or []:
        rec = requirement_to_record(dep, path, project_path)
        if rec:
            records.append(rec)

    optional = project.get("optional-dependencies", {}) or {}
    for deps in optional.values():
        for dep in deps or []:
            rec = requirement_to_record(dep, path, project_path)
            if rec:
                records.append(rec)

    # Poetry-проекты.
    poetry_deps = (
        data.get("tool", {})
        .get("poetry", {})
        .get("dependencies", {})
    )
    for name, value in poetry_deps.items():
        if name.lower() == "python":
            continue
        if isinstance(value, str):
            raw = f"{name}{value if value.startswith(('>', '<', '=', '!', '~')) else '==' + value}"
        else:
            version = value.get("version", "") if isinstance(value, dict) else ""
            raw = f"{name}{version}" if version else name
        rec = requirement_to_record(raw, path, project_path)
        if rec:
            records.append(rec)

    return records


def parse_setup_py_light(path: Path, project_path: Path) -> list[dict]:
    """
    Лёгкий разбор setup.py.

    Это не полноценное выполнение setup.py, а безопасный поиск списков вида:
    install_requires=["pkg>=1.0"], extras_require={...}
    """
    text = path.read_text(encoding="utf-8", errors="ignore")
    records: list[dict] = []

    patterns = [
        r"install_requires\s*=\s*\[(.*?)\]",
        r"tests_require\s*=\s*\[(.*?)\]",
    ]
    for pattern in patterns:
        for match in re.finditer(pattern, text, flags=re.DOTALL):
            block = match.group(1)
            for quoted in re.findall(r"['\"]([^'\"]+)['\"]", block):
                rec = requirement_to_record(quoted, path, project_path)
                if rec:
                    records.append(rec)

    # Достаём строки из extras_require, даже если структура словаря сложнее.
    extras_match = re.search(r"extras_require\s*=\s*\{(.*?)\}\s*,", text, flags=re.DOTALL)
    if extras_match:
        for quoted in re.findall(r"['\"]([^'\"]+)['\"]", extras_match.group(1)):
            if re.fullmatch(r"[A-Za-z0-9_.-]+", quoted):
                # Это может быть имя extra-группы, а не зависимость.
                continue
            rec = requirement_to_record(quoted, path, project_path)
            if rec:
                records.append(rec)

    return records


def collect_dependencies(project_path: Path) -> tuple[list[dict], dict]:
    all_records: list[dict] = []
    found_files: list[str] = []

    for dep_file in sorted(iter_dependency_files(project_path)):
        found_files.append(str(dep_file.relative_to(project_path)))
        if dep_file.name == "setup.cfg":
            all_records.extend(parse_setup_cfg(dep_file, project_path))
        elif dep_file.name == "pyproject.toml":
            all_records.extend(parse_pyproject_toml(dep_file, project_path))
        elif dep_file.name == "setup.py":
            all_records.extend(parse_setup_py_light(dep_file, project_path))
        elif re.fullmatch(r"requirements.*\.txt", dep_file.name):
            all_records.extend(parse_requirements_txt(dep_file, project_path))

    # Дедупликация: одна зависимость может встретиться в нескольких файлах.
    dedup: dict[tuple[str, str, str], dict] = {}
    for rec in all_records:
        key = (rec["ecosystem"], rec["name"], rec["version"])
        if key not in dedup:
            dedup[key] = rec
        else:
            prev_sources = set(str(dedup[key].get("source_file", "")).split("; "))
            prev_sources.add(rec["source_file"])
            dedup[key]["source_file"] = "; ".join(sorted(prev_sources))

    result = sorted(dedup.values(), key=lambda x: (x["ecosystem"], x["name"], x["version"]))

    summary: dict[str, object] = {
        "dependency_files": found_files,
        "total_dependencies": len(result),
        "by_ecosystem": {},
    }
    by_ecosystem: dict[str, int] = {}
    for rec in result:
        by_ecosystem[rec["ecosystem"]] = by_ecosystem.get(rec["ecosystem"], 0) + 1
    summary["by_ecosystem"] = by_ecosystem

    return result, summary


def main() -> None:
    parser = argparse.ArgumentParser(description="Collect project dependencies into result_task_1.json")
    parser.add_argument("--project-path", required=True, help="Path to cloned project, e.g. data/django")
    parser.add_argument("--output", default="results/result_task_1.json", help="Output JSON path")
    args = parser.parse_args()

    project_path = Path(args.project_path).resolve()
    output_path = Path(args.output).resolve()

    if not project_path.exists():
        raise SystemExit(f"Project path not found: {project_path}")

    dependencies, summary = collect_dependencies(project_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    payload = {
        "project": {
            "name": "django",
            "repository": "https://github.com/django/django",
            "selected_version": "3.2",
        },
        "summary": summary,
        "dependencies": dependencies,
    }

    output_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")

    print(f"[OK] Dependencies saved to: {output_path}")
    print(f"[OK] Total dependencies: {summary['total_dependencies']}")
    print(f"[OK] By ecosystem: {summary['by_ecosystem']}")
    print("[INFO] Dependency files found:")
    for file_name in summary["dependency_files"]:  # type: ignore[index]
        print(f"  - {file_name}")


if __name__ == "__main__":
    main()
