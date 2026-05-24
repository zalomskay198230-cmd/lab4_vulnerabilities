#!/usr/bin/env python3
"""
Задание 4.
Инвентаризация операционной системы и установленных пакетов.

Все данные берутся из системы:
- /etc/os-release
- uname -m
- rpm -qa или dpkg-query

Дополнительно скрипт умеет формировать минимальный CycloneDX SBOM для задания 5.
"""


import argparse
import json
import platform
import re
import shutil
import subprocess
from datetime import datetime, timezone
from uuid import uuid4
from pathlib import Path
from typing import Optional, Any, Dict, List, Tuple
from urllib.parse import quote


def run_command(command: List[str]) -> str:
    result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True, check=True)
    return result.stdout


def read_os_release() -> Dict[str, str]:
    path = Path("/etc/os-release")
    data: Dict[str, str] = {}
    if not path.exists():
        return data

    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        value = value.strip().strip('"').strip("'")
        data[key] = value
    return data


def get_os_info() -> Dict[str, str]:
    os_release = read_os_release()
    name = os_release.get("NAME") or platform.system()
    version = os_release.get("VERSION") or os_release.get("VERSION_ID") or platform.release()
    description = os_release.get("PRETTY_NAME") or f"{name} {version}"

    os_info = {
        "name": name,
        "version": version,
        "arch": platform.machine(),
        "id": os_release.get("ID", "unknown"),
        "version_id": os_release.get("VERSION_ID", "unknown"),
        "description": description,
    }

    codename = os_release.get("VERSION_CODENAME") or os_release.get("UBUNTU_CODENAME")
    if codename:
        os_info["codename"] = codename

    return os_info


def first_sentence(text: str) -> str:
    text = " ".join((text or "").split())
    if not text:
        return ""
    match = re.match(r"^(.+?[.!?])\s+", text)
    return match.group(1) if match else text


def collect_rpm_packages() -> List[Dict[str, object]]:
    query_format = "%{NAME}\t%{VERSION}-%{RELEASE}\t%{ARCH}\t%{SIZE}\t%{SUMMARY}\n"
    output = run_command(["rpm", "-qa", f"--queryformat={query_format}"])
    packages: List[Dict[str, object]] = []

    for line in output.splitlines():
        parts = line.split("\t", 4)
        if len(parts) < 5:
            continue
        name, version, arch, size, summary = parts
        item: Dict[str, object] = {
            "name": name,
            "version": version,
            "arch": arch,
        }
        if summary.strip():
            item["description"] = first_sentence(summary)
        if str(size).isdigit():
            item["size"] = int(size)
        packages.append(item)

    return sorted(packages, key=lambda x: str(x["name"]))


def collect_dpkg_packages() -> List[Dict[str, object]]:
    fmt = "${binary:Package}\t${Version}\t${Architecture}\t${Installed-Size}\t${binary:Summary}\n"
    output = run_command(["dpkg-query", "-W", f"-f={fmt}"])
    packages: List[Dict[str, object]] = []

    for line in output.splitlines():
        parts = line.split("\t", 4)
        if len(parts) < 5:
            continue
        name, version, arch, installed_size_kb, summary = parts
        item: Dict[str, object] = {
            "name": name,
            "version": version,
            "arch": arch,
        }
        if summary.strip():
            item["description"] = first_sentence(summary)
        if str(installed_size_kb).isdigit():
            item["size"] = int(installed_size_kb) * 1024
        packages.append(item)

    return sorted(packages, key=lambda x: str(x["name"]))


def collect_packages() -> Tuple[List[Dict[str, object]], str]:
    if shutil.which("rpm"):
        return collect_rpm_packages(), "rpm"
    if shutil.which("dpkg-query"):
        return collect_dpkg_packages(), "dpkg"
    raise RuntimeError("Не найден поддерживаемый пакетный менеджер: rpm или dpkg-query")


def build_purl(os_info: Dict[str, str], package: Dict[str, object], package_manager: str) -> str:
    name = quote(str(package["name"]), safe="")
    version = quote(str(package["version"]), safe="")
    arch = quote(str(package.get("arch", "")), safe="")

    if package_manager == "rpm":
        distro = quote(os_info.get("id", "linux"), safe="")
        return f"pkg:rpm/{distro}/{name}@{version}?arch={arch}"
    if package_manager == "dpkg":
        distro = quote(os_info.get("id", "debian"), safe="")
        return f"pkg:deb/{distro}/{name}@{version}?arch={arch}"
    return f"pkg:generic/{name}@{version}?arch={arch}"


def build_cyclonedx(os_info: Dict[str, str], packages: List[Dict[str, object]], package_manager: str) -> Dict[str, object]:
    components = []
    for package in packages:
        purl = build_purl(os_info, package, package_manager)
        component = {
            "type": "library",
            "bom-ref": purl,
            "name": package["name"],
            "version": package["version"],
            "purl": purl,
            "properties": [
                {"name": "package_manager", "value": package_manager},
                {"name": "arch", "value": str(package.get("arch", ""))},
            ],
        }
        if package.get("description"):
            component["description"] = package["description"]
        components.append(component)

    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "tools": {
                "components": [
                    {
                        "type": "application",
                        "name": "task4_inventory_os.py",
                        "version": "1.0",
                    }
                ]
            },
            "component": {
                "type": "operating-system",
                "name": os_info.get("name"),
                "version": os_info.get("version_id") or os_info.get("version"),
                "description": os_info.get("description"),
            },
        },
        "components": components,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Inventory OS and installed packages")
    parser.add_argument("--output", default="results/result_task_4.json", help="Output JSON path")
    parser.add_argument("--cyclonedx-output", help="Optional CycloneDX SBOM output path for task 5")
    args = parser.parse_args()

    os_info = get_os_info()
    packages, package_manager = collect_packages()

    result = {
        "OS": os_info,
        "package_manager": package_manager,
        "packages_count": len(packages),
        "packages": packages,
    }

    output_path = Path(args.output).resolve()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"[OK] OS inventory saved to: {output_path}")
    print(f"[OK] Packages collected: {len(packages)}")

    if args.cyclonedx_output:
        cdx_path = Path(args.cyclonedx_output).resolve()
        cdx_path.parent.mkdir(parents=True, exist_ok=True)
        cdx = build_cyclonedx(os_info, packages, package_manager)
        cdx_path.write_text(json.dumps(cdx, ensure_ascii=False, indent=2), encoding="utf-8")
        print(f"[OK] CycloneDX SBOM saved to: {cdx_path}")


if __name__ == "__main__":
    main()
