#!/usr/bin/env python3
"""
Задание 5.
Сравнение инвентаризации и результатов OSV Scanner до/после обновления ОС.
"""


import argparse
import json
from pathlib import Path
from typing import Any, Dict, Set


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def package_map_from_task4(payload: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    return {str(pkg.get("name")): pkg for pkg in payload.get("packages", []) if pkg.get("name")}


def package_map_from_cyclonedx(payload: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    result: Dict[str, Dict[str, Any]] = {}
    for component in payload.get("components", []) or []:
        name = component.get("name")
        if name:
            result[str(name)] = component
    return result


def compare_package_sets(before: Dict[str, Dict[str, Any]], after: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    before_names = set(before)
    after_names = set(after)
    common = before_names & after_names

    changed_versions = []
    for name in sorted(common):
        before_version = str(before[name].get("version", ""))
        after_version = str(after[name].get("version", ""))
        if before_version != after_version:
            changed_versions.append(
                {
                    "name": name,
                    "before": before_version,
                    "after": after_version,
                }
            )

    return {
        "before_count": len(before_names),
        "after_count": len(after_names),
        "added_count": len(after_names - before_names),
        "removed_count": len(before_names - after_names),
        "unchanged_name_count": len(common),
        "changed_versions_count": len(changed_versions),
        "added_packages": sorted(after_names - before_names),
        "removed_packages": sorted(before_names - after_names),
        "changed_versions": changed_versions,
    }


def collect_vulnerability_ids(payload: Any) -> set[str]:
    """
    Рекурсивно собираем идентификаторы уязвимостей из JSON OSV Scanner.
    Формат вывода у разных версий scanner может отличаться, поэтому не привязываемся
    к одному конкретному пути.
    """
    ids: set[str] = set()

    def walk(value: Any) -> None:
        if isinstance(value, dict):
            possible_id = value.get("id") or value.get("ghsaId") or value.get("cve")
            if isinstance(possible_id, str) and (
                possible_id.startswith("OSV-")
                or possible_id.startswith("GHSA-")
                or possible_id.startswith("CVE-")
                or possible_id.startswith("PYSEC-")
                or possible_id.startswith("RUSTSEC-")
            ):
                ids.add(possible_id)
            for child in value.values():
                walk(child)
        elif isinstance(value, list):
            for item in value:
                walk(item)

    walk(payload)
    return ids


def summarize_osv(before_payload: Any, after_payload: Any) -> Dict[str, Any]:
    before_ids = collect_vulnerability_ids(before_payload)
    after_ids = collect_vulnerability_ids(after_payload)
    return {
        "before_vulnerabilities_count": len(before_ids),
        "after_vulnerabilities_count": len(after_ids),
        "fixed_or_disappeared_count": len(before_ids - after_ids),
        "new_or_remaining_after_update_count": len(after_ids),
        "fixed_or_disappeared": sorted(before_ids - after_ids),
        "new_after_update": sorted(after_ids - before_ids),
        "still_present": sorted(before_ids & after_ids),
    }


def compare_task4_and_sbom(task4_payload: Dict[str, Any], sbom_payload: Dict[str, Any]) -> Dict[str, Any]:
    task4_packages = package_map_from_task4(task4_payload)
    sbom_packages = package_map_from_cyclonedx(sbom_payload)
    task4_names = set(task4_packages)
    sbom_names = set(sbom_packages)
    return {
        "task4_packages_count": len(task4_names),
        "sbom_components_count": len(sbom_names),
        "present_in_both_count": len(task4_names & sbom_names),
        "missing_in_sbom_count": len(task4_names - sbom_names),
        "extra_in_sbom_count": len(sbom_names - task4_names),
        "missing_in_sbom_examples": sorted(task4_names - sbom_names)[:50],
        "extra_in_sbom_examples": sorted(sbom_names - task4_names)[:50],
    }


def make_markdown(summary: Dict[str, Any]) -> str:
    pkg = summary["task4_before_after"]
    sbom = summary["sbom_before_after"]
    osv = summary["osv_before_after"]
    quality = summary["task4_vs_sbom_quality"]

    lines = [
        "# Анализ результатов задания 5",
        "",
        "## 1. Сравнение пакетов ОС до и после обновления по result_task_4",
        "",
        f"До обновления было обнаружено пакетов: **{pkg['before_count']}**.",
        f"После обновления было обнаружено пакетов: **{pkg['after_count']}**.",
        f"Добавлено пакетов: **{pkg['added_count']}**.",
        f"Удалено пакетов: **{pkg['removed_count']}**.",
        f"Количество пакетов с изменившейся версией: **{pkg['changed_versions_count']}**.",
        "",
        "## 2. Сравнение CycloneDX SBOM до и после обновления",
        "",
        f"В SBOM до обновления компонентов: **{sbom['before_count']}**.",
        f"В SBOM после обновления компонентов: **{sbom['after_count']}**.",
        f"Компонентов с изменившейся версией: **{sbom['changed_versions_count']}**.",
        "",
        "## 3. Сравнение результатов OSV Scanner",
        "",
        f"Уязвимостей до обновления: **{osv['before_vulnerabilities_count']}**.",
        f"Уязвимостей после обновления: **{osv['after_vulnerabilities_count']}**.",
        f"Уязвимостей, исчезнувших после обновления: **{osv['fixed_or_disappeared_count']}**.",
        "",
        "## 4. Сравнение инвентаризации задания 4 и SBOM",
        "",
        f"Пакетов в result_task_4: **{quality['task4_packages_count']}**.",
        f"Компонентов в CycloneDX SBOM: **{quality['sbom_components_count']}**.",
        f"Совпали по имени: **{quality['present_in_both_count']}**.",
        f"Отсутствуют в SBOM: **{quality['missing_in_sbom_count']}**.",
        f"Лишние в SBOM относительно result_task_4: **{quality['extra_in_sbom_count']}**.",
        "",
        "## 5. Оценка качества выполнения задания 4",
        "",
        "Минимально достаточным для инвентаризации было собрать название пакета, версию, архитектуру и сведения об ОС. "
        "Эти данные позволяют сопоставить установленный компонент с базами уязвимостей и понять, относится ли найденная уязвимость к конкретной версии пакета.",
        "",
        "Избыточным может считаться сохранение полного описания пакета, поэтому в скрипте берётся только первая строка или первое предложение. "
        "Это уменьшает размер итогового JSON и делает файл удобнее для анализа.",
        "",
        "Для полноценной промышленной инвентаризации дополнительно было бы полезно фиксировать источник репозитория, поставщика пакета, дату установки, контрольные суммы файлов и зависимости между пакетами. "
        "В рамках лабораторной работы достаточно базовой информации, так как основная цель — получить перечень компонентов и сравнить его с результатами сканирования.",
    ]

    if pkg["changed_versions"]:
        lines.extend(["", "## Примеры пакетов с изменившейся версией", "", "| Пакет | До | После |", "|---|---|---|"])
        for item in pkg["changed_versions"][:30]:
            lines.append(f"| {item['name']} | {item['before']} | {item['after']} |")

    return "\n".join(lines) + "\n"


def main() -> None:
    parser = argparse.ArgumentParser(description="Compare task 5 results before/after OS update")
    parser.add_argument("--task4-before", required=True)
    parser.add_argument("--task4-after", required=True)
    parser.add_argument("--sbom-before", required=True)
    parser.add_argument("--sbom-after", required=True)
    parser.add_argument("--osv-before", required=True)
    parser.add_argument("--osv-after", required=True)
    parser.add_argument("--output-json", default="results/result_task_5_analysis.json")
    parser.add_argument("--output-md", default="results/result_task_5_analysis.md")
    args = parser.parse_args()

    task4_before = load_json(Path(args.task4_before))
    task4_after = load_json(Path(args.task4_after))
    sbom_before = load_json(Path(args.sbom_before))
    sbom_after = load_json(Path(args.sbom_after))
    osv_before = load_json(Path(args.osv_before))
    osv_after = load_json(Path(args.osv_after))

    summary = {
        "task4_before_after": compare_package_sets(
            package_map_from_task4(task4_before),
            package_map_from_task4(task4_after),
        ),
        "sbom_before_after": compare_package_sets(
            package_map_from_cyclonedx(sbom_before),
            package_map_from_cyclonedx(sbom_after),
        ),
        "osv_before_after": summarize_osv(osv_before, osv_after),
        "task4_vs_sbom_quality": compare_task4_and_sbom(task4_before, sbom_before),
    }

    output_json = Path(args.output_json).resolve()
    output_md = Path(args.output_md).resolve()
    output_json.parent.mkdir(parents=True, exist_ok=True)
    output_md.parent.mkdir(parents=True, exist_ok=True)

    output_json.write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    output_md.write_text(make_markdown(summary), encoding="utf-8")

    print(f"[OK] JSON analysis saved to: {output_json}")
    print(f"[OK] Markdown analysis saved to: {output_md}")


if __name__ == "__main__":
    main()
