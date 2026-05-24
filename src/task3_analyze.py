#!/usr/bin/env python3
"""
Задание 3.
Анализ result_task_2.json и формирование таблицы уязвимых зависимостей.
"""

from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
from typing import Any

SEVERITIES = ["critical", "high", "moderate", "medium", "low", "unknown"]


def count_severities(vulnerabilities: list[dict[str, Any]]) -> dict[str, int]:
    counts = {severity: 0 for severity in SEVERITIES}
    for vuln in vulnerabilities:
        severity = str(vuln.get("severity", "unknown")).lower()
        if severity not in counts:
            severity = "unknown"
        counts[severity] += 1
    return counts


def make_strategy(dep: dict[str, Any], counts: dict[str, int]) -> str:
    secure_version = dep.get("secure_version", "manual-review-required")
    vulns = dep.get("vulnerabilities") or []

    if not vulns:
        return "Уязвимости не выявлены. Действия не требуются."

    if secure_version and secure_version != "manual-review-required":
        base = f"Обновить зависимость до версии {secure_version} или выше."
    else:
        base = "Провести ручной анализ: для части уязвимостей не указана исправленная версия."

    if counts.get("critical", 0) or counts.get("high", 0):
        return base + " Выполнить приоритетно, так как присутствуют уязвимости высокого/критического уровня. После обновления повторить сканирование."
    if counts.get("moderate", 0) or counts.get("medium", 0):
        return base + " Запланировать обновление в ближайшем цикле сопровождения и проверить совместимость проекта."
    return base + " Выполнить плановое обновление и зафиксировать результат повторной проверки."


def build_rows(input_path: Path) -> list[dict[str, Any]]:
    payload = json.loads(input_path.read_text(encoding="utf-8"))
    dependencies = payload.get("dependencies", payload if isinstance(payload, list) else [])

    rows: list[dict[str, Any]] = []
    for dep in dependencies:
        vulnerabilities = dep.get("vulnerabilities") or []
        if not vulnerabilities:
            continue
        counts = count_severities(vulnerabilities)
        row = {
            "Наименование зависимости": dep.get("name"),
            "Версия зависимости": dep.get("version"),
            "Экосистема": dep.get("ecosystem"),
            "Critical": counts.get("critical", 0),
            "High": counts.get("high", 0),
            "Moderate/Medium": counts.get("moderate", 0) + counts.get("medium", 0),
            "Low": counts.get("low", 0),
            "Unknown": counts.get("unknown", 0),
            "Всего уязвимостей": len(vulnerabilities),
            "Версия без уязвимостей": dep.get("secure_version"),
            "Рекомендуемая стратегия устранения": make_strategy(dep, counts),
        }
        rows.append(row)

    rows.sort(
        key=lambda item: (
            int(item["Всего уязвимостей"]),
            int(item["Critical"]),
            int(item["High"]),
        ),
        reverse=True,
    )
    return rows


def write_csv(rows: list[dict[str, Any]], output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = [
        "Наименование зависимости",
        "Версия зависимости",
        "Экосистема",
        "Critical",
        "High",
        "Moderate/Medium",
        "Low",
        "Unknown",
        "Всего уязвимостей",
        "Версия без уязвимостей",
        "Рекомендуемая стратегия устранения",
    ]
    with output_path.open("w", encoding="utf-8-sig", newline="") as file:
        writer = csv.DictWriter(file, fieldnames=fieldnames, delimiter=";")
        writer.writeheader()
        writer.writerows(rows)


def write_markdown(rows: list[dict[str, Any]], output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    if not rows:
        output_path.write_text("Уязвимые зависимости не выявлены.\n", encoding="utf-8")
        return

    headers = list(rows[0].keys())
    lines = []
    lines.append("| " + " | ".join(headers) + " |")
    lines.append("| " + " | ".join(["---"] * len(headers)) + " |")
    for row in rows:
        values = [str(row.get(header, "")).replace("|", "\\|") for header in headers]
        lines.append("| " + " | ".join(values) + " |")
    output_path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description="Analyze vulnerable dependencies from result_task_2.json")
    parser.add_argument("--input", default="results/result_task_2.json", help="Input JSON from task 2")
    parser.add_argument("--output-csv", default="results/result_task_3.csv", help="Output CSV path")
    parser.add_argument("--output-md", default="results/result_task_3.md", help="Output Markdown path")
    args = parser.parse_args()

    rows = build_rows(Path(args.input).resolve())
    write_csv(rows, Path(args.output_csv).resolve())
    write_markdown(rows, Path(args.output_md).resolve())

    print(f"[OK] Vulnerable dependencies: {len(rows)}")
    print(f"[OK] CSV saved to: {Path(args.output_csv).resolve()}")
    print(f"[OK] Markdown saved to: {Path(args.output_md).resolve()}")


if __name__ == "__main__":
    main()
