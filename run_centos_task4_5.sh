#!/usr/bin/env bash
set -euo pipefail

mkdir -p results

# До обновления
python3 src/task4_inventory_os.py \
  --output results/result_task_4_before.json \
  --cyclonedx-output results/os_inventory_before.cdx.json

osv-scanner scan source -L results/os_inventory_before.cdx.json \
  --format json \
  --output-file results/osv_before.json || true

# Обновление CentOS 7
sudo yum makecache
sudo yum update -y

# После обновления
python3 src/task4_inventory_os.py \
  --output results/result_task_4_after.json \
  --cyclonedx-output results/os_inventory_after.cdx.json

# Отдельно дублируем файл под название, требуемое заданием 4.
cp results/result_task_4_after.json results/result_task_4.json

osv-scanner scan source -L results/os_inventory_after.cdx.json \
  --format json \
  --output-file results/osv_after.json || true

# Сравнение
python3 src/task5_compare_osv.py \
  --task4-before results/result_task_4_before.json \
  --task4-after results/result_task_4_after.json \
  --sbom-before results/os_inventory_before.cdx.json \
  --sbom-after results/os_inventory_after.cdx.json \
  --osv-before results/osv_before.json \
  --osv-after results/osv_after.json \
  --output-json results/result_task_5_analysis.json \
  --output-md results/result_task_5_analysis.md
