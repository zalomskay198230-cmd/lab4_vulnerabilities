# Лабораторная работа №3: работа с уязвимостями

Проект подготовлен под вариант с `django/django` и дистрибутивом CentOS 7.
Для проекта используется версия Django 3.2, так как она выпущена в 2021 году.

## Что лежит в репозитории

```text
src/
  task1_collect_dependencies.py  # сбор зависимостей проекта в result_task_1.json
  task2_check_ghsa.py            # проверка зависимостей через GitHub Security Advisory GraphQL API
  task3_analyze.py               # формирование таблицы по уязвимым зависимостям
  task4_inventory_os.py          # инвентаризация ОС и пакетов + CycloneDX SBOM
  task5_compare_osv.py           # сравнение результатов до/после обновления ОС
requirements.txt
.gitignore
```


## Подготовка на Windows

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt

git clone https://github.com/django/django.git data/django
cd data/django
git checkout 3.2
cd ..\..
```

## Задание 1

```powershell
python src/task1_collect_dependencies.py --project-path data/django --output results/result_task_1.json
```

На выходе появится `results/result_task_1.json`.

## Задание 2

Нужен GitHub token с доступом к публичному GraphQL API. Удобнее всего создать classic token без лишних прав, достаточно базового доступа к публичным данным.

```powershell
$env:GITHUB_TOKEN="ghp_ВАШ_ТОКЕН"
python src/task2_check_ghsa.py --input results/result_task_1.json --output results/result_task_2.json
```

## Задание 3

```powershell
python src/task3_analyze.py --input results/result_task_2.json --output-csv results/result_task_3.csv --output-md results/result_task_3.md
```

## Задание 4 на CentOS 7

Скопируйте проект на виртуальную машину CentOS 7 и выполните:

```bash
python3 src/task4_inventory_os.py \
  --output results/result_task_4.json \
  --cyclonedx-output results/os_inventory_before.cdx.json
```

Файл `result_task_4.json` содержит данные ОС и список RPM-пакетов.
Файл `os_inventory_before.cdx.json` нужен для OSV Scanner в задании 5.

## Задание 5 на CentOS 7

### До обновления

```bash
python3 src/task4_inventory_os.py \
  --output results/result_task_4_before.json \
  --cyclonedx-output results/os_inventory_before.cdx.json

osv-scanner scan source -L results/os_inventory_before.cdx.json \
  --format json \
  --output-file results/osv_before.json
```

### Обновление системы

Для CentOS 7:

```bash
sudo yum makecache
sudo yum update -y
```


### После обновления

```bash
python3 src/task4_inventory_os.py \
  --output results/result_task_4_after.json \
  --cyclonedx-output results/os_inventory_after.cdx.json

osv-scanner scan source -L results/os_inventory_after.cdx.json \
  --format json \
  --output-file results/osv_after.json
```

### Сравнение

```bash
python3 src/task5_compare_osv.py \
  --task4-before results/result_task_4_before.json \
  --task4-after results/result_task_4_after.json \
  --sbom-before results/os_inventory_before.cdx.json \
  --sbom-after results/os_inventory_after.cdx.json \
  --osv-before results/osv_before.json \
  --osv-after results/osv_after.json \
  --output-json results/result_task_5_analysis.json \
  --output-md results/result_task_5_analysis.md
```

