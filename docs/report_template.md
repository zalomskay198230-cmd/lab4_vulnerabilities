# Лабораторная работа №3. Работа с уязвимостями

## Цель работы

Целью лабораторной работы является проведение сканирования проекта и операционной системы на наличие известных уязвимостей, анализ полученных результатов и подготовка перечня действий для устранения выявленных проблем.

## Исходные данные

В качестве анализируемого проекта выбран репозиторий `django/django`. Для выполнения требования о выборе версии 2021 года используется версия Django 3.2. В качестве операционной системы для заданий 4 и 5 используется CentOS 7.

## Задание 1. Сбор зависимостей проекта

Для выполнения задания был написан скрипт `src/task1_collect_dependencies.py`. Скрипт выполняет поиск файлов зависимостей в проекте, анализирует `setup.cfg`, `setup.py`, `pyproject.toml` и файлы `requirements*.txt`, после чего формирует файл `result_task_1.json`.

В итоговый файл включаются следующие поля: `name`, `version`, `ecosystem`, `url`, `purl`, а также служебные поля `source_file` и `requirement`, которые позволяют понять, из какого файла была получена зависимость.

Команда запуска:

```bash
python src/task1_collect_dependencies.py --project-path data/django --output results/result_task_1.json
```

Сводные данные по экосистемам после запуска скрипта:

| Экосистема | Количество пакетов |
|---|---:|
| pypi | ВСТАВИТЬ_КОЛИЧЕСТВО |

Возникшая сложность: в проекте часть зависимостей может быть задана не точной версией, а диапазоном версий. Для сохранения корректности анализа такие значения не отбрасывались, а сохранялись в поле `version` как диапазон.

## Задание 2. Проверка зависимостей через GitHub Security Advisory

Для проверки зависимостей был написан скрипт `src/task2_check_ghsa.py`, использующий GitHub Security Advisory GraphQL API. Для каждого пакета из `result_task_1.json` выполняется запрос к базе GitHub Advisory Database. Далее скрипт сопоставляет версию или диапазон версии зависимости с диапазоном уязвимых версий, указанным в advisory.

Команда запуска:

```bash
export GITHUB_TOKEN="ghp_..."
python src/task2_check_ghsa.py --input results/result_task_1.json --output results/result_task_2.json
```

В файл `result_task_2.json` добавляются поля `vulnerabilities` и `secure_version`.

Возникшая сложность: GitHub Advisory использует диапазоны версий в формате semver. Для обработки диапазонов использовалась библиотека `packaging`, а при невозможности однозначного сравнения зависимость помечалась как требующая ручной проверки, чтобы не пропустить потенциальную уязвимость.

## Задание 3. Анализ состояния проекта

На основе файла `result_task_2.json` был сформирован список уязвимых зависимостей. Для этого использовался скрипт `src/task3_analyze.py`.

Команда запуска:

```bash
python src/task3_analyze.py --input results/result_task_2.json --output-csv results/result_task_3.csv --output-md results/result_task_3.md
```

Таблица уязвимых зависимостей отсортирована по убыванию количества уязвимостей. Для каждой зависимости указаны количество уязвимостей по уровням критичности, безопасная версия и рекомендуемая стратегия устранения.

## Задание 4. Инвентаризация операционной системы

Для инвентаризации ОС был разработан скрипт `src/task4_inventory_os.py`. Скрипт получает сведения об ОС из `/etc/os-release`, архитектуру через системные средства Python и список установленных пакетов через `rpm -qa`. Для каждого пакета сохраняются название, версия, архитектура, описание и размер при наличии данных.

Команда запуска:

```bash
python3 src/task4_inventory_os.py --output results/result_task_4.json --cyclonedx-output results/os_inventory_before.cdx.json
```

Особенность версионирования RPM-пакетов заключается в использовании схемы `VERSION-RELEASE`. Часть `VERSION` отражает версию программного продукта, а `RELEASE` указывает номер сборки пакета в конкретном дистрибутиве. Например, запись `1.2.3-4.el7` означает версию программы `1.2.3`, четвёртую сборку пакета для Enterprise Linux 7. При сравнении RPM-версий важно учитывать не только основную версию, но и release-часть, так как обновление безопасности может поставляться без изменения upstream-версии программы.

Примеры сравнения:

| Версия 1 | Версия 2 | Результат |
|---|---|---|
| `1.2.3-4.el7` | `1.2.3-5.el7` | вторая новее за счёт release |
| `1.2.3-4.el7` | `1.2.4-1.el7` | вторая новее за счёт version |
| `2.0.0-1.el7` | `1.9.9-10.el7` | первая новее за счёт version |

## Задание 5. Сканирование ОС до и после обновления

Для задания 5 использовался файл CycloneDX SBOM, сформированный скриптом инвентаризации, и инструмент `osv-scanner`.

Команды до обновления:

```bash
python3 src/task4_inventory_os.py --output results/result_task_4_before.json --cyclonedx-output results/os_inventory_before.cdx.json
osv-scanner scan source -L results/os_inventory_before.cdx.json --format json --output-file results/osv_before.json
```

Обновление CentOS 7:

```bash
sudo yum makecache
sudo yum update -y
```

Команды после обновления:

```bash
python3 src/task4_inventory_os.py --output results/result_task_4_after.json --cyclonedx-output results/os_inventory_after.cdx.json
osv-scanner scan source -L results/os_inventory_after.cdx.json --format json --output-file results/osv_after.json
```

Сравнение результатов:

```bash
python3 src/task5_compare_osv.py --task4-before results/result_task_4_before.json --task4-after results/result_task_4_after.json --sbom-before results/os_inventory_before.cdx.json --sbom-after results/os_inventory_after.cdx.json --osv-before results/osv_before.json --osv-after results/osv_after.json --output-json results/result_task_5_analysis.json --output-md results/result_task_5_analysis.md
```

По итогам сравнения необходимо указать, насколько изменилось количество пакетов, сколько пакетов получили новые версии, уменьшилось ли количество уязвимостей после обновления, а также насколько совпадает список пакетов из задания 4 со списком компонентов в SBOM.

## Вывод

В ходе выполнения лабораторной работы были реализованы скрипты для сбора зависимостей проекта, проверки зависимостей через GitHub Security Advisory, анализа уязвимых компонентов, инвентаризации операционной системы и сравнения состояния ОС до и после обновления. Полученные результаты позволяют определить уязвимые компоненты и сформировать практические рекомендации по их устранению.
