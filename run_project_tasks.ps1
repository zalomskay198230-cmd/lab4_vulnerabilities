# Запуск заданий 1-3 на Windows.
# Перед запуском укажите GITHUB_TOKEN:
# $env:GITHUB_TOKEN="ghp_ВАШ_ТОКЕН"

if (-not (Test-Path ".venv")) {
    python -m venv .venv
}

. .\.venv\Scripts\Activate.ps1
pip install -r requirements.txt

if (-not (Test-Path "data/django")) {
    git clone https://github.com/django/django.git data/django
    Push-Location data/django
    git checkout 3.2
    Pop-Location
}

python src/task1_collect_dependencies.py --project-path data/django --output results/result_task_1.json
python src/task2_check_ghsa.py --input results/result_task_1.json --output results/result_task_2.json
python src/task3_analyze.py --input results/result_task_2.json --output-csv results/result_task_3.csv --output-md results/result_task_3.md
