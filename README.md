# sitewatcher (MVP)


Async мониторинг доменов + Telegram-бот.


### Команды бота
- `/add_domain <name.ru>` — добавить домен
- `/remove_domain <name.ru>` — удалить домен
- `/list_domain` — список доменов
- `/check_domain <name.ru>` — проверить один
- `/check_all` — проверить все


### Быстрый старт
```bash
# 1) Установка
python -m venv .venv && source .venv/bin/activate
pip install -e .


# 2) Настройка
cp .env.example .env # заполните TELEGRAM_TOKEN


# 3) Запуск бота
python -m sitewatcher.main bot


# Одноразовые проверки без бота
python -m sitewatcher.main check_all
python -m sitewatcher.main check_domain example.com