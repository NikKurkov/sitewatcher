<img src="https://raw.githubusercontent.com/NikKurkov/sitewatcher/refs/heads/main/sitewatcher_logo.png" width="300"/>


# SiteWatcher — бот для мониторинга сайтов
Лёгкий асинхронный мониторинг доступности сайтов и доменов с уведомлениями в Telegram.
Поддерживает плановые проверки, быстрые разовые проверки, дедупликацию алертов и гибкую конфигурацию.

<img src="https://raw.githubusercontent.com/NikKurkov/sitewatcher/refs/heads/main/screenshot.png"/>

---

## Возможности

**Проверки (checks):**
- **HTTP Basic** — статус-код (200, 440, 500 и т.д.) и время ответа главной страницы (с учётом редиректов).
- **TLS-сертификат** — срок действия, предупреждение за N дней до истечения.
- **Ping** — ICMP-пинг и время ответа.
- **Keywords** — наличие обязательных ключевых слов/строк в HTML (например, счётчик/метрика).
- **Deface** — поиск типичных маркеров взлома на главной странице (например: “defaced by”, “hacked by”, “was here”, «сайт взломан» и т.п.). 
- **RKN Block** — проверка на блокировки в реестре Роскомнадзора (создает локальный офлайн-индекс, обновляемый по расписанию).
- **IP change** — отслеживание смены A-записей домена.
- **IP blacklist** — проверка IP сайта на наличие в чёрных списках Spamhaus и т.д.
- **Ports** — проверка доступности заданных портов (например: веб 80 и 443, почтовый 25 и т.д.)


**Другие функции:**
- Планировщик периодических проверок (общие и индивидуальные для каждого сайта).
- Разовые проверки домена без сохранения в БД и алертов.
- Дедупликация и «охлаждение» алертов, чтобы не спамить при повторяющихся проблемах.
- Ограничение доступа к боту по списку Telegram-ID или доступ для всех.
- SQLite-хранилище, создаётся автоматически. Хранение настроек, данных по проверкам, пользователей.
- Прокси для Telegram-бота (HTTP/SOCKS); HTTP-прокси для проверок — через конфиг.

---

## Быстрый старт

```bash
# 1) Требования
# Python 3.11+ (рекомендуется 3.12), Linux/Windows

# 2) Установка
python -m venv .venv
source .venv/bin/activate  # Windows: venv\Scripts\activate
python -m pip install -U pip
pip install -r requirements.txt

# 3) Настройка окружения
cp .env.example .env
# откройте .env и задайте TELEGRAM_TOKEN, при необходимости TELEGRAM_ALLOWED_USER_IDS и TELEGRAM_ALERT_CHAT_ID

# 4) Запуск Telegram-бота
python -m sitewatcher.main bot
```

> ⚠️ Не коммитьте `.env` в репозиторий, он содержит секреты (токен бота и т.д.).

---

## Переменные окружения

| Переменная                 | Обязательна | Описание |
|---------------------------|-------------|----------|
| `TELEGRAM_TOKEN`          | да          | Токен Telegram-бота. |
| `TELEGRAM_ALLOWED_USER_IDS` | нет       | Список разрешённых Telegram-ID через запятую. Если не задано — доступ открыт всем (не рекомендуется в проде). |
| `TELEGRAM_ALERT_CHAT_ID`  | нет         | ID чата/группы для алертов (например, `-1001234567890`). Если не задан — алерты приходят в последний чат пользователя с ботом. |
| `TELEGRAM_PROXY`          | нет         | Прокси для Telegram (например, `http://user:pass@host:3128` или `socks5://...`). |
| `DATABASE_PATH`           | нет         | Путь к SQLite-БД (по умолчанию `./sitewatcher.db`). |

---

## Запуск из CLI (без бота)

Можно запускать проверки из командной строки:

```bash
# Все домены один раз
python -m sitewatcher.main check_all

# Один домен один раз
python -m sitewatcher.main check_domain example.com

# Опции:
# --only a,b,c   запустить только выбранные проверки (например: http_basic,tls_cert)
# --force        игнорировать кэш (выполнить «свежие» проверки)
# --config path  путь к config.yaml (см. ниже)
```

Примеры:
```bash
python -m sitewatcher.main check_domain example.com --only http_basic,tls_cert --force
python -m sitewatcher.main check_all --config ./config.yaml
```

---

## Команды бота

- `/start` / `/help` — справка.
- `/add <name.ru> [ещё.ru ...]` — добавить один или несколько доменов.
- `/remove <name.ru>` — удалить домен.
- `/status [crit|warn|ok|unknown|problems]` — показать последние известные статусы по всем доменам (без новых проверок).
- `/status <domain> [crit|warn|ok|unknown|problems]` — подробный отчёт по одному домену на основе последних сохранённых результатов (без новых проверок).
- `/list` — показать домены владельца.
- `/check <name.ru>` — проверить домен разово **без** записи в историю и **без** алертов (для доменов, которых нет в БД). Для уже добавленных — обычная проверка.
- `/check_all` — проверить все домены владельца по разу.
- `/clear_cache` — очистить кэш результатов проверок.
- `/cfg <name.ru>` — показать эффективные настройки домена (с учётом глобальных и доменных override).
- `/cfg_set <name.ru> <path> <value>` — задать override на домен (см. примеры ниже).
- `/cfg_unset <name.ru> <path>` — удалить доменный override по указанному пути.

**Примеры `/cfg_set`:**
```text
# выставить мягкий порог по времени ответа
/cfg_set example.com latency_warn_ms 1000

# выставить жёсткий порог по времени ответа
/cfg_set example.com latency_crit_ms 2500

# предупредить о сертификате за 14 дней до окончания
/cfg_set example.com tls_warn_days 14

# отключить проверку keywords для домена
/cfg_set example.com checks.keywords false

# включить все проверки раз в 10 минут (единый интервал для домена)
# <=0 отключает плановые проверки домена вообще
/cfg_set example.com interval_minutes 10
```

> «Пути» (`<path>`) поддерживают «точечную» нотацию для вложенных полей (например, `checks.keywords`).

---

## Как это работает (коротко)

- **Dispatcher** собирает список включённых проверок для домена, учитывая глобальные дефолты, расписания и доменные override.
- **Планировщик** запускает проверки по своим интервалам. Для домена можно задать единый `interval_minutes`:  
  `<= 0` — отключить плановые проверки домена; `> 0` — использовать единый интервал для всех его проверок.  
  Если не задан — используются интервалы по умолчанию для каждого типа проверки.
- **Кэш**: некоторые проверки кэшируются на заданное время (TTL), чтобы не бить внешние источники слишком часто. Флаг `--force` игнорирует кэш.
- **Алерты**: результаты агрегируются (OK/WARN/CRIT). Есть «охлаждение» (cooldown), чтобы одинаковые алерты не приходили слишком часто. Если домен **не** в БД — разовая проверка выполняется «эфемерно»: без записи и без алертов; проверка `keywords` при этом отключается.

---

## Конфигурация (опционально) — `config.yaml`

Файл `config.yaml` позволяет переопределить дефолты и создать доменные профили. Укажите путь через `--config ./config.yaml` или просто положите его в /data/config.yaml.

Пример (упрощённо):
```yaml
# Глобальные значения по умолчанию
defaults:
  http_timeout_s: 5
  latency_warn_ms: 800
  latency_crit_ms: 2000
  tls_warn_days: 21
  proxy: null
  keywords: []
  checks:
    http_basic: true
    tls_cert:   true
    keywords:   false
    deface:     true
    ping:       true
    rkn_block:  true
    ports:      false
    whois:      true
    ip_change:  true
    ip_blacklist: true

# Расписания и TTL кэша (минуты)
schedules:
  http_basic:   { interval_minutes: 5,    cache_ttl_minutes: 0    }
  ping:         { interval_minutes: 5,    cache_ttl_minutes: 0    }
  keywords:     { interval_minutes: 60,   cache_ttl_minutes: 0    }
  tls_cert:     { interval_minutes: 1440, cache_ttl_minutes: 1440 }
  rkn_block:    { interval_minutes: 1440, cache_ttl_minutes: 1440 }
  ports:        { interval_minutes: 1440, cache_ttl_minutes: 0    }
  whois:        { interval_minutes: 1440, cache_ttl_minutes: 1440 }
  ip_blacklist: { interval_minutes: 1440, cache_ttl_minutes: 1440 }

# Доменные профили и overrides
domains:
  - name: example.com
    latency_warn_ms: 1200
    tls_warn_days: 14
    proxy: "http://user:pass@127.0.0.1:3128"
    keywords: ["metrika", "yandex"]
    checks:
      keywords: true
      ports: true
    ports: [80, 443]     # если включена проверка ports
```

> Структура может эволюционировать; ориентируйтесь на подсказки `/cfg` и фактические поля в `config.py`.

---

## Хранилище

SQLite-БД (по умолчанию `./sitewatcher.db`) создаётся автоматически. Хранит:
- пользователей (Telegram-ID, аккаунт, последний чат для алертов),
- добавленные домены,
- результаты проверок (в т.ч. кэш),
- доменные overrides для гибкой настройки.

---

## Советы по эксплуатации

- Ограничьте доступ к боту через `TELEGRAM_ALLOWED_USER_IDS`.
- Создайте отдельный чат/группу и задайте `TELEGRAM_ALERT_CHAT_ID`, чтобы алерты не терялись.
- Для «разовой диагностики» неизвестного домена используйте `/check`: это не изменит БД и не отправит алерт.
- Проверка `ping` требует прав на отправку ICMP (на Linux запускайте под обычным пользователем; библиотека использует непривилегированный режим там, где это возможно).
- Для проверки **Deface** вы можете расширить словарь фраз собственным файлом: задайте путь в `deface.phrases_path`  (или доработайте существующий в sitewatcher/data/deface_markers.txt) разместите по одной фразе на строку.
