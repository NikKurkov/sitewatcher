<h1 align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="assets/brand/logo-dark.svg">
    <img src="assets/brand/logo-light.svg" alt="SiteWatcher" width="360">
  </picture>
</h1>

<p align="center"><strong>Проверяет ваши сайты и сообщает, если что-то пошло не так.</strong></p>
<p align="center"><strong>Русский</strong> · <a href="README.md">English</a></p>

[![Обзор сайтов в тёмной теме — демонстрационные данные](docs/screenshots/readme-overview-dark-ru.png)](docs/screenshots/readme-overview-dark-ru.png)

<table>
  <tr>
    <td width="50%"><a href="docs/screenshots/readme-signals-dark-ru.png"><img src="docs/screenshots/readme-signals-dark-ru.png" alt="Карта выполнения проверок — демонстрационные данные"></a></td>
    <td width="50%"><a href="docs/screenshots/readme-history-dark-ru.png"><img src="docs/screenshots/readme-history-dark-ru.png" alt="История и время ответа сайта — демонстрационные данные"></a></td>
  </tr>
  <tr>
    <td align="center">Как проходят проверки</td>
    <td align="center">История и время ответа</td>
  </tr>
</table>

## Для чего это нужно

Чтобы держать под присмотром интернет-магазин, сайт компании или свои проекты. SiteWatcher собирает их состояние на одном экране: открывается ли сайт, быстро ли отвечает и нет ли других проблем.

Программа помогает:

- Заметить, что сайт перестал открываться или стал медленным.
- Узнать, когда пора продлить домен или сертификат для HTTPS.
- Посмотреть историю и понять, когда появилась проблема.
- Получать сообщения о сбоях и восстановлении в Telegram.
- Дать клиентам ссылку на страницу состояния выбранных сайтов.

## Как это работает

1. **Вы добавляете адрес сайта**, например `example.com` или `example.com/catalog/`.
2. **SiteWatcher проверяет его по расписанию** и сохраняет результаты.
3. **Вы смотрите панель или получаете уведомление**, если подключили Telegram.

На карте можно наблюдать за ходом проверок. Для подробностей откройте историю сайта.

SiteWatcher работает на вашем компьютере или сервере. Чтобы проверки продолжались, он должен оставаться включённым.

## Как запустить

Нужны Git и запущенный [Docker](https://docs.docker.com/get-started/get-docker/) с Compose. Откройте терминал и выполните:

```bash
mkdir sitewatcher &&
cd sitewatcher &&
git clone https://github.com/NikKurkov/sitewatcher.git . &&
docker compose run --rm --build setup &&
docker compose up -d
```

Команда `setup` попросит придумать логин и пароль. Затем откройте **http://127.0.0.1:8080**, войдите и нажмите **«Добавить домен»** — значок **+** вверху.

Базовые проверки работают сразу. Telegram и дополнительные сервисы можно подключить позже. По умолчанию панель доступна только на компьютере, где вы её запустили.

## Что дальше

В **[руководстве пользователя](docs/usage.ru.md)** собраны пошаговые инструкции: запуск без Docker, добавление сайтов, статусы, Telegram, прокси, дополнительные проверки, публичная страница, обновление и резервные копии.

[Сообщить об ошибке](https://github.com/NikKurkov/sitewatcher/issues) · [Лицензия MIT](LICENSE)
