<h1 align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="assets/brand/logo-dark.svg">
    <img src="assets/brand/logo-light.svg" alt="SiteWatcher" width="360">
  </picture>
</h1>

<p align="center"><strong>Checks your websites and lets you know when something goes wrong.</strong></p>
<p align="center"><a href="README.md">Русский</a> · <strong>English</strong></p>

[![Website overview in dark mode — demo data](docs/screenshots/readme-overview-dark-en.png)](docs/screenshots/readme-overview-dark-en.png)

<table>
  <tr>
    <td width="50%"><a href="docs/screenshots/readme-signals-dark-en.png"><img src="docs/screenshots/readme-signals-dark-en.png" alt="Checks moving across the signal map — demo data"></a></td>
    <td width="50%"><a href="docs/screenshots/readme-history-dark-en.png"><img src="docs/screenshots/readme-history-dark-en.png" alt="Website history and response times — demo data"></a></td>
  </tr>
  <tr>
    <td align="center">Watch checks in progress</td>
    <td align="center">History and response times</td>
  </tr>
</table>

<sub>The screenshots use made-up results with familiar domain names, not their current status. Click an image to take a closer look.</sub>

## What is it for?

Keep an eye on an online shop, a company website or your own projects. SiteWatcher brings them together on one screen so you can see whether they open, how quickly they respond and whether anything needs attention.

It helps you:

- Notice when a website stops responding or becomes slow.
- See when a domain or HTTPS certificate needs renewing.
- Look through past checks to find when a problem started.
- Get Telegram messages about problems and recovery.
- Share a status page for the websites you choose.

## How does it work?

1. **Add a website address**, such as `example.com` or `example.com/catalog/`.
2. **SiteWatcher checks it on a schedule** and saves the results.
3. **Open the dashboard or receive an alert** if you have connected Telegram.

The map shows checks moving between SiteWatcher and your websites. Open a site's history for the details.

SiteWatcher runs on your computer or server. That machine must stay on for checks to continue.

## Get started

1. Install and start [Docker](https://docs.docker.com/get-started/get-docker/).
2. Download the [SiteWatcher ZIP](https://github.com/NikKurkov/sitewatcher/archive/refs/heads/main.zip) and extract it.
3. Open a terminal in the folder containing `compose.yaml` and run:

```bash
docker compose run --rm --build setup
docker compose up -d
```

The `setup` command asks you to choose a username and password. Then open **http://127.0.0.1:8080**, sign in and click **Add domain** — the **+** icon at the top.

Basic checks work straight away. You can connect Telegram and other services later. By default, the dashboard is accessible only on the computer running it.

## Next steps

The **[user guide](docs/usage.en.md)** covers installation without Docker, adding websites, understanding results, Telegram, proxies, extra checks, public status pages, updates and backups.

[Report a problem](https://github.com/NikKurkov/sitewatcher/issues) · [MIT license](LICENSE)
