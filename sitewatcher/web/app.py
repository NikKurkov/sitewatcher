"""Owner-only, server-rendered control panel for SiteWatcher."""

from __future__ import annotations

import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

import yaml
from dotenv import load_dotenv
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware

# Storage resolves DATABASE_PATH when imported.
load_dotenv(Path.cwd() / ".env")

from .. import storage
from ..bot.validators import DOMAIN_RE, normalize_domain
from ..checks.rkn_block_sqlite import rkn_index_path
from ..config import AppConfig, ChecksModel, PortSpec, load_config, resolve_settings
from ..dispatcher import Dispatcher
from ..utils.domains_csv import export_domains_csv, import_domains_csv
from .auth import (
    LoginRateLimiter,
    WebSettings,
    csrf_token,
    password_fingerprint,
    verify_csrf,
    verify_password,
)
from .config_edit import save_config_yaml
from .views import domain_cards, domain_checks, history_dicts, latency_chart, status_chart


WEB_DIR = Path(__file__).resolve().parent
PERIOD_DAYS = {"1d": 1, "7d": 7, "30d": 30}


def _period_since(value: str) -> datetime:
    return datetime.now(timezone.utc) - timedelta(days=PERIOD_DAYS.get(value, 7))


def _domain_for_owner(owner_id: int, domain: str) -> str:
    if not DOMAIN_RE.fullmatch(domain) or not storage.domain_exists(owner_id, domain):
        raise HTTPException(status_code=404, detail="Domain not found")
    return domain


def _port_view(value: object) -> list[dict[str, int]]:
    if not isinstance(value, list):
        return []
    result = []
    for item in value:
        if hasattr(item, "port"):
            port = item.port
        elif isinstance(item, dict):
            port = item.get("port")
        else:
            port = item
        result.append({"port": int(port)})
    return result


def _ports_input(value: object) -> str:
    if not isinstance(value, list) or not value:
        return ""
    if any(isinstance(item, dict) and set(item) != {"port"} for item in value):
        return json.dumps(value, ensure_ascii=False)
    return ", ".join(str(item["port"] if isinstance(item, dict) else item) for item in value)


def _effective(owner_id: int, domain: str, cfg: AppConfig) -> tuple[dict, dict]:
    override = storage.get_domain_override(owner_id, domain) or {}
    settings = resolve_settings(cfg, domain, override)
    result = {
        "checks": settings.checks.model_dump(),
        "http_timeout_s": settings.http_timeout_s,
        "latency_warn_ms": settings.latency_warn_ms,
        "latency_crit_ms": settings.latency_crit_ms,
        "tls_warn_days": settings.tls_warn_days,
        "proxy": settings.proxy,
        "keywords": settings.keywords,
        "ports": _port_view(settings.ports),
    }
    override = {**override, "ports_input": _ports_input(override.get("ports"))}
    return result, override


def _settings_patch(form: dict, current: dict) -> tuple[dict, list[str]]:
    """Parse the complete domain form while keeping absent numeric fields inherited."""
    patch: dict = {"checks": {name: form.get(f"checks.{name}") == "on" for name in ChecksModel.model_fields}}
    unset = []
    for key in ("http_timeout_s", "latency_warn_ms", "latency_crit_ms", "tls_warn_days", "interval_minutes"):
        raw = str(form.get(key, "")).strip()
        if not raw:
            unset.append(key)
            continue
        try:
            value = int(raw)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=f"{key} must be an integer") from exc
        if value < (1 if key == "http_timeout_s" else 0):
            raise HTTPException(status_code=400, detail=f"{key} is out of range")
        patch[key] = value
    warn = patch.get("latency_warn_ms")
    crit = patch.get("latency_crit_ms")
    if warn is not None and crit is not None and crit < warn:
        raise HTTPException(status_code=400, detail="Critical latency must be at least warning latency")
    raw_keywords = str(form.get("keywords", "")).strip()
    if raw_keywords:
        patch["keywords"] = [word.strip() for word in raw_keywords.split(",") if word.strip()]
    else:
        unset.append("keywords")
    raw_ports = str(form.get("ports", "")).strip()
    if raw_ports:
        current_ports = current.get("ports")
        same_numbers = (not raw_ports.startswith("[") and
                        raw_ports == ", ".join(str(item["port"]) for item in _port_view(current_ports)))
        if raw_ports != _ports_input(current_ports) and not same_numbers:
            try:
                if raw_ports.startswith("["):
                    items = json.loads(raw_ports)
                    if not isinstance(items, list):
                        raise ValueError("Expected a JSON array")
                    ports = [PortSpec.model_validate(item).model_dump(exclude_none=True) for item in items]
                else:
                    ports = [{"port": int(part.strip())} for part in raw_ports.split(",")]
                if not ports or any(not 1 <= item["port"] <= 65535 or
                                    item.get("timeout_s", 1) <= 0 or
                                    item.get("read_bytes", 1) <= 0 for item in ports):
                    raise ValueError("Invalid port target")
            except (TypeError, ValueError, json.JSONDecodeError) as exc:
                raise HTTPException(status_code=400, detail="Use port numbers or a valid JSON target array") from exc
            patch["ports"] = ports
    else:
        unset.append("ports")
    proxy = str(form.get("proxy", "")).strip()
    if proxy:
        patch["proxy"] = proxy
    else:
        unset.append("proxy")
    return patch, unset


def create_app(settings: WebSettings | None = None) -> FastAPI:
    """Create a single-owner web app; missing credentials fail closed."""
    settings = settings or WebSettings.from_env()
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
    app.add_middleware(
        SessionMiddleware,
        secret_key=settings.session_secret,
        session_cookie="sitewatcher_session",
        max_age=12 * 3600,
        same_site="strict",
        https_only=settings.cookie_secure,
    )
    app.mount("/static", StaticFiles(directory=WEB_DIR / "static"), name="static")
    templates = Jinja2Templates(directory=WEB_DIR / "templates")
    limiter = LoginRateLimiter()
    storage.ensure_user(settings.owner_id)
    config_path = Path(os.getenv("SITEWATCHER_CONFIG", "config.yaml"))

    def config() -> AppConfig:
        return load_config(config_path) if config_path.exists() else AppConfig()

    def render(request: Request, name: str, *, active: str, **context):
        data = {
            "active": active,
            "csrf": csrf_token(request.session),
            "flash": request.session.pop("flash", None),
            "owner_id": settings.owner_id,
            **context,
        }
        response = templates.TemplateResponse(request, name, data)
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        return response

    def notice(request: Request, message: str, kind: str = "success") -> None:
        request.session["flash"] = {"message": message, "kind": kind}

    async def owner(request: Request) -> int:
        if (request.session.get("owner_id") != settings.owner_id or
                request.session.get("fingerprint") != password_fingerprint(settings.password_hash)):
            raise HTTPException(status_code=303, headers={"Location": "/login"})
        return settings.owner_id

    async def csrf_owner(request: Request, owner_id: int = Depends(owner)) -> int:
        form = await request.form()
        if not verify_csrf(request.session, form.get("csrf")):
            raise HTTPException(status_code=403, detail="Invalid CSRF token")
        return owner_id

    def redirect(path: str) -> RedirectResponse:
        return RedirectResponse(path, status_code=303)

    @app.get("/login")
    async def login_page(request: Request):
        if (request.session.get("owner_id") == settings.owner_id and
                request.session.get("fingerprint") == password_fingerprint(settings.password_hash)):
            return redirect("/")
        return render(request, "login.html", active="login")

    @app.post("/login")
    async def login(request: Request):
        form = await request.form()
        if not verify_csrf(request.session, form.get("csrf")):
            raise HTTPException(status_code=403, detail="Invalid CSRF token")
        key = request.client.host if request.client else "unknown"
        if not limiter.allow(key):
            raise HTTPException(status_code=429, detail="Too many login attempts; retry later")
        if not verify_password(str(form.get("password", "")), settings.password_hash):
            limiter.record_failure(key)
            request.session["flash"] = {"kind": "error", "message": "Incorrect password"}
            return render(request, "login.html", active="login")
        limiter.reset(key)
        request.session.clear()
        request.session["owner_id"] = settings.owner_id
        request.session["fingerprint"] = password_fingerprint(settings.password_hash)
        csrf_token(request.session)
        return redirect("/")

    @app.post("/logout")
    async def logout(request: Request, _: int = Depends(csrf_owner)):
        request.session.clear()
        return redirect("/login")

    @app.get("/")
    async def overview(request: Request, owner_id: int = Depends(owner)):
        cards, summary = domain_cards(owner_id, config())
        return render(request, "index.html", active="overview", domains=cards, summary=summary,
                      alerts_enabled=storage.is_user_alerts_enabled(owner_id))

    @app.get("/domains")
    async def domains(request: Request, owner_id: int = Depends(owner), q: str = "", status: str = ""):
        cards, _ = domain_cards(owner_id, config())
        cards = [card for card in cards if q.lower() in card["name"] and
                 (not status or card["status"].lower() == status.lower())]
        return render(request, "domains.html", active="domains", domains=cards, q=q, status_filter=status)

    @app.post("/domains")
    async def add_domain(request: Request, owner_id: int = Depends(csrf_owner)):
        form = await request.form()
        name = normalize_domain(str(form.get("name", "")))
        if not name or not DOMAIN_RE.fullmatch(name):
            raise HTTPException(status_code=400, detail="Enter a valid domain")
        storage.add_domain(owner_id, name)
        notice(request, f"Added {name}")
        return redirect(f"/domains/{name}")

    @app.post("/domains/delete-all")
    async def delete_all_domains(request: Request, owner_id: int = Depends(csrf_owner)):
        form = await request.form()
        if form.get("confirm") != "DELETE ALL":
            raise HTTPException(status_code=400, detail="Type DELETE ALL to confirm")
        names = storage.list_domains(owner_id)
        for name in names:
            storage.remove_domain(owner_id, name)
        notice(request, f"Deleted {len(names)} domains and their history")
        return redirect("/domains")

    @app.get("/scan")
    async def scan_page(request: Request, _: int = Depends(owner)):
        return render(request, "scan.html", active="scan", scan_domain=None, scan_results=None)

    @app.post("/scan")
    async def scan_domain(request: Request, owner_id: int = Depends(csrf_owner)):
        form = await request.form()
        name = normalize_domain(str(form.get("name", "")))
        if not name or not DOMAIN_RE.fullmatch(name):
            raise HTTPException(status_code=400, detail="Enter a valid domain")
        async with Dispatcher(config()) as dispatcher:
            outcomes = await dispatcher.run_for(owner_id, name, use_cache=False, ephemeral=True)
        results = [{"check": item.check, "status": getattr(item.status, "value", str(item.status)),
                    "message": item.message} for item in outcomes]
        return render(request, "scan.html", active="scan", scan_domain=name, scan_results=results)

    @app.get("/domains/{domain}")
    async def domain_page(request: Request, domain: str, owner_id: int = Depends(owner), period: str = "7d"):
        domain = _domain_for_owner(owner_id, domain)
        period = period if period in PERIOD_DAYS else "7d"
        cfg = config()
        recent = history_dicts(list(storage.iter_history(owner_id, domain=domain,
                                                        since=_period_since(period), limit=2000)))
        effective, override = _effective(owner_id, domain, cfg)
        return render(
            request, "domain.html", active="domain", domain=domain,
            check_rows=domain_checks(owner_id, domain, cfg), history=recent[:30],
            status_chart=status_chart(recent), latency_chart=latency_chart(recent),
            period=period, settings=effective, override=override,
            check_names=list(ChecksModel.model_fields),
        )

    @app.post("/domains/{domain}/delete")
    async def delete_domain(request: Request, domain: str, owner_id: int = Depends(csrf_owner)):
        storage.remove_domain(owner_id, _domain_for_owner(owner_id, domain))
        notice(request, f"Deleted {domain}")
        return redirect("/domains")

    @app.post("/domains/{domain}/check")
    async def run_domain(request: Request, domain: str, owner_id: int = Depends(csrf_owner)):
        domain = _domain_for_owner(owner_id, domain)
        async with Dispatcher(config()) as dispatcher:
            results = await dispatcher.run_for(owner_id, domain, use_cache=False)
        if not storage.domain_exists(owner_id, domain):
            raise HTTPException(status_code=404, detail="Domain removed during check")
        storage.save_histories(owner_id, domain, results)
        notice(request, f"Ran {len(results)} checks for {domain}")
        return redirect(f"/domains/{domain}")

    @app.post("/check-all")
    async def run_all(request: Request, owner_id: int = Depends(csrf_owner)):
        names = storage.list_domains(owner_id)
        async with Dispatcher(config()) as dispatcher:
            for name in names:
                results = await dispatcher.run_for(owner_id, name, use_cache=False)
                if storage.domain_exists(owner_id, name):
                    storage.save_histories(owner_id, name, results)
        notice(request, f"Checked {len(names)} domains")
        return redirect("/")

    @app.post("/domains/{domain}/settings")
    async def save_domain_settings(request: Request, domain: str, owner_id: int = Depends(csrf_owner)):
        domain = _domain_for_owner(owner_id, domain)
        form = await request.form()
        patch, unset = _settings_patch(dict(form), storage.get_domain_override(owner_id, domain) or {})
        for key in unset:
            storage.unset_domain_override(owner_id, domain, key)
        storage.set_domain_override(owner_id, domain, patch)
        notice(request, "Domain settings saved")
        return redirect(f"/domains/{domain}")

    @app.post("/domains/{domain}/settings/reset")
    async def reset_domain_settings(request: Request, domain: str, owner_id: int = Depends(csrf_owner)):
        domain = _domain_for_owner(owner_id, domain)
        storage.unset_domain_override(owner_id, domain, None)
        notice(request, "Domain overrides reset")
        return redirect(f"/domains/{domain}")

    @app.get("/history")
    async def history_page(request: Request, owner_id: int = Depends(owner),
                           domain: str = "", check: str = "", status: str = "", period: str = "7d", page: int = 1):
        if domain:
            _domain_for_owner(owner_id, domain)
        if check and check not in ChecksModel.model_fields:
            raise HTTPException(status_code=400, detail="Unknown check")
        if status and status.upper() not in {"OK", "WARN", "CRIT", "UNKNOWN"}:
            raise HTTPException(status_code=400, detail="Unknown status")
        period = period if period in PERIOD_DAYS else "7d"
        if page < 1 or page > 2**53:
            raise HTTPException(status_code=400, detail="Invalid page")
        rows = history_dicts(list(storage.iter_history(owner_id, domain=domain or None, check=check or None,
            statuses={status.upper()} if status else None, since=_period_since(period),
            limit=51, offset=(page - 1) * 50)))
        filters = {"domain": domain, "check": check, "status": status.lower(), "period": period,
                   "page": page, "has_next": len(rows) > 50}
        return render(request, "history.html", active="history", history=rows[:50],
                      domains=storage.list_domains(owner_id), filters=filters)

    @app.get("/settings")
    async def settings_page(request: Request, owner_id: int = Depends(owner)):
        cfg = config()
        raw = (config_path.read_text(encoding="utf-8") if config_path.exists()
               else yaml.safe_dump(cfg.model_dump(mode="json"), sort_keys=False))
        return render(request, "settings.html", active="settings", cfg=cfg, yaml_text=raw,
                      alerts_enabled=storage.is_user_alerts_enabled(owner_id),
                      restart_required=request.session.pop("restart_required", False))

    @app.post("/settings/alerts")
    async def set_alerts(request: Request, owner_id: int = Depends(csrf_owner)):
        form = await request.form()
        value = str(form.get("enabled", ""))
        if value not in ("true", "false"):
            raise HTTPException(status_code=400, detail="Invalid alert setting")
        storage.set_user_alerts_enabled(owner_id, value == "true")
        notice(request, "Telegram alerts updated")
        return redirect("/settings")

    @app.post("/settings/cache")
    async def clear_cache(request: Request, _: int = Depends(csrf_owner)):
        storage.clear_whois_cache()
        index = rkn_index_path(config().rkn)
        for suffix in ("", "-wal", "-shm", "-journal"):
            Path(str(index) + suffix).unlink(missing_ok=True)
        notice(request, "WHOIS and RKN caches cleared")
        return redirect("/settings")

    @app.post("/settings/config")
    async def save_global_config(request: Request, _: int = Depends(csrf_owner)):
        form = await request.form()
        raw = str(form.get("yaml_text", ""))
        if len(raw) > 1_000_000:
            raise HTTPException(status_code=413, detail="Configuration is too large")
        try:
            save_config_yaml(raw, config_path)
        except (ValueError, OSError) as exc:
            raise HTTPException(status_code=400, detail=f"Invalid configuration: {exc}") from exc
        request.session["restart_required"] = True
        notice(request, "Global configuration saved. Restart the bot to apply it.")
        return redirect("/settings")

    @app.get("/import")
    async def import_page(request: Request, _: int = Depends(owner)):
        return render(request, "import_export.html", active="import",
                      import_report=request.session.pop("import_report", None))

    @app.get("/export")
    async def export_csv(_: int = Depends(owner)):
        payload = export_domains_csv(settings.owner_id)
        return Response(payload, media_type="text/csv; charset=utf-8",
                        headers={"Content-Disposition": "attachment; filename=sitewatcher-domains.csv"})

    @app.post("/import")
    async def import_csv(request: Request, owner_id: int = Depends(csrf_owner)):
        form = await request.form()
        upload = form.get("file")
        mode = str(form.get("mode", "merge"))
        if mode not in ("merge", "replace") or not hasattr(upload, "read"):
            raise HTTPException(status_code=400, detail="Choose a CSV file and import mode")
        payload = await upload.read(1_000_001)
        if len(payload) > 1_000_000:
            raise HTTPException(status_code=413, detail="CSV is too large")
        try:
            report = import_domains_csv(owner_id, payload, mode=mode)
        except (UnicodeError, ValueError) as exc:
            raise HTTPException(status_code=400, detail=f"Invalid CSV: {exc}") from exc
        request.session["import_report"] = {
            "added": report.added, "updated": report.updated, "skipped": report.skipped,
            "errors": report.errors[:5],
        }
        notice(request, f"Imported: {report.added} added, {report.updated} updated, {report.skipped} skipped")
        return redirect("/import")

    return app
