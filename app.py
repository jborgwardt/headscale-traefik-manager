"""Simple Traefik public-route manager.

Reads/writes a Traefik file-provider dynamic YAML. Focused on Host() HTTPS
routes → backend URL. Leaves tcp: and special system routes alone.
"""
from __future__ import annotations

import os
import re
import secrets
import shutil
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml
from fastapi import Depends, FastAPI, Form, HTTPException, Request, Response, status
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from itsdangerous import BadSignature, URLSafeSerializer
from passlib.hash import bcrypt
from pydantic import BaseModel, Field

CONFIG_PATH = Path(os.environ.get("TRAEFIK_DYNAMIC_PATH", "/managed/dynamic.yml"))
BACKUP_DIR = Path(os.environ.get("BACKUP_DIR", "/app/backups"))
SECRET = os.environ.get("APP_SECRET") or secrets.token_hex(32)
PASSWORD_HASH = os.environ.get("APP_PASSWORD_HASH", "")
PASSWORD_PLAIN = os.environ.get("APP_PASSWORD", "")
COOKIE_NAME = "rtm_session"
HOST_RE = re.compile(r"Host\(`([^`]+)`\)")
SYSTEM_ROUTERS = {"hermes-mobile-loopback-host"}

app = FastAPI(title="Route Manager", docs_url=None, redoc_url=None)
signer = URLSafeSerializer(SECRET, salt="route-manager-session")
STATIC = Path(__file__).parent / "static"
if STATIC.exists():
    app.mount("/static", StaticFiles(directory=str(STATIC)), name="static")


def _load() -> dict[str, Any]:
    if not CONFIG_PATH.exists():
        return {"http": {"routers": {}, "services": {}, "middlewares": {}}}
    with CONFIG_PATH.open() as f:
        data = yaml.safe_load(f) or {}
    data.setdefault("http", {})
    data["http"].setdefault("routers", {})
    data["http"].setdefault("services", {})
    data["http"].setdefault("middlewares", {})
    return data


def _dump(data: dict[str, Any]) -> None:
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    if CONFIG_PATH.exists():
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        shutil.copy2(CONFIG_PATH, BACKUP_DIR / f"dynamic.yml.{stamp}.bak")
        # keep last 30
        backups = sorted(BACKUP_DIR.glob("dynamic.yml.*.bak"))
        for old in backups[:-30]:
            old.unlink(missing_ok=True)
    CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    # Write in place — os.replace fails on Docker bind-mounted files (EBUSY).
    text = yaml.safe_dump(data, default_flow_style=False, sort_keys=False, allow_unicode=True)
    with CONFIG_PATH.open("w") as f:
        f.write(text)
        f.flush()


def _auth_ok(request: Request) -> bool:
    raw = request.cookies.get(COOKIE_NAME)
    if not raw:
        return False
    try:
        payload = signer.loads(raw)
        return bool(payload.get("ok")) and (time.time() - float(payload.get("t", 0))) < 60 * 60 * 24 * 14
    except BadSignature:
        return False


def require_auth(request: Request) -> None:
    if not _auth_ok(request):
        raise HTTPException(status_code=401, detail="unauthorized")


def _verify_password(password: str) -> bool:
    if PASSWORD_HASH:
        try:
            return bcrypt.verify(password, PASSWORD_HASH)
        except Exception:
            return False
    if PASSWORD_PLAIN:
        return secrets.compare_digest(password, PASSWORD_PLAIN)
    return False


def _extract_host(rule: str) -> str | None:
    m = HOST_RE.search(rule or "")
    return m.group(1) if m else None


def _backend_url(data: dict[str, Any], service_name: str) -> str:
    svc = (data.get("http", {}).get("services") or {}).get(service_name) or {}
    servers = ((svc.get("loadBalancer") or {}).get("servers")) or []
    if servers:
        return servers[0].get("url") or ""
    return ""


def list_routes(data: dict[str, Any]) -> list[dict[str, Any]]:
    routers = data.get("http", {}).get("routers") or {}
    out = []
    for name, r in routers.items():
        host = _extract_host(r.get("rule") or "")
        if not host and name in SYSTEM_ROUTERS:
            host = "(system)"
        if not host:
            continue
        service = r.get("service") or name
        mws = r.get("middlewares") or []
        if isinstance(mws, str):
            mws = [mws]
        out.append(
            {
                "id": name,
                "host": host,
                "backend": _backend_url(data, service),
                "service": service,
                "middlewares": mws,
                "tls": bool(r.get("tls")),
                "entryPoints": r.get("entryPoints") or [],
                "system": name in SYSTEM_ROUTERS or host == "(system)",
                "public_url": f"https://{host}" if host and host != "(system)" else "",
            }
        )
    out.sort(key=lambda x: (x["system"], x["host"]))
    return out


def slugify(host: str) -> str:
    s = host.strip().lower()
    s = re.sub(r"[^a-z0-9]+", "-", s).strip("-")
    return s or f"route-{secrets.token_hex(3)}"


class RouteIn(BaseModel):
    host: str = Field(min_length=1, max_length=253)
    backend: str = Field(min_length=1, max_length=500)
    id: str | None = None
    hsts: bool = True
    hsts_subdomains: bool = False


@app.get("/health")
def health():
    return {"ok": True, "config": str(CONFIG_PATH), "exists": CONFIG_PATH.exists()}


@app.get("/api/routes")
def api_routes(request: Request, _: None = Depends(require_auth)):
    return {"routes": list_routes(_load())}


@app.post("/api/routes")
def api_create(body: RouteIn, request: Request, _: None = Depends(require_auth)):
    host = body.host.strip().lower().rstrip(".")
    backend = body.backend.strip()
    if not re.match(r"^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$", host):
        raise HTTPException(400, "invalid hostname")
    if not re.match(r"^https?://", backend):
        raise HTTPException(400, "backend must start with http:// or https://")
    data = _load()
    # uniqueness
    for r in list_routes(data):
        if r["host"] == host and not r["system"]:
            raise HTTPException(409, f"host already used by {r['id']}")
    rid = (body.id or slugify(host)).strip()
    rid = re.sub(r"[^a-zA-Z0-9_-]", "-", rid)
    if rid in SYSTEM_ROUTERS:
        raise HTTPException(400, "reserved id")
    if rid in (data["http"]["routers"] or {}):
        raise HTTPException(409, "route id exists")
    mw = []
    if body.hsts_subdomains:
        mw = ["heil-hsts-include"]
    elif body.hsts:
        mw = ["heil-hsts"]
    # ensure middlewares exist
    mws = data["http"].setdefault("middlewares", {})
    mws.setdefault("heil-hsts", {"headers": {"stsSeconds": 63072000}})
    mws.setdefault(
        "heil-hsts-include",
        {"headers": {"stsSeconds": 63072000, "stsIncludeSubdomains": True}},
    )
    data["http"]["routers"][rid] = {
        "rule": f"Host(`{host}`)",
        "entryPoints": ["websecure"],
        "service": rid,
        **({"middlewares": mw} if mw else {}),
        "tls": {"certResolver": "letsencrypt"},
    }
    data["http"]["services"][rid] = {
        "loadBalancer": {
            "passHostHeader": True,
            "servers": [{"url": backend}],
        }
    }
    _dump(data)
    return {"ok": True, "route": next(r for r in list_routes(data) if r["id"] == rid)}


@app.put("/api/routes/{rid}")
def api_update(rid: str, body: RouteIn, request: Request, _: None = Depends(require_auth)):
    if rid in SYSTEM_ROUTERS:
        raise HTTPException(400, "system route is protected")
    data = _load()
    routers = data["http"]["routers"]
    if rid not in routers:
        raise HTTPException(404, "not found")
    host = body.host.strip().lower().rstrip(".")
    backend = body.backend.strip()
    if not re.match(r"^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$", host):
        raise HTTPException(400, "invalid hostname")
    if not re.match(r"^https?://", backend):
        raise HTTPException(400, "backend must start with http:// or https://")
    for r in list_routes(data):
        if r["host"] == host and r["id"] != rid and not r["system"]:
            raise HTTPException(409, f"host already used by {r['id']}")
    mw = []
    if body.hsts_subdomains:
        mw = ["heil-hsts-include"]
    elif body.hsts:
        mw = ["heil-hsts"]
    service = routers[rid].get("service") or rid
    routers[rid] = {
        "rule": f"Host(`{host}`)",
        "entryPoints": ["websecure"],
        "service": service,
        **({"middlewares": mw} if mw else {}),
        "tls": {"certResolver": "letsencrypt"},
    }
    data["http"]["services"][service] = {
        "loadBalancer": {
            "passHostHeader": True,
            "servers": [{"url": backend}],
        }
    }
    _dump(data)
    return {"ok": True, "route": next(r for r in list_routes(data) if r["id"] == rid)}


@app.delete("/api/routes/{rid}")
def api_delete(rid: str, request: Request, _: None = Depends(require_auth)):
    if rid in SYSTEM_ROUTERS:
        raise HTTPException(400, "system route is protected")
    data = _load()
    routers = data["http"]["routers"]
    if rid not in routers:
        raise HTTPException(404, "not found")
    service = routers[rid].get("service") or rid
    del routers[rid]
    # remove service if unused
    used = {r.get("service") for r in routers.values()}
    if service not in used and service in (data["http"].get("services") or {}):
        del data["http"]["services"][service]
    _dump(data)
    return {"ok": True}


@app.post("/login")
def login(response: Response, password: str = Form(...)):
    if not _verify_password(password):
        return RedirectResponse("/?e=1", status_code=303)
    token = signer.dumps({"ok": True, "t": time.time()})
    resp = RedirectResponse("/", status_code=303)
    resp.set_cookie(
        COOKIE_NAME,
        token,
        httponly=True,
        secure=True,
        samesite="lax",
        max_age=60 * 60 * 24 * 14,
    )
    return resp


@app.post("/logout")
def logout():
    resp = RedirectResponse("/", status_code=303)
    resp.delete_cookie(COOKIE_NAME)
    return resp


@app.get("/", response_class=HTMLResponse)
def index(request: Request):
    html = (STATIC / "index.html").read_text()
    authed = "true" if _auth_ok(request) else "false"
    html = html.replace("__AUTHED__", authed)
    return HTMLResponse(html)
