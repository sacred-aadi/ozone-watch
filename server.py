import hashlib
import os
import re
from datetime import datetime, timezone
from typing import Any

import httpx
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

load_dotenv()

USER_AGENT = os.getenv(
    "APP_USER_AGENT",
    "OzoneWatch/1.0 (free-breach-scanner; contact@example.com)",
)

XON_BASE = "https://api.xposedornot.com/v1"
LEAKCHECK_PUBLIC = "https://leakcheck.io/api/public"
DISIFY_BASE = "https://disify.com/api/email"
PWNED_PASSWORDS = "https://api.pwnedpasswords.com/range"

app = FastAPI(title="Ozone Watch API")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

_breach_catalog: dict[str, dict[str, Any]] = {}


class ScanRequest(BaseModel):
    input: str = Field(..., min_length=3, max_length=320)


class PasswordRequest(BaseModel):
    password: str = Field(..., min_length=4, max_length=128)


def valid_email(value: str) -> bool:
    return bool(re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", value))


def normalize_phone(value: str) -> str | None:
    digits = re.sub(r"\D", "", value)
    if len(digits) < 10 or len(digits) > 15:
        return None
    if digits.startswith("00"):
        digits = digits[2:]
    return digits


def client_headers() -> dict[str, str]:
    return {"User-Agent": USER_AGENT, "Accept": "application/json"}


def normalize_name(value: str) -> str:
    return re.sub(r"[^a-z0-9]", "", value.lower())


def map_leak_fields(fields: list[str]) -> list[str]:
    mapping = {
        "password": "Passwords",
        "email": "Email addresses",
        "phone": "Phone numbers",
        "username": "Usernames",
        "ip": "IP addresses",
        "name": "Names",
        "first_name": "Names",
        "last_name": "Names",
        "dob": "Dates of birth",
        "address": "Physical addresses",
        "ssn": "Government IDs",
    }
    mapped = {mapping.get(f, f.replace("_", " ").title()) for f in fields}
    return sorted(mapped)


async def fetch_json(
    client: httpx.AsyncClient,
    url: str,
    *,
    params: dict[str, Any] | None = None,
    optional: bool = False,
) -> dict[str, Any] | list[Any] | None:
    try:
        response = await client.get(url, params=params, headers=client_headers())
        if response.status_code == 404:
            return None
        if response.status_code == 429:
            if optional:
                return None
            raise HTTPException(status_code=429, detail="Rate limit hit. Try again shortly.")
        if response.status_code >= 400:
            if optional:
                return None
            raise HTTPException(
                status_code=502,
                detail=f"Upstream request failed ({response.status_code})",
            )
        return response.json()
    except httpx.RequestError:
        if optional:
            return None
        raise HTTPException(status_code=502, detail="Could not reach upstream data source.")


async def load_breach_catalog(client: httpx.AsyncClient) -> dict[str, dict[str, Any]]:
    global _breach_catalog
    if _breach_catalog:
        return _breach_catalog

    data = await fetch_json(client, f"{XON_BASE}/breaches", optional=True)
    if isinstance(data, dict):
        for breach in data.get("exposedBreaches", []):
            breach_id = breach.get("breachID")
            if breach_id:
                _breach_catalog[normalize_name(breach_id)] = breach
    return _breach_catalog


async def check_xposedornot_email(client: httpx.AsyncClient, email: str) -> list[str]:
    data = await fetch_json(client, f"{XON_BASE}/check-email/{email}", optional=True)
    if not isinstance(data, dict):
        return []
    if data.get("Error"):
        return []

    breaches = data.get("breaches")
    if not breaches:
        return []

    if isinstance(breaches, list) and breaches and isinstance(breaches[0], list):
        return [str(name) for name in breaches[0]]
    if isinstance(breaches, list):
        return [str(name) for name in breaches]
    return []


async def check_leakcheck(client: httpx.AsyncClient, value: str) -> dict[str, Any]:
    data = await fetch_json(
        client,
        LEAKCHECK_PUBLIC,
        params={"check": value},
        optional=True,
    )
    if not isinstance(data, dict) or not data.get("success"):
        return {"found": 0, "fields": [], "sources": []}

    return {
        "found": int(data.get("found") or 0),
        "fields": data.get("fields") or [],
        "sources": data.get("sources") or [],
    }


async def check_disify(client: httpx.AsyncClient, email: str) -> dict[str, Any]:
    data = await fetch_json(client, f"{DISIFY_BASE}/{email}", optional=True)
    if not isinstance(data, dict):
        return {}
    return {
        "format_valid": bool(data.get("format")),
        "disposable": bool(data.get("disposable")),
        "domain": data.get("domain"),
        "dns_valid": bool(data.get("dns")),
        "whitelist": bool(data.get("whitelist")),
    }


def enrich_xon_breach(name: str, catalog: dict[str, dict[str, Any]]) -> dict[str, Any]:
    meta = catalog.get(normalize_name(name), {})
    exposed = meta.get("exposedData") or []
    breached_date = meta.get("breachedDate") or ""
    year = breached_date[:4] if breached_date else "N/A"
    return {
        "source": meta.get("breachID") or name,
        "year": year,
        "date": breached_date[:10] if breached_date else None,
        "records": 0,
        "data_classes": exposed,
        "provider": "XposedOrNot",
        "verified": bool(meta.get("verified")),
        "sensitive": bool(meta.get("sensitive")),
    }


def merge_breaches(
    xon_names: list[str],
    leak_sources: list[dict[str, Any]],
    catalog: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    merged: dict[str, dict[str, Any]] = {}

    for name in xon_names:
        row = enrich_xon_breach(name, catalog)
        merged[normalize_name(row["source"])] = row

    for source in leak_sources:
        name = source.get("name") or "Unknown"
        key = normalize_name(name)
        date = source.get("date") or ""
        year = date[:4] if date else "N/A"
        if key in merged:
            merged[key]["provider"] = "XposedOrNot + LeakCheck"
            if date and merged[key]["year"] == "N/A":
                merged[key]["year"] = year
            continue
        merged[key] = {
            "source": name,
            "year": year,
            "date": date or None,
            "records": 0,
            "data_classes": [],
            "provider": "LeakCheck",
            "verified": True,
            "sensitive": False,
        }

    return list(merged.values())


def calculate_risk(
    breaches: list[dict[str, Any]],
    data_types: list[str],
    leak_hits: int,
    *,
    disposable: bool = False,
) -> str:
    score = 0

    for breach in breaches:
        classes = breach.get("data_classes") or []
        if any("password" in c.lower() for c in classes):
            score += 24
        if breach.get("sensitive"):
            score += 10
        if breach.get("verified"):
            score += 4

    if "Passwords" in data_types:
        score += 28
    if "Phone numbers" in data_types:
        score += 10
    if "Email addresses" in data_types:
        score += 6

    score += min(len(breaches) * 7, 28)
    if leak_hits > 0:
        score += min(12, max(4, len(str(leak_hits)) * 2))
    if disposable:
        score += 6

    if score >= 65:
        return "HIGH"
    if score >= 30:
        return "MEDIUM"
    return "LOW"


def build_actions(
    risk: str,
    data_types: list[str],
    *,
    disposable: bool = False,
    input_type: str = "email",
) -> list[str]:
    actions = [
        "Enable multi-factor authentication on primary accounts.",
        "Use a password manager and avoid reused passwords.",
    ]

    if "Passwords" in data_types:
        actions.insert(0, "Change passwords immediately for breached services.")
    if "Phone numbers" in data_types or input_type == "phone":
        actions.append("Harden SIM and carrier account recovery settings.")
    if disposable:
        actions.append("Avoid disposable emails for banking, work, or recovery accounts.")
    if risk == "HIGH":
        actions.append("Prioritize critical accounts: email, banking, cloud storage.")
    elif risk == "MEDIUM":
        actions.append("Monitor account logins and alert emails for 30 days.")
    else:
        actions.append("Run periodic scans — new breaches appear every week.")

    seen: set[str] = set()
    unique: list[str] = []
    for action in actions:
        if action not in seen:
            seen.add(action)
            unique.append(action)
    return unique


@app.get("/")
async def root():
    return FileResponse("index.html")


@app.get("/scanner.js")
async def scanner_js():
    return FileResponse("scanner.js", media_type="application/javascript")


@app.get("/api/health")
async def health():
    return {
        "status": "ok",
        "mode": "free",
        "sources": [
            "XposedOrNot (email breaches)",
            "LeakCheck public (email + phone)",
            "Disify (email intel)",
            "HIBP Pwned Passwords (password check)",
        ],
        "api_keys_required": False,
    }


@app.post("/api/scan")
async def scan(payload: ScanRequest):
    raw = payload.input.strip()
    input_type = "email"
    query_value = raw

    if valid_email(raw):
        query_value = raw.lower()
    else:
        phone = normalize_phone(raw)
        if not phone:
            raise HTTPException(
                status_code=400,
                detail="Enter a valid email or phone number (10-15 digits).",
            )
        query_value = phone
        input_type = "phone"

    sources_used: list[str] = []
    email_intel: dict[str, Any] = {}

    async with httpx.AsyncClient(timeout=20.0) as client:
        catalog = await load_breach_catalog(client)

        xon_names: list[str] = []
        if input_type == "email":
            xon_names = await check_xposedornot_email(client, query_value)
            if xon_names:
                sources_used.append("XposedOrNot")

            email_intel = await check_disify(client, query_value)
            if email_intel:
                sources_used.append("Disify")

        leak = await check_leakcheck(client, query_value)
        if leak.get("found") or leak.get("sources"):
            sources_used.append("LeakCheck")

        breaches = merge_breaches(xon_names, leak.get("sources", []), catalog)
        leak_types = map_leak_fields(leak.get("fields", []))
        catalog_types = sorted(
            {
                cls
                for breach in breaches
                for cls in (breach.get("data_classes") or [])
            }
        )
        data_types = sorted(set(leak_types + catalog_types))

        risk = calculate_risk(
            breaches,
            data_types,
            int(leak.get("found") or 0),
            disposable=bool(email_intel.get("disposable")),
        )
        actions = build_actions(
            risk,
            data_types,
            disposable=bool(email_intel.get("disposable")),
            input_type=input_type,
        )

    if not sources_used:
        sources_used = ["No live source responded"]

    return {
        "target": raw,
        "input_type": input_type,
        "risk": risk,
        "breach_count": len(breaches),
        "paste_count": 0,
        "leakcheck_hits": int(leak.get("found") or 0),
        "data_types": data_types,
        "breaches": breaches,
        "pastes": [],
        "actions": actions,
        "sources_used": sources_used,
        "email_intel": email_intel,
        "source": " + ".join(sources_used),
        "confidence": "medium" if len(sources_used) >= 2 else "basic",
    }


@app.post("/api/check-password")
async def check_password(payload: PasswordRequest):
    digest = hashlib.sha1(payload.password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = digest[:5], digest[5:]

    async with httpx.AsyncClient(timeout=15.0) as client:
        response = await client.get(
            f"{PWNED_PASSWORDS}/{prefix}",
            headers={**client_headers(), "Add-Padding": "true"},
        )
        if response.status_code >= 400:
            raise HTTPException(status_code=502, detail="Password check service unavailable.")

        count = 0
        for line in response.text.splitlines():
            hash_suffix, _, exposures = line.partition(":")
            if hash_suffix == suffix:
                count = int(exposures)
                break

    if count >= 1000:
        risk = "HIGH"
    elif count > 0:
        risk = "MEDIUM"
    else:
        risk = "LOW"

    return {
        "exposed": count > 0,
        "count": count,
        "risk": risk,
        "source": "HIBP Pwned Passwords (free)",
        "message": (
            f"Seen {count:,} times in known breach corpuses."
            if count
            else "Not found in known breached password lists."
        ),
    }
