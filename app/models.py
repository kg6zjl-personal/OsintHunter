import ipaddress
import re

from .config import settings

# tipo -> (nombre visible, color, forma en el grafo, ¿se puede investigar directamente?)
ENTITY_TYPES: dict[str, dict] = {
    "username": {"label": "Usuario", "color": "#4fc3f7", "shape": "ellipse", "input": True},
    "email": {"label": "Email", "color": "#ffb74d", "shape": "round-rectangle", "input": True},
    "phone": {"label": "Teléfono", "color": "#81c784", "shape": "round-rectangle", "input": True},
    "person": {"label": "Persona", "color": "#f06292", "shape": "ellipse", "input": True},
    "domain": {"label": "Dominio", "color": "#ba68c8", "shape": "hexagon", "input": True},
    "ip": {"label": "IP", "color": "#e57373", "shape": "diamond", "input": True},
    "url": {"label": "URL", "color": "#90a4ae", "shape": "round-tag", "input": True},
    "hash": {"label": "Hash", "color": "#a1887f", "shape": "rectangle", "input": True},
    "crypto": {"label": "Cripto", "color": "#ffd54f", "shape": "octagon", "input": True},
    "rut": {"label": "RUT", "color": "#ff8a65", "shape": "round-pentagon", "input": True},
    "plate": {"label": "Patente", "color": "#dce775", "shape": "cut-rectangle", "input": True},
    "account": {"label": "Cuenta", "color": "#4db6ac", "shape": "round-rectangle", "input": False},
    "location": {"label": "Ubicación", "color": "#aed581", "shape": "triangle", "input": False},
    "organization": {"label": "Organización", "color": "#7986cb", "shape": "barrel", "input": False},
    "asn": {"label": "ASN", "color": "#9575cd", "shape": "barrel", "input": False},
    "breach": {"label": "Filtración", "color": "#ef5350", "shape": "star", "input": False},
    "image": {"label": "Imagen", "color": "#4dd0e1", "shape": "rectangle", "input": False},
}

# Tipos que el pivotado automático (profundidad > 0) vuelve a investigar.
AUTO_PIVOT_TYPES = {"username", "email", "phone", "domain", "ip", "crypto", "rut"}

_RUT = re.compile(r"^\d{1,2}(?:\.\d{3}){2}-?[\dkK]$|^\d{7,8}-[\dkK]$")
_PLATE_SEP = re.compile(r"^[A-Za-z]{2}[\s.\-·•][A-Za-z]{2}[\s.\-·•]?\d{2}$|^[A-Za-z]{2,4}[\s.\-·•]\d{2,4}$")

_EMAIL = re.compile(r"^[^@\s]+@[^@\s]+\.[a-z]{2,}$", re.I)
_DOMAIN = re.compile(r"^(?=.{4,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$", re.I)
_PHONE = re.compile(r"^\+?[\d\s().\-]{7,22}$")
_HEX = re.compile(r"^[a-f0-9]+$", re.I)

CRYPTO_PATTERNS = {
    "btc": re.compile(r"^(?:bc1[ac-hj-np-z02-9]{25,62}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})$"),
    "eth": re.compile(r"^0x[a-fA-F0-9]{40}$"),
    "ltc": re.compile(r"^(?:ltc1[ac-hj-np-z02-9]{25,62}|[LM][a-km-zA-HJ-NP-Z1-9]{26,33})$"),
    "doge": re.compile(r"^D[5-9A-HJ-NP-U][1-9A-HJ-NP-Za-km-z]{32}$"),
    "trx": re.compile(r"^T[1-9A-HJ-NP-Za-km-z]{33}$"),
}
CRYPTO_NAMES = {"btc": "Bitcoin", "eth": "Ethereum / EVM", "ltc": "Litecoin", "doge": "Dogecoin", "trx": "Tron"}


def crypto_chain(value: str) -> str | None:
    for chain, rx in CRYPTO_PATTERNS.items():
        if rx.match(value):
            return chain
    return None


def detect_type(value: str) -> str:
    v = value.strip()
    if re.match(r"^https?://", v, re.I):
        return "url"
    if _EMAIL.match(v):
        return "email"
    try:
        ipaddress.ip_address(v)
        return "ip"
    except ValueError:
        pass
    if crypto_chain(v):
        return "crypto"
    if _HEX.match(v) and len(v) in (32, 40, 56, 64, 96, 128):
        return "hash"
    if settings.chile_enabled():
        from .modules.chile import plate_kind

        if _RUT.match(v):
            return "rut"
        # sin separadores sólo en mayúsculas, para no confundir con usuarios tipo «abcd12»
        if plate_kind(v) and (_PLATE_SEP.match(v) or (v.isupper() and re.fullmatch(r"[A-Z]{4}\d{2}|[A-Z]{2}\d{4}", v))):
            return "plate"
    digits = re.sub(r"\D", "", v)
    if _PHONE.match(v) and 7 <= len(digits) <= 15 and (v.startswith("+") or not re.search(r"[a-z]", v, re.I)):
        return "phone"
    if _DOMAIN.match(v):
        return "domain"
    if " " in v:
        return "person"
    return "username"


def normalize(etype: str, value: str) -> str:
    v = (value or "").strip()
    if etype in ("email", "domain", "username", "hash"):
        v = v.lower()
    if etype == "domain":
        v = v.rstrip(".")
    elif etype == "username":
        v = v.lstrip("@")
    elif etype == "ip":
        try:
            v = str(ipaddress.ip_address(v))
        except ValueError:
            pass
    elif etype == "phone":
        v = re.sub(r"[^\d+]", "", v)
    elif etype == "person":
        v = " ".join(v.split()).title()
    elif etype == "account":
        v = v.rstrip("/")
    elif etype == "rut" and settings.chile_enabled():
        from .modules.chile import rut_fmt, rut_parts

        p = rut_parts(v)
        v = rut_fmt(*p) if p else v.upper()
    elif etype == "plate" and settings.chile_enabled():
        from .modules.chile import plate_clean

        v = plate_clean(v)
    return v


def entity_id(etype: str, value: str) -> str:
    key = value.lower() if etype in ("account", "url", "location", "organization", "person") else value
    return f"{etype}:{key}"


def display_label(etype: str, value: str, attrs: dict) -> str:
    if etype == "account":
        platform = attrs.get("Plataforma") or ""
        user = attrs.get("Usuario") or ""
        if platform:
            return f"{platform}: {user}" if user else platform
    if etype == "asn" and attrs.get("Organización"):
        return f"{value} {attrs['Organización']}"
    if etype == "image" and attrs.get("Archivo"):
        return attrs["Archivo"]
    if etype == "plate" and settings.chile_enabled():
        from .modules.chile import plate_display

        return plate_display(value)
    return value


def entity_types_public() -> dict:
    """Entity type catalog for the UI; hide Chile-only inputs when disabled."""
    if settings.chile_enabled():
        return ENTITY_TYPES
    skip = {"rut", "plate"}
    return {k: v for k, v in ENTITY_TYPES.items() if k not in skip}
