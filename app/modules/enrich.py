"""Enriquecedores automáticos: se ejecutan solos sobre cada entidad nueva que encaje."""

import asyncio
import html
import json
import re
import time
from urllib.parse import urlparse

import httpx

from ..config import DATA_DIR
from .base import Module, Skip, register

DISCORD_INVITE = re.compile(r"^https?://(?:www\.)?(?:discord\.gg|discord(?:app)?\.com/invite)/([A-Za-z0-9\-]{2,32})/?$", re.I)
DISCORD_EPOCH_MS = 1420070400000


def snowflake_date(sid) -> str | None:
    try:
        return time.strftime("%Y-%m-%d", time.gmtime(((int(sid) >> 22) + DISCORD_EPOCH_MS) / 1000))
    except (TypeError, ValueError):
        return None


@register
class DiscordInvite(Module):
    name = "discord_invite"
    title = "Invitación de Discord"
    description = "Servidor, número de miembros, fecha de creación y quién creó la invitación."
    inputs = ("url",)
    sources = ("API pública de Discord",)
    auto = True

    def applies(self, entity):
        return entity["type"] == "url" and bool(DISCORD_INVITE.match(entity["value"]))

    async def run(self, ctx):
        code = DISCORD_INVITE.match(ctx.value).group(1)
        st, d = await ctx.get_json(f"https://discord.com/api/v10/invites/{code}",
                                   params={"with_counts": "true", "with_expiration": "true"})
        if st == 404 or not isinstance(d, dict) or not d.get("guild"):
            ctx.message = "Invitación caducada o inválida"
            return
        g = d["guild"]
        icon = f"https://cdn.discordapp.com/icons/{g['id']}/{g['icon']}.png" if g.get("icon") else None
        ctx.enrich({
            "Servidor": g.get("name"),
            "Miembros": d.get("approximate_member_count"),
            "En línea": d.get("approximate_presence_count"),
            "Caduca": (d.get("expires_at") or "")[:10] or "Nunca",
        })
        org = ctx.add("organization", f"Discord: {g.get('name')}", {
            "ID del servidor": g["id"],
            "Descripción": g.get("description"),
            "Servidor creado": snowflake_date(g["id"]),
            "Miembros": d.get("approximate_member_count"),
            "URL personalizada": g.get("vanity_url_code"),
            "_avatar": icon,
        }, rel="servidor", pivot=False)
        inv = d.get("inviter")
        if inv and org:
            avatar = f"https://cdn.discordapp.com/avatars/{inv['id']}/{inv['avatar']}.png" if inv.get("avatar") else None
            acc = ctx.add("account", f"https://discord.com/users/{inv['id']}", {
                "Plataforma": "Discord", "Usuario": inv.get("username"), "Nombre visible": inv.get("global_name"),
                "ID": inv["id"], "Creada": snowflake_date(inv["id"]), "Verificación": "Creó la invitación",
                "_avatar": avatar, "_links": [["Perfil", f"https://discord.com/users/{inv['id']}"]],
            }, rel="invitación creada por", pivot=False)
            if acc and inv.get("username"):
                ctx.add("username", inv["username"], rel="usuario", parent=acc, pivot=False)


_geo_lock = asyncio.Lock()
_geo_last = 0.0
_GEO_CACHE = DATA_DIR / "geocache.json"
_COORDS = re.compile(r"^\s*(-?\d{1,2}(?:\.\d+)?)\s*,\s*(-?\d{1,3}(?:\.\d+)?)\s*$")


def _load_cache() -> dict:
    try:
        return json.loads(_GEO_CACHE.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


@register
class Geocode(Module):
    name = "geocode"
    title = "Geolocalizar ubicación"
    description = "Convierte el texto de una ubicación en coordenadas para mostrarla en el mapa."
    inputs = ("location",)
    sources = ("OpenStreetMap Nominatim",)
    timeout = 180
    auto = True

    def applies(self, entity):
        return entity["type"] == "location" and entity["attrs"].get("_lat") is None

    async def run(self, ctx):
        global _geo_last
        q = " ".join(ctx.value.split())
        m = _COORDS.match(q)
        if m:
            lat, lon = float(m.group(1)), float(m.group(2))
            ctx.enrich({"_lat": lat, "_lon": lon})
            return
        if len(q) < 2:
            return
        key = q.lower()
        cache = _load_cache()
        if key not in cache:
            async with _geo_lock:
                # Política de uso de Nominatim: como máximo una petición por segundo.
                wait = 1.1 - (time.time() - _geo_last)
                if wait > 0:
                    await asyncio.sleep(wait)
                st, d = await ctx.get_json(
                    "https://nominatim.openstreetmap.org/search",
                    params={"q": q, "format": "json", "limit": 1, "accept-language": "es"},
                    headers={"User-Agent": "OsintHunter/1.0 (herramienta OSINT local)"},
                )
                _geo_last = time.time()
            if st != 200 or not isinstance(d, list):
                ctx.message = f"Nominatim respondió {st}"
                return
            cache = _load_cache()
            cache[key] = d[0] if d else None
            _GEO_CACHE.write_text(json.dumps(cache, ensure_ascii=False), encoding="utf-8")
        hit = cache.get(key)
        if not hit:
            ctx.message = "No se encontró en el mapa"
            return
        lat, lon = float(hit["lat"]), float(hit["lon"])
        ctx.enrich({
            "_lat": lat, "_lon": lon,
            "Lugar (OpenStreetMap)": hit.get("display_name"),
            "_links": [["Ver en mapa", f"https://www.openstreetmap.org/?mlat={lat}&mlon={lon}#map=10/{lat}/{lon}"]],
        })


# Flickr sólo deja consultar fotos públicas sin clave a través del feed, y el feed pide el ID interno (NSID)
FLICKR_NSID = re.compile(r"(?:flickr\.com/(?:photos|people)/)?(\d{5,12}@N\d{2})\b", re.I)


@register
class FlickrGeo(Module):
    name = "flickr_geo"
    title = "Flickr: fotos con ubicación"
    description = ("Lee las últimas fotos públicas de un usuario de Flickr (por su ID tipo 12345678@N04) y "
                   "pone en el mapa las que guardan coordenadas GPS")
    inputs = ("url", "username")
    sources = ("Feed público de Flickr",)
    auto = True

    def applies(self, entity):
        return entity["type"] in self.inputs and bool(FLICKR_NSID.search(entity["value"]))

    async def run(self, ctx):
        nsid = FLICKR_NSID.search(ctx.value).group(1).upper()
        r = await ctx.http.get("https://www.flickr.com/services/feeds/photos_public.gne",
                               params={"id": nsid, "format": "rss2", "georss": "1"}, timeout=30)
        if r.status_code != 200 or "<item>" not in r.text:
            ctx.message = "Sin fotos públicas o el usuario no existe"
            return
        xml = r.text
        owner = re.search(r"<title>Uploads from ([^<]+)</title>", xml)
        items = re.findall(r"<item>(.*?)</item>", xml, re.S)
        clusters: dict[tuple[float, float], dict] = {}
        taken = []
        for it in items:
            date = re.search(r"<dc:date\.Taken>([^<]+)", it)
            if date:
                taken.append(date.group(1)[:10])
            pt = re.search(r"<georss:point>\s*([-\d.]+)\s+([-\d.]+)", it)
            if not pt:
                continue
            lat, lon = float(pt.group(1)), float(pt.group(2))
            key = (round(lat, 2), round(lon, 2))
            c = clusters.setdefault(key, {"n": 0, "lat": lat, "lon": lon, "dates": [], "links": []})
            c["n"] += 1
            link = re.search(r"<link>([^<]+)</link>", it)
            title = re.search(r"<title>([^<]*)</title>", it)
            if link:
                c["links"].append([f"Foto: {(title.group(1) if title else '')[:50] or 'sin título'}", link.group(1)])
            if date:
                c["dates"].append(date.group(1)[:10])
        url = f"https://www.flickr.com/photos/{nsid}/"
        acc = ctx.add("account", url, {
            "Plataforma": "Flickr", "Usuario": nsid, "Nombre visible": owner.group(1).strip() if owner else None,
            "Fotos públicas recientes": len(items), "Fotos con GPS": sum(c["n"] for c in clusters.values()),
            "Primera foto reciente": min(taken) if taken else None, "Última foto": max(taken) if taken else None,
            "_links": [["Abrir perfil", url]],
        }, rel="cuenta", pivot=False)
        for c in sorted(clusters.values(), key=lambda c: -c["n"])[:15]:
            ctx.add("location", f"{c['lat']:.4f}, {c['lon']:.4f}", {
                "_lat": c["lat"], "_lon": c["lon"], "Fotos tomadas aquí": c["n"],
                "Fechas": sorted(set(c["dates"]))[:10] or None, "_links": c["links"][:5],
            }, rel="foto tomada en", parent=acc)
        ctx.message = f"{len(items)} fotos recientes · {len(clusters)} lugares con GPS"


# ---------------------------------------------------------------- perfil público de cuentas sin datos

META_TAG = re.compile(r"<meta\b[^>]*>", re.I)
META_KEY = re.compile(r'(?:property|name)\s*=\s*["\']((?:og|twitter):(?:title|description|image))["\']', re.I)
META_VAL = re.compile(r'content\s*=\s*"([^"]*)"|content\s*=\s*\'([^\']*)\'', re.I)
TITLE_TAG = re.compile(r"<title[^>]*>(.*?)</title>", re.S | re.I)
WALL_TITLES = re.compile(r"just a moment|client challenge|attention required|access denied|captcha|log ?in|sign ?in|sign ?up|"
                         r"iniciar sesi[oó]n|reg[ií]strate|not found|no encontrad|page not|404|error", re.I)
GENERIC_IMAGE = re.compile(r"default|placeholder|logo|/static/|og[-_]?image|web-capture|share|banner|-og-|_og_|"
                           r"opengraph|social[-_]?(?:card|preview)|favicon|sprite|brand", re.I)
GENERIC_WORDS = re.compile(r"\b(live|stream|profile|perfil|photos|videos|watch|home|official|user|usuario|page|"
                           r"p[aá]gina|account|cuenta|channel|canal|games?)\b", re.I)
NO_PAGE_PLATFORMS = {"Facebook", "LinkedIn", "Instagram", "TikTok", "X/Twitter", "Pinterest"}
_home_cache: dict[str, dict] = {}


def page_meta(page: str) -> dict:
    out: dict[str, str] = {}
    for tag in META_TAG.findall(page[:500_000]):
        k, v = META_KEY.search(tag), META_VAL.search(tag)
        if k and v and k.group(1).lower() not in out:
            out[k.group(1).lower()] = html.unescape(v.group(1) or v.group(2) or "").strip()
    t = TITLE_TAG.search(page[:500_000])
    out["title"] = html.unescape(re.sub(r"\s+", " ", t.group(1))).strip() if t else ""
    return out


async def _home(http, url: str) -> dict:
    """Metadatos de la portada del sitio: lo que se repite ahí es genérico, no del perfil."""
    p = urlparse(url)
    host = f"{p.scheme}://{p.netloc}/"
    if host not in _home_cache:
        try:
            r = await http.get(host, timeout=12)
            _home_cache[host] = page_meta(r.text) if r.status_code == 200 else {}
        except httpx.HTTPError:
            _home_cache[host] = {}
    return _home_cache[host]


def name_from_title(title: str, user: str, platform: str, host: str) -> str | None:
    """Nombre visible a partir del título de la página («Ana (@anita_r) | Snapchat» → «Ana»)."""
    if not title or WALL_TITLES.search(title):
        return None
    u = user.lower()
    site = {platform.lower(), host.split(".")[-2] if host.count(".") else host}
    m = re.match(r"^(.*?)\s*\(@?([\w.\-]+)\)", title)
    if m and m.group(2).lower() == u:
        cand = m.group(1)
    else:
        parts = [p for p in re.split(r"\s+[|\-–—·•:]\s+", title) if p.strip()]
        cand = next((p for p in parts if not any(s and s in p.lower() for s in site)), "")
    cand = re.sub(r"\s+(?:en|on|at|auf|sur|na|no)\s+\S+$", "", cand.strip())
    cand = re.sub(r"(?i)^(?:perfil de|profile of|perfil|profile)\s+|['’]s?\s+(?:profile|page)$", "", cand).strip(" -|·•")
    if (not cand or len(cand) > 60 or u in cand.lower() or not re.search(r"[^\W\d_]", cand)
            or GENERIC_WORDS.search(cand) or any(s and s in cand.lower() for s in site)):
        return None
    return cand


@register
class AccountPage(Module):
    name = "account_page"
    title = "Leer el perfil público"
    description = ("Abre la página de la cuenta y saca el nombre visible, la foto y la descripción que muestra a cualquiera. "
                   "Sirve para las cuentas de las que sólo se sabía que existen: con eso se pueden puntuar y comparar.")
    inputs = ("account",)
    sources = ("Página pública del perfil",)
    timeout = 40
    auto = True

    def applies(self, entity: dict) -> bool:
        a = entity.get("attrs") or {}
        return (entity["type"] == "account" and a.get("Plataforma") not in NO_PAGE_PLATFORMS
                and not any(a.get(k) for k in ("Nombre", "Nombre visible", "Nombre real", "_avatar")))

    async def run(self, ctx):
        url = ctx.value if ctx.value.startswith("http") else None
        if not url:
            raise Skip("La cuenta no tiene una URL que abrir")
        a = ctx.entity.get("attrs") or {}
        user, platform = str(a.get("Usuario") or ""), str(a.get("Plataforma") or "")
        r = await ctx.http.get(url, timeout=15)
        if r.status_code in (404, 410):
            ctx.enrich({"Página del perfil": "No existe (error 404): puede ser un falso positivo"})
            ctx.message = "La página del perfil no existe"
            return
        meta = page_meta(r.text)
        if r.status_code != 200 or WALL_TITLES.search(meta["title"]) and not meta.get("og:title"):
            raise Skip(f"La página no deja leer el perfil sin navegador (respuesta {r.status_code})")
        home = await _home(ctx.http, url)
        host = (urlparse(str(r.url)).hostname or "").removeprefix("www.")
        same = lambda k: meta.get(k) and meta.get(k) == home.get(k)  # noqa: E731
        name = None
        for t in (meta["title"], meta.get("og:title"), meta.get("twitter:title")):
            if t and t != home.get("title") and t != home.get("og:title"):
                name = name_from_title(t, user, platform, host)
                if name:
                    break
        img = meta.get("og:image") or meta.get("twitter:image")
        if img and (same("og:image") or GENERIC_IMAGE.search(img) or not img.startswith("http")):
            img = None
        desc = meta.get("og:description") or ""
        if same("og:description") or platform.lower() in desc.lower() or (user and user.lower() in desc.lower()
                                                                           and len(desc) < 160):
            desc = ""
        ctx.enrich({"Nombre visible": name, "Descripción": desc[:400] or None, "_avatar": img})
        got = [x for x, v in (("nombre", name), ("foto", img), ("descripción", desc)) if v]
        ctx.message = ("Leído: " + ", ".join(got)) if got else "La página no muestra nombre ni foto"
