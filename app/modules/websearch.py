"""Búsqueda web real por nombre de persona, con el nombre completo y sus formas abreviadas."""
import asyncio
import base64
import html
import re
from urllib.parse import parse_qs, unquote, urlparse

import httpx

from ..config import settings
from ..db import db
from .base import Module, register
from .people import name_match, name_variants

UA = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/130.0 Safari/537.36", "Accept-Language": "es-CL,es;q=0.9,en;q=0.5"}

SOCIAL = "(site:linkedin.com/in OR site:facebook.com OR site:instagram.com OR site:x.com OR site:tiktok.com)"

PROFILE_PATTERNS = [
    ("LinkedIn", re.compile(r"^(?:[a-z]{2,3}\.)?linkedin\.com/in/([^/]+)$"), "https://www.linkedin.com/in/{}"),
    ("Facebook", re.compile(r"^(?:[a-z\-]+\.)?facebook\.com/people/[^/]+/(\d+)$"), "https://www.facebook.com/profile.php?id={}"),
    ("Facebook", re.compile(r"^(?:[a-z\-]+\.)?facebook\.com/(?!public|pages|groups|events|watch|hashtag|share|story|photo|"
                            r"permalink|login|marketplace|reel|profile\.php)([A-Za-z0-9.\-]{3,})$"), "https://www.facebook.com/{}"),
    ("Instagram", re.compile(r"^(?:www\.)?instagram\.com/(?!p/|reel|explore|stories|accounts)([A-Za-z0-9._]{2,30})$"),
     "https://www.instagram.com/{}"),
    ("X/Twitter", re.compile(r"^(?:www\.|mobile\.)?(?:twitter|x)\.com/(?!search|hashtag|i$|intent|home)([A-Za-z0-9_]{2,15})$"),
     "https://x.com/{}"),
    ("TikTok", re.compile(r"^(?:www\.)?tiktok\.com/@([A-Za-z0-9._]{2,24})$"), "https://www.tiktok.com/@{}"),
]

REGION_CODES = {"CL": ("cl", "cl-es"), "AR": ("ar", "ar-es"), "ES": ("es", "es-es"), "MX": ("mx", "mx-es"),
                "CO": ("co", "co-es"), "PE": ("pe", "pe-es"), "US": ("us", "us-en")}


class RateLimited(Exception):
    pass


def profile_of(url: str) -> tuple[str, str, str] | None:
    """(plataforma, usuario, url canónica) si el resultado es un perfil personal."""
    p = urlparse(url)
    if (p.hostname or "").endswith("facebook.com") and p.path.rstrip("/") == "/profile.php":
        uid = (parse_qs(p.query).get("id") or [""])[0]
        return ("Facebook", uid, f"https://www.facebook.com/profile.php?id={uid}") if uid.isdigit() else None
    path = f"{(p.hostname or '').lower()}{p.path}".rstrip("/")
    for platform, rx, tpl in PROFILE_PATTERNS:
        m = rx.match(path)
        if m:
            user = unquote(m.group(1))
            return platform, user, tpl.format(user)
    return None


def _clean(s: str) -> str:
    return html.unescape(re.sub(r"<[^>]+>", "", s or "")).strip()


async def _serper(http, q, gl):
    r = await http.post("https://google.serper.dev/search", json={"q": q, "gl": gl, "hl": "es", "num": 20},
                        headers={"X-API-KEY": settings.key("serper")})
    if r.status_code == 429:
        raise RateLimited("Serper: cuota agotada")
    r.raise_for_status()
    return [(x.get("title", ""), x.get("link", ""), x.get("snippet", "")) for x in r.json().get("organic") or []]


async def _brave(http, q, gl):
    r = await http.get("https://api.search.brave.com/res/v1/web/search", params={"q": q, "count": 20, "country": gl},
                       headers={"X-Subscription-Token": settings.key("brave"), "Accept": "application/json"})
    if r.status_code == 429:
        raise RateLimited("Brave: límite de peticiones")
    r.raise_for_status()
    return [(_clean(x.get("title")), x.get("url", ""), _clean(x.get("description")))
            for x in (r.json().get("web") or {}).get("results") or []]


DDG_LINK = re.compile(r'<a\b([^>]*class="result__a"[^>]*)>(.*?)</a>', re.S)
DDG_HREF = re.compile(r'href="([^"]+)"')
DDG_SNIPPET = re.compile(r'class="result__snippet"[^>]*>(.*?)</(?:a|td|div)>', re.S)


async def _ddg(http, q, kl):
    r = await http.post("https://html.duckduckgo.com/html/", data={"q": q, "kl": kl}, headers=UA)
    if r.status_code != 200 or "anomaly" in r.text[:5000].lower():
        raise RateLimited("DuckDuckGo limitó las búsquedas automáticas")
    return parse_ddg(r.text)


def parse_ddg(page: str) -> list[tuple[str, str, str]]:
    out = []
    links = list(DDG_LINK.finditer(page))
    for i, m in enumerate(links):
        h = DDG_HREF.search(m.group(1))
        if not h:
            continue
        href = html.unescape(h.group(1))
        title = m.group(2)
        rest = page[m.end():links[i + 1].start() if i + 1 < len(links) else len(page)]
        if "uddg=" in href:
            href = unquote(parse_qs(urlparse(href).query).get("uddg", [""])[0])
        if href.startswith("//"):
            href = "https:" + href
        if "duckduckgo.com/y.js" in href or not href.startswith("http"):
            continue
        sn = DDG_SNIPPET.search(rest)
        out.append((_clean(title), href, _clean(sn.group(1)) if sn else ""))
    return out


LITE_LINK = re.compile(r"<a\b[^>]*href=\"([^\"]+)\"[^>]*class='result-link'[^>]*>(.*?)</a>", re.S)
LITE_SNIPPET = re.compile(r"<td class='result-snippet'>(.*?)</td>", re.S)


async def _ddg_lite(http, q, kl):
    r = await http.post("https://lite.duckduckgo.com/lite/", data={"q": q, "kl": kl}, headers=UA)
    if r.status_code != 200 or "anomaly" in r.text[:5000].lower():
        raise RateLimited("DuckDuckGo Lite limitó las búsquedas automáticas")
    return parse_ddg_lite(r.text)


def parse_ddg_lite(page: str) -> list[tuple[str, str, str]]:
    out = []
    links = list(LITE_LINK.finditer(page))
    for i, m in enumerate(links):
        href = html.unescape(m.group(1))
        if "uddg=" in href:
            href = unquote(parse_qs(urlparse(href).query).get("uddg", [""])[0])
        if not href.startswith("http") or "duckduckgo.com/y.js" in href:
            continue
        rest = page[m.end():links[i + 1].start() if i + 1 < len(links) else len(page)]
        sn = LITE_SNIPPET.search(rest)
        out.append((_clean(m.group(2)), href, _clean(sn.group(1)) if sn else ""))
    return out


BING_ITEM = re.compile(r'<li class="b_algo"(.*?)</li>', re.S)
BING_TITLE = re.compile(r'<h2[^>]*>\s*<a\b[^>]*href="([^"]+)"[^>]*>(.*?)</a>', re.S)
BING_SNIPPET = re.compile(r"<p\b[^>]*>(.*?)</p>", re.S)


def _bing_target(href: str) -> str:
    """Bing envuelve los enlaces en /ck/a?…&u=a1<url en base64>."""
    href = html.unescape(href)
    if "bing.com/ck/a" in href:
        u = (parse_qs(urlparse(href).query).get("u") or [""])[0]
        if u.startswith("a1"):
            try:
                return base64.urlsafe_b64decode(u[2:] + "=" * (-len(u[2:]) % 4)).decode("utf-8", "replace")
            except ValueError:
                return ""
    return href


async def _bing(http, q, gl):
    r = await http.get("https://www.bing.com/search", params={"q": q, "cc": gl, "setlang": "es", "count": 30}, headers=UA)
    if r.status_code != 200 or ('class="b_algo"' not in r.text and "captcha" in r.text.lower()):
        raise RateLimited("Bing limitó las búsquedas automáticas")
    return parse_bing(r.text)


def parse_bing(page: str) -> list[tuple[str, str, str]]:
    out = []
    for item in BING_ITEM.finditer(page):
        t = BING_TITLE.search(item.group(1))
        if not t:
            continue
        url = _bing_target(t.group(1))
        if not url.startswith("http"):
            continue
        sn = BING_SNIPPET.search(item.group(1))
        snippet = re.sub(r"^.*?&nbsp;·&#32;|^.*?\u00a0·\u00a0", "", sn.group(1)) if sn else ""
        out.append((_clean(t.group(2)), url, _clean(snippet)))
    return out


# Sin clave: si un buscador bloquea, la misma consulta sigue en el siguiente.
FREE_ENGINES = (("DuckDuckGo", _ddg, 1), ("DuckDuckGo Lite", _ddg_lite, 1), ("Bing", _bing, 0))


async def free_search(http, queries: list[str], region: tuple[str, str]):
    """(resultados, buscadores usados, aviso si todos bloquearon)."""
    results, used, i = [], [], 0
    for n, q in enumerate(queries):
        while i < len(FREE_ENGINES):
            name, call, arg = FREE_ENGINES[i]
            try:
                results += await call(http, q, region[arg])
            except RateLimited:
                i += 1
                continue
            except httpx.HTTPError:
                i += 1
                continue
            if name not in used:
                used.append(name)
            break
        if i >= len(FREE_ENGINES):
            return results, used, "Los buscadores gratuitos (DuckDuckGo y Bing) limitaron las búsquedas automáticas"
        if n < len(queries) - 1:
            await asyncio.sleep(1.5)
    return results, used, None


@register
class WebSearch(Module):
    name = "web_search"
    title = "Búsqueda web del nombre (completo y abreviado)"
    description = ("Busca el nombre en la web y en LinkedIn, Facebook, Instagram, X y TikTok, también sin el segundo "
                   "nombre o apellido. Con clave de Serper o Brave es más fiable; sin clave usa DuckDuckGo y, si "
                   "bloquea, sigue con Bing.")
    inputs = ("person",)
    optional_keys = ("serper", "brave")
    sources = ("Serper (Google)", "Brave Search", "DuckDuckGo")
    timeout = 120

    async def run(self, ctx):
        full = " ".join(ctx.value.split())
        variants = name_variants(full)
        region = REGION_CODES.get((settings.get("default_region") or "CL").upper(), ("cl", "cl-es"))
        gl = region[0]
        queries = [f'"{full}"', f'"{full}" {SOCIAL}'] + [f'"{v}" {SOCIAL}' for v in variants[:3]]
        if variants:
            queries.append(f'"{variants[0]}"')

        if settings.key("serper"):
            engine, call = "Google (Serper)", _serper
        elif settings.key("brave"):
            engine, call = "Brave Search", _brave
        else:
            engine, call = None, None

        results, limited = [], None
        if call is None:
            results, used, limited = await free_search(ctx.http, queries, region)
            engine = " + ".join(used) or FREE_ENGINES[0][0]
        else:
            for res in await asyncio.gather(*(call(ctx.http, q, gl) for q in queries), return_exceptions=True):
                if isinstance(res, RateLimited):
                    limited = str(res)
                elif isinstance(res, list):
                    results += res

        hits, seen = [], set()
        for title, url, snippet in results:
            prof = profile_of(url)
            key = (prof[2] if prof else url).lower()
            if key in seen:
                continue
            m = name_match(title, full, variants) or (None if prof else name_match(snippet, full, variants))
            if not m:
                continue
            seen.add(key)
            hits.append({"kind": m[0], "variant": m[1], "title": title, "url": prof[2] if prof else url,
                         "snippet": snippet[:240], "platform": prof[0] if prof else None,
                         "user": prof[1] if prof else None})
        hits.sort(key=lambda h: (h["kind"] != "exacta", h["platform"] is None))

        added = 0
        for h in hits:
            if h["kind"] == "exacta" and h["platform"] and added < 12:
                ctx.add("account", h["url"], {
                    "Plataforma": h["platform"], "Usuario": h["user"], "Título": h["title"],
                    "Descripción": h["snippet"] or None, "_links": [["Abrir perfil", h["url"]]],
                    "Verificación": "Búsqueda web: perfil con el nombre completo",
                }, rel="posible perfil (nombre completo)", pivot=False)
                added += 1

        ent = db.update_attrs(ctx.case_id, ctx.entity["id"], {"_web": hits[:60], "_web_engine": engine}, replace=True)
        if ent:
            ctx.job.emit({"type": "entity", "entity": ent, "created": False})
            ctx.enriched = True
        exact = sum(h["kind"] == "exacta" for h in hits)
        ctx.found = len(hits)
        parts = [f"{exact} con el nombre completo", f"{len(hits) - exact} parciales"]
        if limited:
            parts.append(f"{limited}: añade una clave gratuita de Serper o Brave en Ajustes, o usa los dorks")
        ctx.message = f"{engine}: " + ", ".join(parts)
        if not hits and limited and not results:
            raise RuntimeError(parts[-1])
