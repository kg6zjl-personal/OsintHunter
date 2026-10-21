import asyncio
import html as htmllib
import re
from urllib.parse import urljoin, urlparse

import dns.exception
import dns.resolver
import dns.reversename

EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,24}")
URL_RE = re.compile(r"https?://[^\s\"'<>()\[\]{}]+", re.I)
_IGNORED_EMAIL_SUFFIX = (".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg", ".css", ".js")

SOCIAL_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("X/Twitter", re.compile(r"^https?://(?:www\.|mobile\.)?(?:twitter|x)\.com/(?!share|intent|home|search|hashtag|i/|privacy|tos)([A-Za-z0-9_]{1,15})/?$", re.I)),
    ("Instagram", re.compile(r"^https?://(?:www\.)?instagram\.com/(?!p/|reel/|explore/|accounts/)([A-Za-z0-9_.]{1,30})/?$", re.I)),
    ("Facebook", re.compile(r"^https?://(?:www\.|m\.|es-la\.)?facebook\.com/(?!sharer|share|dialog|plugins|tr\b|groups/|events/|pages/)([A-Za-z0-9.\-]{2,50})/?$", re.I)),
    ("LinkedIn", re.compile(r"^https?://(?:[a-z]{2,3}\.)?linkedin\.com/(?:in|company)/([A-Za-z0-9\-_%]{2,100})/?$", re.I)),
    ("GitHub", re.compile(r"^https?://(?:www\.)?github\.com/(?!sponsors|orgs|features|about|login|topics|marketplace)([A-Za-z0-9\-]{1,39})/?$", re.I)),
    ("YouTube", re.compile(r"^https?://(?:www\.)?youtube\.com/@([A-Za-z0-9_\-.]{2,100})/?$", re.I)),
    ("TikTok", re.compile(r"^https?://(?:www\.)?tiktok\.com/@([A-Za-z0-9_.]{2,24})/?$", re.I)),
    ("Telegram", re.compile(r"^https?://(?:t\.me|telegram\.me)/(?!share|joinchat|s/|\+)([A-Za-z0-9_]{5,32})/?$", re.I)),
    ("Twitch", re.compile(r"^https?://(?:www\.)?twitch\.tv/([A-Za-z0-9_]{3,25})/?$", re.I)),
    ("Reddit", re.compile(r"^https?://(?:www\.|old\.)?reddit\.com/(?:u|user)/([A-Za-z0-9_\-]{3,20})/?$", re.I)),
    ("Bluesky", re.compile(r"^https?://bsky\.app/profile/([A-Za-z0-9.\-]{3,100})/?$", re.I)),
    ("Threads", re.compile(r"^https?://(?:www\.)?threads\.net/@([A-Za-z0-9_.]{1,30})/?$", re.I)),
]


def social_from_url(url: str) -> tuple[str, str] | None:
    u = url.split("?")[0].split("#")[0]
    for platform, rx in SOCIAL_PATTERNS:
        m = rx.match(u)
        if m:
            return platform, m.group(1)
    return None


def clean_emails(text: str) -> list[str]:
    out = []
    for e in EMAIL_RE.findall(text or ""):
        e = e.strip(".").lower()
        if e.endswith(_IGNORED_EMAIL_SUFFIX) or "example." in e or e in out:
            continue
        out.append(e)
    return out


def _meta(html: str, name: str) -> str | None:
    m = re.search(
        rf'<meta[^>]+(?:name|property)=["\']{re.escape(name)}["\'][^>]*content=["\']([^"\']*)["\']', html, re.I
    ) or re.search(rf'<meta[^>]+content=["\']([^"\']*)["\'][^>]*(?:name|property)=["\']{re.escape(name)}["\']', html, re.I)
    return htmllib.unescape(m.group(1)).strip() if m else None


def parse_page(html: str, base_url: str) -> dict:
    """Extrae título, metadatos, emails, redes sociales y enlaces externos de un HTML."""
    title = re.search(r"<title[^>]*>(.*?)</title>", html, re.I | re.S)
    hrefs = re.findall(r'href=["\']([^"\']+)["\']', html, re.I)
    links = []
    for h in hrefs:
        h = htmllib.unescape(h)
        if h.startswith("mailto:"):
            continue
        full = urljoin(base_url, h)
        if full.startswith("http") and full not in links:
            links.append(full)
    mailtos = [htmllib.unescape(m).split("?")[0] for m in re.findall(r'mailto:([^"\'>\s]+)', html, re.I)]
    socials = []
    for l in links:
        s = social_from_url(l)
        if s and (s[0], s[1].lower()) not in {(p, u.lower()) for p, u, _ in socials}:
            socials.append((s[0], s[1], l))
    base_host = urlparse(base_url).hostname or ""
    from .modules.chile import find_ruts

    text = htmllib.unescape(re.sub(r"<script.*?</script>|<style.*?</style>", " ", html, flags=re.S | re.I))
    text = re.sub(r"<[^>]+>", " ", text)
    return {
        "ruts": find_ruts(text, limit=20),
        "title": htmllib.unescape(" ".join(title.group(1).split()))[:200] if title else None,
        "description": _meta(html, "description") or _meta(html, "og:description"),
        "generator": _meta(html, "generator"),
        "emails": clean_emails(" ".join(mailtos) + " " + re.sub(r"<[^>]+>", " ", html)),
        "socials": socials,
        "external_links": [l for l in links if (urlparse(l).hostname or "") != base_host][:200],
    }


def tech_from_response(headers, html: str) -> list[str]:
    tech = []
    for h in ("server", "x-powered-by", "x-generator", "x-aspnet-version"):
        if headers.get(h):
            tech.append(f"{h}: {headers[h]}")
    lower = html.lower()
    hints = {
        "WordPress": "wp-content/",
        "Shopify": "cdn.shopify.com",
        "Wix": "wix.com",
        "Squarespace": "squarespace",
        "Drupal": "drupal-settings-json",
        "Joomla": "/media/jui/",
        "Next.js": "__next_data__",
        "React": "data-reactroot",
        "Google Analytics": "google-analytics.com",
        "Google Tag Manager": "googletagmanager.com",
        "Cloudflare": "cdn-cgi/",
    }
    tech += [name for name, needle in hints.items() if needle in lower]
    if "cf-ray" in headers:
        tech.append("Cloudflare")
    return list(dict.fromkeys(tech))


def find_analytics_ids(html: str) -> list[str]:
    """IDs de Google Analytics/AdSense/GTM: sirven para encontrar webs del mismo dueño."""
    ids = set(re.findall(r"\b(UA-\d{4,10}-\d{1,4}|G-[A-Z0-9]{6,12}|GTM-[A-Z0-9]{4,9}|ca-pub-\d{10,20}|pub-\d{10,20})\b", html))
    return sorted(ids)


_resolver = dns.resolver.Resolver(configure=True)
if not _resolver.nameservers:
    _resolver.nameservers = ["1.1.1.1", "8.8.8.8"]
_resolver.lifetime = 8.0


def _resolve(name: str, rtype: str) -> list[str]:
    try:
        return [r.to_text().strip('"') for r in _resolver.resolve(name, rtype)]
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers, dns.exception.Timeout,
            dns.name.EmptyLabel, dns.name.LabelTooLong):
        return []


async def resolve(name: str, rtype: str) -> list[str]:
    return await asyncio.to_thread(_resolve, name, rtype)


async def reverse_dns(ip: str) -> list[str]:
    try:
        name = dns.reversename.from_address(ip).to_text()
    except (dns.exception.SyntaxError, ValueError):
        return []
    return [h.rstrip(".") for h in await resolve(name, "PTR")]


FREE_EMAIL_PROVIDERS = {
    "gmail.com", "googlemail.com", "outlook.com", "outlook.es", "hotmail.com", "hotmail.es", "hotmail.com.ar",
    "live.com", "live.com.ar", "msn.com", "yahoo.com", "yahoo.es", "yahoo.com.ar", "yahoo.com.mx", "ymail.com",
    "icloud.com", "me.com", "mac.com", "aol.com", "proton.me", "protonmail.com", "pm.me", "gmx.com", "gmx.net",
    "gmx.es", "mail.com", "yandex.com", "yandex.ru", "zoho.com", "tutanota.com", "tuta.io", "mail.ru", "qq.com",
    "163.com", "126.com", "fastmail.com", "hey.com", "terra.com.br", "uol.com.br", "bol.com.br", "inbox.ru",
}
