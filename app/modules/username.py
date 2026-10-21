import asyncio
import html
import json
import random
import re
import string
import time
import unicodedata
import xml.etree.ElementTree as ET
from collections import Counter

import httpx

from ..config import DATA_DIR, RESOURCES_DIR, settings
from ..db import db
from ..util import URL_RE, clean_emails, social_from_url
from .base import Module, Skip, register

# ---------------------------------------------------------------------------
# Perfiles enriquecidos: plataformas con API pública de las que sacamos datos
# ---------------------------------------------------------------------------

PROFILE_URLS = {
    "X/Twitter": "https://x.com/{}",
    "GitHub": "https://github.com/{}",
    "Reddit": "https://www.reddit.com/user/{}",
    "Instagram": "https://www.instagram.com/{}",
    "Facebook": "https://www.facebook.com/{}",
    "LinkedIn": "https://www.linkedin.com/in/{}",
    "YouTube": "https://www.youtube.com/@{}",
    "TikTok": "https://www.tiktok.com/@{}",
    "Telegram": "https://t.me/{}",
    "Twitch": "https://www.twitch.tv/{}",
    "Bluesky": "https://bsky.app/profile/{}",
    "Hacker News": "https://news.ycombinator.com/user?id={}",
    "Mastodon": "{}",
    "Threads": "https://www.threads.net/@{}",
}


class Blocked(Exception):
    """La plataforma ha limitado o bloqueado la consulta: no sabemos si la cuenta existe."""


def _txt(html: str | None) -> str:
    return re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", html or "")).strip()


def _date(ts) -> str | None:
    if ts in (None, ""):
        return None
    if isinstance(ts, (int, float)):
        if ts > 1e11:
            ts /= 1000
        return time.strftime("%Y-%m-%d", time.gmtime(ts))
    return str(ts)[:10]


async def p_github(ctx, u):
    h = {"Accept": "application/vnd.github+json"}
    if ctx.key("github"):
        h["Authorization"] = f"Bearer {ctx.key('github')}"
    st, d = await ctx.get_json(f"https://api.github.com/users/{u}", headers=h)
    if st != 200 or not isinstance(d, dict):
        return None
    login = d["login"]
    emails: list[str] = [d.get("email") or ""]
    names: list[str] = []
    own_names = {login.lower(), (d.get("name") or "").strip().lower()} - {""}
    # emails de commits públicos: primero eventos, después commits de sus repos.
    # Un push puede incluir commits de otras personas: sólo cuentan los del propio usuario.
    st, ev = await ctx.get_json(f"https://api.github.com/users/{login}/events/public?per_page=100", headers=h)
    if st == 200 and isinstance(ev, list):
        for e in ev:
            for c in (e.get("payload") or {}).get("commits") or []:
                a = c.get("author") or {}
                em, nm = (a.get("email") or "").lower(), (a.get("name") or "").strip()
                if nm.lower() in own_names or login.lower() in em.split("@")[0]:
                    emails.append(em)
                    names.append(nm)
    if not [e for e in emails if e and "noreply" not in e]:
        st, repos = await ctx.get_json(
            f"https://api.github.com/users/{login}/repos?sort=pushed&per_page=10&type=owner", headers=h
        )
        if st == 200 and isinstance(repos, list):
            own = [r for r in repos if not r.get("fork")][:3]
            for r in own:
                st, commits = await ctx.get_json(
                    f"https://api.github.com/repos/{login}/{r['name']}/commits?author={login}&per_page=5", headers=h
                )
                if st == 200 and isinstance(commits, list):
                    for c in commits:
                        a = (c.get("commit") or {}).get("author") or {}
                        emails.append(a.get("email") or "")
                        names.append(a.get("name") or "")
    emails = [e.lower() for e in emails if e and "noreply" not in e.lower() and "@" in e]
    return {
        "platform": "GitHub",
        "user": login,
        "url": d["html_url"],
        "attrs": {
            "Nombre": d.get("name"),
            "Bio": d.get("bio"),
            "Empresa": d.get("company"),
            "Web": d.get("blog"),
            "Repos públicos": d.get("public_repos"),
            "Seguidores": d.get("followers"),
            "Creada": _date(d.get("created_at")),
            "Nombres en commits": sorted({n for n in names if n}) or None,
            "_avatar": d.get("avatar_url"),
        },
        "name": d.get("name"),
        "location": d.get("location"),
        "emails": emails,
        "urls": [d.get("blog")],
        "linked": [("X/Twitter", d.get("twitter_username"))],
    }


async def p_gitlab(ctx, u):
    st, d = await ctx.get_json(f"https://gitlab.com/api/v4/users?username={u}")
    if st != 200 or not d:
        return None
    base = d[0]
    st, full = await ctx.get_json(f"https://gitlab.com/api/v4/users/{base['id']}")
    full = full if st == 200 and isinstance(full, dict) else base
    return {
        "platform": "GitLab",
        "user": base["username"],
        "url": base["web_url"],
        "attrs": {
            "Nombre": full.get("name"),
            "Bio": full.get("bio"),
            "Organización": full.get("organization"),
            "Puesto": full.get("job_title"),
            "Creada": _date(full.get("created_at")),
            "_avatar": full.get("avatar_url"),
        },
        "name": full.get("name"),
        "location": full.get("location"),
        "emails": [full.get("public_email")],
        "urls": [full.get("website_url")],
        "linked": [("X/Twitter", full.get("twitter")), ("LinkedIn", full.get("linkedin"))],
    }


async def p_keybase(ctx, u):
    st, d = await ctx.get_json(
        f"https://keybase.io/_/api/1.0/user/lookup.json?usernames={u}&fields=basics,profile,proofs_summary,pictures"
    )
    them = (d or {}).get("them") if isinstance(d, dict) else None
    if st != 200 or not them or not them[0]:
        return None
    t = them[0]
    prof = t.get("profile") or {}
    linked, urls = [], []
    for p in (t.get("proofs_summary") or {}).get("all") or []:
        kind, tag, surl = p.get("proof_type"), p.get("nametag"), p.get("service_url")
        mapping = {"twitter": "X/Twitter", "github": "GitHub", "reddit": "Reddit", "hackernews": "Hacker News",
                   "facebook": "Facebook", "mastodon": "Mastodon"}
        if kind in mapping:
            linked.append((mapping[kind], tag))
        elif kind in ("dns", "generic_web_site", "https", "http"):
            urls.append(surl or f"https://{tag}")
    pic = ((t.get("pictures") or {}).get("primary") or {}).get("url")
    return {
        "platform": "Keybase",
        "user": t["basics"]["username"],
        "url": f"https://keybase.io/{t['basics']['username']}",
        "attrs": {"Nombre": prof.get("full_name"), "Bio": prof.get("bio"), "_avatar": pic},
        "name": prof.get("full_name"),
        "location": prof.get("location"),
        "urls": urls,
        "linked": linked,
    }


async def p_hackernews(ctx, u):
    st, d = await ctx.get_json(f"https://hacker-news.firebaseio.com/v0/user/{u}.json")
    if st != 200 or not isinstance(d, dict):
        return None
    about = _txt(d.get("about"))
    return {
        "platform": "Hacker News",
        "user": d["id"],
        "url": f"https://news.ycombinator.com/user?id={d['id']}",
        "attrs": {"Bio": about, "Karma": d.get("karma"), "Creada": _date(d.get("created"))},
        "bio": about,
    }


async def p_bluesky(ctx, u):
    actor = u if "." in u else f"{u}.bsky.social"
    st, d = await ctx.get_json(f"https://public.api.bsky.app/xrpc/app.bsky.actor.getProfile?actor={actor}")
    if st != 200 or not isinstance(d, dict) or not d.get("handle"):
        return None
    return {
        "platform": "Bluesky",
        "user": d["handle"],
        "url": f"https://bsky.app/profile/{d['handle']}",
        "attrs": {
            "Nombre": d.get("displayName"),
            "Bio": d.get("description"),
            "Seguidores": d.get("followersCount"),
            "Publicaciones": d.get("postsCount"),
            "Creada": _date(d.get("createdAt")),
            "DID": d.get("did"),
            "_avatar": d.get("avatar"),
        },
        "name": d.get("displayName"),
        "bio": d.get("description"),
    }


async def p_mastodon(ctx, u):
    st, d = await ctx.get_json(f"https://mastodon.social/api/v1/accounts/lookup?acct={u}")
    if st != 200 or not isinstance(d, dict) or not d.get("url"):
        return None
    fields = {f["name"]: _txt(f.get("value")) for f in d.get("fields") or []}
    note = _txt(d.get("note"))
    return {
        "platform": "Mastodon",
        "user": d.get("acct"),
        "url": d["url"],
        "attrs": {
            "Nombre": d.get("display_name"),
            "Bio": note,
            "Seguidores": d.get("followers_count"),
            "Creada": _date(d.get("created_at")),
            "Campos": fields or None,
            "_avatar": d.get("avatar"),
        },
        "name": d.get("display_name"),
        "bio": note + " " + " ".join(fields.values()),
    }


async def p_telegram(ctx, u):
    if not re.match(r"^[A-Za-z][A-Za-z0-9_]{4,31}$", u):
        return None
    r = await ctx.http.get(f"https://t.me/{u}")
    html = r.text
    if r.status_code != 200 or "tgme_page_title" not in html:
        return None
    title = re.search(r'<div class="tgme_page_title"[^>]*>\s*<span[^>]*>(.*?)</span>', html, re.S)
    desc = re.search(r'<div class="tgme_page_description[^"]*"[^>]*>(.*?)</div>', html, re.S)
    extra = re.search(r'<div class="tgme_page_extra">(.*?)</div>', html, re.S)
    photo = re.search(r'<img class="tgme_page_photo_image" src="([^"]+)"', html)
    bio = _txt(desc.group(1)) if desc else ""
    attrs = {
        "Nombre": _txt(title.group(1)) if title else None,
        "Bio": bio,
        "Info": _txt(extra.group(1)) if extra else None,
        "_avatar": photo.group(1) if photo else None,
    }
    # Los canales públicos tienen vista previa con las últimas publicaciones.
    posts_text = ""
    r2 = await ctx.http.get(f"https://t.me/s/{u}")
    if r2.status_code == 200 and "tgme_widget_message" in r2.text:
        page = r2.text
        counters = dict((t, v) for v, t in re.findall(
            r'<span class="counter_value">([^<]+)</span>\s*<span class="counter_type">([^<]+)</span>', page))
        posts = [_txt(p) for p in re.findall(r'<div class="tgme_widget_message_text[^"]*"[^>]*>(.*?)</div>', page, re.S)]
        dates = re.findall(r'<time datetime="([^"]+)"', page)
        attrs.update({
            "Tipo": "Canal público",
            "Suscriptores": counters.get("subscribers") or counters.get("members"),
            "Última publicación": dates[-1][:10] if dates else None,
            "Publicaciones recientes": [p[:280] for p in posts[-5:]][::-1] or None,
        })
        posts_text = " ".join(posts[-20:])
    return {
        "platform": "Telegram",
        "user": u,
        "url": f"https://t.me/{u}",
        "attrs": attrs,
        "name": attrs["Nombre"],
        "bio": bio,
        "emails": clean_emails(posts_text),
    }


async def p_twitter(ctx, u):
    if not re.match(r"^[A-Za-z0-9_]{1,15}$", u):
        return None
    st, d = await ctx.get_json(f"https://api.fxtwitter.com/{u}")
    user = (d or {}).get("user") if isinstance(d, dict) else None
    if st != 200 or not user:
        return None
    joined = None
    try:
        joined = time.strftime("%Y-%m-%d", time.strptime(user.get("joined") or "", "%a %b %d %H:%M:%S %z %Y"))
    except ValueError:
        pass
    site = user.get("website")
    site = site.get("url") if isinstance(site, dict) else site
    return {
        "platform": "X/Twitter",
        "user": user.get("screen_name") or u,
        "url": user.get("url") or f"https://x.com/{u}",
        "attrs": {
            "Nombre": user.get("name"),
            "Bio": user.get("description"),
            "Seguidores": user.get("followers"),
            "Siguiendo": user.get("following"),
            "Publicaciones": user.get("tweets"),
            "Creada": joined,
            "Verificada": "Sí" if (user.get("verification") or {}).get("verified") else None,
            "Protegida": "Sí" if user.get("protected") else None,
            "_avatar": (user.get("avatar_url") or "").replace("_normal.", "_400x400.") or None,
        },
        "name": user.get("name"),
        "location": (user.get("location") or "").strip() or None,
        "urls": [site],
        "bio": user.get("description"),
    }


def _sleep_window(hours: Counter) -> str | None:
    """Estima la zona horaria buscando las 6 horas seguidas con menos actividad (se asume que duerme de 1 a 7)."""
    total = sum(hours.values())
    if total < 30:
        return None
    start = min(range(24), key=lambda s: sum(hours[(s + i) % 24] for i in range(6)))
    offset = (1 - start + 12) % 24 - 12
    return f"UTC{offset:+d} aprox. (inactivo entre las {start:02d}h y {(start + 6) % 24:02d}h UTC, {total} comentarios)"


async def p_reddit(ctx, u):
    if not re.match(r"^[A-Za-z0-9_\-]{3,20}$", u):
        return None
    base = "https://arctic-shift.photon-reddit.com/api"
    st, d = await ctx.get_json(f"{base}/users/search", params={"author": u, "limit": 1})
    rows = (d or {}).get("data") if isinstance(d, dict) else None
    if st != 200 or not rows or (rows[0].get("author") or "").lower() != u.lower():
        return None
    name = rows[0]["author"]
    meta = rows[0].get("_meta") or {}
    first = [x for x in (meta.get("earliest_comment_at"), meta.get("earliest_post_at")) if x]
    last = [x for x in (meta.get("last_comment_at"), meta.get("last_post_at")) if x]
    attrs = {
        "Karma": meta.get("total_karma"),
        "Comentarios": meta.get("num_comments"),
        "Publicaciones": meta.get("num_posts"),
        "Primera actividad": _date(min(first)) if first else None,
        "Última actividad": _date(max(last)) if last else None,
    }
    emails: list[str] = []
    st, c = await ctx.get_json(f"{base}/comments/search",
                               params={"author": name, "limit": 100, "fields": "subreddit,created_utc,body"})
    comments = (c or {}).get("data") if isinstance(c, dict) else None
    if st == 200 and comments:
        subs = Counter(x.get("subreddit") for x in comments if x.get("subreddit"))
        hours = Counter(time.gmtime(x["created_utc"]).tm_hour for x in comments if x.get("created_utc"))
        attrs["Subreddits frecuentes"] = [f"r/{s} ({n})" for s, n in subs.most_common(10)]
        attrs["Horas más activas (UTC)"] = [f"{h:02d}h" for h, _ in hours.most_common(3)]
        attrs["Zona horaria estimada"] = _sleep_window(hours)
        emails = clean_emails(" ".join(x.get("body") or "" for x in comments))
    return {
        "platform": "Reddit",
        "user": name,
        "url": f"https://www.reddit.com/user/{name}",
        "attrs": attrs,
        "emails": emails,
    }


async def p_youtube(ctx, u):
    if not re.match(r"^[A-Za-z0-9_.\-]{3,30}$", u):
        return None
    r = await ctx.http.get(f"https://www.youtube.com/@{u}", headers={"Cookie": "CONSENT=YES+1; SOCS=CAI"})
    marker = '"channelMetadataRenderer":'
    i = r.text.find(marker)
    if r.status_code != 200 or i < 0:
        return None
    try:
        meta, _ = json.JSONDecoder().raw_decode(r.text, i + len(marker))
    except ValueError:
        return None
    subs = re.search(r'"content":"([^"]{1,30}(?:suscriptores|subscribers))"', r.text)
    thumbs = (meta.get("avatar") or {}).get("thumbnails") or []
    return {
        "platform": "YouTube",
        "user": u,
        "url": meta.get("vanityChannelUrl") or f"https://www.youtube.com/@{u}",
        "attrs": {
            "Nombre": meta.get("title"),
            "Bio": meta.get("description"),
            "ID del canal": meta.get("externalId"),
            "Suscriptores": subs.group(1) if subs else None,
            "_avatar": thumbs[-1]["url"] if thumbs else None,
        },
        "bio": meta.get("description"),
    }


async def p_twitch(ctx, u):
    if not re.match(r"^[A-Za-z0-9_]{3,25}$", u):
        return None
    q = ("query($l:String!){user(login:$l){login displayName description createdAt profileImageURL(width:300) "
         "followers{totalCount} lastBroadcast{startedAt title}}}")
    r = await ctx.http.post("https://gql.twitch.tv/gql", headers={"Client-Id": "kimne78kx3ncx6brgo4mv6wki5h1ko"},
                            json={"query": q, "variables": {"l": u.lower()}})
    user = ((r.json() if r.status_code == 200 else {}).get("data") or {}).get("user")
    if not user:
        return None
    lb = user.get("lastBroadcast") or {}
    return {
        "platform": "Twitch",
        "user": user["login"],
        "url": f"https://www.twitch.tv/{user['login']}",
        "attrs": {
            "Nombre visible": user.get("displayName"),
            "Bio": user.get("description"),
            "Seguidores": (user.get("followers") or {}).get("totalCount"),
            "Creada": _date(user.get("createdAt")),
            "Última emisión": _date(lb.get("startedAt")),
            "Título última emisión": lb.get("title"),
            "_avatar": user.get("profileImageURL"),
        },
        "bio": user.get("description"),
    }


IG_META = re.compile(r'<meta property="og:(title|description|image)" content="([^"]*)"')
IG_COUNTS = re.compile(r"^([\d.,]+[KMB]?) Followers, ([\d.,]+[KMB]?) Following, ([\d.,]+[KMB]?) Posts")


async def _instagram_preview(ctx, u):
    """La API limita por IP muy rápido; la vista previa para enlaces (la que leen Facebook o WhatsApp) sigue respondiendo."""
    r = await ctx.http.get(f"https://www.instagram.com/{u}/", headers={"User-Agent": "facebookexternalhit/1.1"})
    page = re.search(r'"pageID":"(\w+)"', r.text) if r.status_code == 200 else None
    if page and page.group(1) == "httpErrorPage":
        return None
    meta = {k: html.unescape(v) for k, v in IG_META.findall(r.text)}
    if not page or page.group(1) != "profilePage" or "title" not in meta:
        raise Blocked("Instagram")
    m = re.match(r"^(.*?)\s*\(@([A-Za-z0-9_.]+)\)", meta["title"])
    name, user = (m.group(1).strip(), m.group(2)) if m else (None, u)
    counts = IG_COUNTS.match(meta.get("description", ""))
    pid = re.search(r'"profile_id":"(\d+)"', r.text)
    return {
        "platform": "Instagram",
        "user": user,
        "url": f"https://www.instagram.com/{user}",
        "attrs": {
            "Nombre": name if name and name != user else None,
            "Seguidores": counts and counts.group(1),
            "Siguiendo": counts and counts.group(2),
            "Publicaciones": counts and counts.group(3),
            "ID de Instagram": pid and pid.group(1),
            "Nota": "Datos de la vista previa pública (Instagram limitó su API): sin bio ni enlaces",
            "_avatar": meta.get("image"),
        },
        "name": name,
    }


_PACE: dict[str, list] = {}


async def _paced(platform: str, gap: float) -> None:
    """Espacia las consultas a redes que limitan por IP en cuanto reciben varias seguidas."""
    slot = _PACE.setdefault(platform, [asyncio.Lock(), 0.0])
    async with slot[0]:
        wait = slot[1] + gap - time.monotonic()
        if wait > 0:
            await asyncio.sleep(wait)
        slot[1] = time.monotonic()


async def p_instagram(ctx, u):
    if not re.match(r"^[A-Za-z0-9_.]{1,30}$", u):
        return None
    await _paced("Instagram", 1.5)
    r = await ctx.http.get(f"https://i.instagram.com/api/v1/users/web_profile_info/?username={u}",
                           headers={"x-ig-app-id": "936619743392459"})
    if r.status_code == 404:
        return None
    if r.status_code != 200:
        return await _instagram_preview(ctx, u)
    user = ((r.json() or {}).get("data") or {}).get("user")
    if not user:
        return None
    links = [l.get("url") for l in user.get("bio_links") or [] if l.get("url")] + [user.get("external_url")]
    return {
        "platform": "Instagram",
        "user": user.get("username") or u,
        "url": f"https://www.instagram.com/{user.get('username') or u}",
        "attrs": {
            "Nombre": user.get("full_name"),
            "Bio": user.get("biography"),
            "Seguidores": (user.get("edge_followed_by") or {}).get("count"),
            "Siguiendo": (user.get("edge_follow") or {}).get("count"),
            "Publicaciones": (user.get("edge_owner_to_timeline_media") or {}).get("count"),
            "Privada": "Sí" if user.get("is_private") else None,
            "Verificada": "Sí" if user.get("is_verified") else None,
            "Categoría": user.get("category_name"),
            "Teléfono de empresa": user.get("business_phone_number"),
            "_avatar": user.get("profile_pic_url_hd") or user.get("profile_pic_url"),
        },
        "name": user.get("full_name"),
        "emails": [user.get("business_email")],
        "urls": links,
        "bio": user.get("biography"),
    }


MOBILE_UA = ("Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 "
             "(KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1")


async def _tiktok_oembed(ctx, u):
    """Respaldo: el servicio de incrustación sólo dice si el perfil existe y su nombre visible."""
    r = await ctx.http.get("https://www.tiktok.com/oembed", params={"url": f"https://www.tiktok.com/@{u}"})
    if r.status_code == 400:
        return None
    try:
        d = r.json() if r.status_code == 200 else None
    except ValueError:
        d = None
    if not isinstance(d, dict) or not d.get("author_url"):
        raise Blocked("TikTok")
    user = d["author_url"].rstrip("/").rsplit("@", 1)[-1] or u
    return {
        "platform": "TikTok",
        "user": user,
        "url": f"https://www.tiktok.com/@{user}",
        "attrs": {"Nombre": d.get("author_name"), "Nota": "Datos mínimos (TikTok no dejó ver el perfil completo)"},
        "name": d.get("author_name"),
    }


async def p_tiktok(ctx, u):
    if not re.match(r"^[A-Za-z0-9_.]{2,24}$", u):
        return None
    await _paced("TikTok", 1.0)
    # a un navegador de escritorio le sale el muro anti-bots; la versión móvil trae los datos del perfil
    r = await ctx.http.get(f"https://www.tiktok.com/@{u}", headers={"User-Agent": MOBILE_UA})
    m = re.search(r'<script id="__UNIVERSAL_DATA_FOR_REHYDRATION__"[^>]*>(.*?)</script>', r.text, re.S)
    detail = None
    if m:
        try:
            detail = json.loads(m.group(1))["__DEFAULT_SCOPE__"]["webapp.user-detail"]
        except (ValueError, KeyError):
            detail = None
    if detail is None:
        return await _tiktok_oembed(ctx, u)
    if detail.get("statusCode") != 0:
        return None
    user = (detail.get("userInfo") or {}).get("user") or {}
    stats = (detail.get("userInfo") or {}).get("stats") or {}
    return {
        "platform": "TikTok",
        "user": user.get("uniqueId") or u,
        "url": f"https://www.tiktok.com/@{user.get('uniqueId') or u}",
        "attrs": {
            "Nombre": user.get("nickname"),
            "Bio": user.get("signature"),
            "Seguidores": stats.get("followerCount"),
            "Siguiendo": stats.get("followingCount"),
            "Me gusta": stats.get("heartCount"),
            "Vídeos": stats.get("videoCount"),
            "Creada": _date(user.get("createTime")),
            "Región": user.get("region"),
            "Verificada": "Sí" if user.get("verified") else None,
            "Privada": "Sí" if user.get("privateAccount") else None,
            "_avatar": user.get("avatarLarger"),
        },
        "name": user.get("nickname"),
        "bio": user.get("signature"),
    }


async def p_chesscom(ctx, u):
    st, d = await ctx.get_json(f"https://api.chess.com/pub/player/{u.lower()}")
    if st != 200 or not isinstance(d, dict) or not d.get("username"):
        return None
    return {
        "platform": "Chess.com",
        "user": d["username"],
        "url": d.get("url") or f"https://www.chess.com/member/{d['username']}",
        "attrs": {
            "Nombre": d.get("name"),
            "País": (d.get("country") or "").rsplit("/", 1)[-1] or None,
            "Seguidores": d.get("followers"),
            "Creada": _date(d.get("joined")),
            "Última conexión": _date(d.get("last_online")),
            "_avatar": d.get("avatar"),
        },
        "name": d.get("name"),
        "location": d.get("location"),
    }


async def p_lichess(ctx, u):
    st, d = await ctx.get_json(f"https://lichess.org/api/user/{u}")
    if st != 200 or not isinstance(d, dict) or not d.get("username") or d.get("disabled"):
        return None
    prof = d.get("profile") or {}
    name = prof.get("realName") or " ".join(x for x in (prof.get("firstName"), prof.get("lastName")) if x) or None
    return {
        "platform": "Lichess",
        "user": d["username"],
        "url": d.get("url") or f"https://lichess.org/@/{d['username']}",
        "attrs": {"Nombre": name, "Bio": prof.get("bio"), "País": prof.get("flag") or prof.get("country"),
                  "Creada": _date(d.get("createdAt")), "Última conexión": _date(d.get("seenAt"))},
        "name": name,
        "location": prof.get("location"),
        "bio": (prof.get("bio") or "") + " " + (prof.get("links") or ""),
    }


async def p_duolingo(ctx, u):
    st, d = await ctx.get_json(f"https://www.duolingo.com/2017-06-30/users?username={u}")
    users = (d or {}).get("users") if isinstance(d, dict) else None
    match = [x for x in users or [] if (x.get("username") or "").lower() == u.lower()]
    if st != 200 or not match:
        return None
    x = match[0]
    pic = x.get("picture")
    return {
        "platform": "Duolingo",
        "user": x["username"],
        "url": f"https://www.duolingo.com/profile/{x['username']}",
        "attrs": {
            "Nombre": x.get("name"),
            "Bio": x.get("bio"),
            "Racha": x.get("streak"),
            "XP total": x.get("totalXp"),
            "Idiomas": [c.get("title") for c in x.get("courses") or [] if c.get("title")] or None,
            "Creada": _date(x.get("creationDate")),
            "_avatar": f"https:{pic}/xlarge" if pic and pic.startswith("//") else None,
        },
        "name": x.get("name"),
    }


async def p_roblox(ctx, u):
    r = await ctx.http.post(
        "https://users.roblox.com/v1/usernames/users", json={"usernames": [u], "excludeBannedUsers": False}
    )
    data = (r.json() or {}).get("data") if r.status_code == 200 else None
    if not data:
        return None
    uid = data[0]["id"]
    st, full = await ctx.get_json(f"https://users.roblox.com/v1/users/{uid}")
    full = full if st == 200 and isinstance(full, dict) else {}
    return {
        "platform": "Roblox",
        "user": data[0]["name"],
        "url": f"https://www.roblox.com/users/{uid}/profile",
        "attrs": {"Nombre visible": data[0].get("displayName"), "Bio": full.get("description"),
                  "Creada": _date(full.get("created")), "Baneado": full.get("isBanned") or None, "ID": uid},
        "bio": full.get("description"),
    }


async def p_minecraft(ctx, u):
    st, d = await ctx.get_json(f"https://api.mojang.com/users/profiles/minecraft/{u}")
    if st != 200 or not isinstance(d, dict) or not d.get("id"):
        return None
    return {
        "platform": "Minecraft",
        "user": d["name"],
        "url": f"https://namemc.com/profile/{d['name']}",
        "attrs": {"UUID": d["id"], "_avatar": f"https://mc-heads.net/avatar/{d['id']}"},
    }


async def p_steam(ctx, u):
    r = await ctx.http.get(f"https://steamcommunity.com/id/{u}/?xml=1")
    if r.status_code != 200 or "<steamID64>" not in r.text:
        return None
    try:
        root = ET.fromstring(r.text)
    except ET.ParseError:
        return None
    g = lambda tag: (root.findtext(tag) or "").strip() or None  # noqa: E731
    return {
        "platform": "Steam",
        "user": u,
        "url": f"https://steamcommunity.com/id/{u}",
        "attrs": {
            "Nombre visible": g("steamID"),
            "Nombre real": g("realname"),
            "SteamID64": g("steamID64"),
            "Miembro desde": g("memberSince"),
            "Resumen": _txt(g("summary")),
            "_avatar": g("avatarFull"),
        },
        "name": g("realname"),
        "location": g("location"),
        "bio": _txt(g("summary")),
    }


async def p_devto(ctx, u):
    st, d = await ctx.get_json(f"https://dev.to/api/users/by_username?url={u}")
    if st != 200 or not isinstance(d, dict) or not d.get("username"):
        return None
    return {
        "platform": "Dev.to",
        "user": d["username"],
        "url": f"https://dev.to/{d['username']}",
        "attrs": {"Nombre": d.get("name"), "Bio": d.get("summary"), "Creada": d.get("joined_at"),
                  "_avatar": d.get("profile_image")},
        "name": d.get("name"),
        "location": d.get("location"),
        "urls": [d.get("website_url")],
        "linked": [("X/Twitter", d.get("twitter_username")), ("GitHub", d.get("github_username"))],
    }


async def p_dockerhub(ctx, u):
    st, d = await ctx.get_json(f"https://hub.docker.com/v2/users/{u}/")
    if st != 200 or not isinstance(d, dict) or not d.get("username"):
        return None
    return {
        "platform": "Docker Hub",
        "user": d["username"],
        "url": f"https://hub.docker.com/u/{d['username']}",
        "attrs": {"Nombre": d.get("full_name"), "Empresa": d.get("company"), "Creada": _date(d.get("date_joined")),
                  "_avatar": d.get("gravatar_url")},
        "name": d.get("full_name"),
        "location": d.get("location"),
        "urls": [d.get("profile_url")],
    }


async def p_lobsters(ctx, u):
    st, d = await ctx.get_json(f"https://lobste.rs/~{u}.json")
    if st != 200 or not isinstance(d, dict) or not d.get("username"):
        return None
    avatar = d.get("avatar_url")
    return {
        "platform": "Lobsters",
        "user": d["username"],
        "url": f"https://lobste.rs/~{d['username']}",
        "attrs": {"Bio": _txt(d.get("about")), "Karma": d.get("karma"), "Creada": _date(d.get("created_at")),
                  "Invitado por": d.get("invited_by_user"),
                  "_avatar": f"https://lobste.rs{avatar}" if avatar and avatar.startswith("/") else avatar},
        "bio": _txt(d.get("about")),
        "linked": [("GitHub", d.get("github_username")), ("X/Twitter", d.get("twitter_username"))],
    }


async def p_stackoverflow(ctx, u):
    st, d = await ctx.get_json(
        "https://api.stackexchange.com/2.3/users",
        params={"inname": u, "site": "stackoverflow", "pagesize": 30, "order": "desc", "sort": "reputation"},
    )
    if st != 200 or not isinstance(d, dict):
        return None
    exact = [x for x in d.get("items") or [] if (x.get("display_name") or "").lower() == u.lower()]
    if not exact:
        return None
    x = exact[0]
    return {
        "platform": "Stack Overflow",
        "user": x.get("display_name"),
        "url": x.get("link") or f"https://stackoverflow.com/users/{x['user_id']}",
        "attrs": {"Reputación": x.get("reputation"), "Creada": _date(x.get("creation_date")),
                  "Última conexión": _date(x.get("last_access_date")), "ID": x.get("user_id"),
                  "Otros con el mismo nombre": len(exact) - 1 or None, "_avatar": x.get("profile_image")},
        "location": x.get("location"),
        "urls": [x.get("website_url")],
    }


PROFILE_CHECKS = {
    "GitHub": p_github, "GitLab": p_gitlab, "Keybase": p_keybase,
    "Hacker News": p_hackernews, "Bluesky": p_bluesky, "Mastodon": p_mastodon, "Telegram": p_telegram,
    "Chess.com": p_chesscom, "Lichess": p_lichess, "Duolingo": p_duolingo, "Roblox": p_roblox,
    "Minecraft": p_minecraft, "Steam": p_steam, "Dev.to": p_devto, "Docker Hub": p_dockerhub,
    "X/Twitter": p_twitter, "Reddit": p_reddit, "YouTube": p_youtube, "Twitch": p_twitch,
    "Instagram": p_instagram, "TikTok": p_tiktok, "Lobsters": p_lobsters, "Stack Overflow": p_stackoverflow,
}
# nombres equivalentes en la base de Sherlock, para no repetirlos en el barrido
COVERED_BY_PROFILES = {n.lower() for n in PROFILE_CHECKS} | {
    "hackernews", "chess", "docker hub", "devto", "dev community", "mastodon.social", "mastodon (mastodon.social)",
    "steam community (user)", "steamid", "minecraft", "roblox", "lichess", "bluesky", "twitter", "x",
    "lobsters", "stackoverflow", "stack overflow",
}


def _norm_url(u: str | None) -> str | None:
    if not u or not isinstance(u, str):
        return None
    u = u.strip()
    if not u:
        return None
    if not u.startswith("http"):
        u = "https://" + u
    return u


def add_profile(ctx, res: dict, parent: str | None = None) -> str | None:
    attrs = {k: v for k, v in res.get("attrs", {}).items()}
    attrs.update({"Plataforma": res["platform"], "Usuario": res.get("user"), "_links": [["Abrir perfil", res["url"]]]})
    acc = ctx.add("account", res["url"], attrs, rel="cuenta", parent=parent, pivot=False)
    if not acc:
        return None
    if res.get("name") and len(res["name"]) > 2 and " " in res["name"].strip():
        ctx.add("person", res["name"], rel="nombre", parent=acc, pivot=False)
    if res.get("location"):
        ctx.add("location", res["location"], rel="ubicación declarada", parent=acc)
    text = " ".join(str(x) for x in (res.get("bio"), attrs.get("Bio")) if x)
    for e in list(res.get("emails") or []) + clean_emails(text):
        if e and "@" in e:
            ctx.add("email", e, rel="email", parent=acc)
    urls = [_norm_url(u) for u in (res.get("urls") or [])] + URL_RE.findall(text)
    linked = [(p, x) for p, x in res.get("linked") or [] if x]
    for u in dict.fromkeys(u for u in urls if u):
        s = social_from_url(u)
        if s:
            linked.append(s)
        else:
            ctx.add("url", u, {"_links": [["Abrir", u]]}, rel="web", parent=acc, pivot=False)
    current = (ctx.value or "").lower()
    for platform, user in linked:
        user = user.strip().lstrip("@")
        tpl = PROFILE_URLS.get(platform)
        if not tpl or platform == "Mastodon":
            continue
        url = tpl.format(user)
        other = ctx.add("account", url, {"Plataforma": platform, "Usuario": user, "_links": [["Abrir perfil", url]],
                                         "Verificación": f"Enlazada desde {res['platform']}"},
                        rel="enlaza a", parent=acc, pivot=False)
        if user.lower() != current and other:
            ctx.add("username", user, rel="usuario", parent=other)
    return acc


@register
class UsernameProfiles(Module):
    name = "username_profiles"
    title = "Perfiles con datos"
    description = "Busca el usuario en plataformas con API pública y extrae nombre, bio, ubicación, emails de commits y cuentas enlazadas."
    inputs = ("username",)
    optional_keys = ("github",)
    sources = tuple(PROFILE_CHECKS)
    timeout = 60

    async def run(self, ctx):
        u = ctx.value
        results = await asyncio.gather(*(f(ctx, u) for f in PROFILE_CHECKS.values()), return_exceptions=True)
        found, blocked = [], []
        for res in results:
            if isinstance(res, dict):
                add_profile(ctx, res)
                found.append(res["platform"])
            elif isinstance(res, Blocked):
                blocked.append(str(res))
        ctx.enrich({"_bloq_perfiles": blocked}, replace=True)
        msg = f"Encontrado en {len(found)} de {len(PROFILE_CHECKS)}: {', '.join(found)}" if found else "Sin perfiles"
        if blocked:
            msg += f" · no se pudo comprobar (limitado): {', '.join(blocked)}"
        ctx.message = msg


# ---------------------------------------------------------------------------
# Barrido masivo (formato de datos compatible con Sherlock)
# ---------------------------------------------------------------------------

SHERLOCK_URL = "https://raw.githubusercontent.com/sherlock-project/sherlock/master/sherlock_project/resources/data.json"
WAF_MARKERS = (
    ".loading-spinner{visibility:hidden}body.no-js .challenge-running{display:none}",
    '<span id="challenge-error-text">',
    "AwsWafIntegration.forceRefreshToken",
    "perimeterxIdentifiers",
    "_cf_chl_opt",
    "cf-browser-verification",
)
_sites_cache: tuple[float, dict] | None = None


async def load_sites(http: httpx.AsyncClient) -> dict:
    global _sites_cache
    if _sites_cache and time.time() - _sites_cache[0] < 3600:
        return _sites_cache[1]
    sites: dict = {}
    if settings.get("sherlock_db", True):
        cache = DATA_DIR / "sherlock.json"
        stale = not cache.exists() or time.time() - cache.stat().st_mtime > 7 * 86400
        if stale:
            try:
                r = await http.get(SHERLOCK_URL, timeout=30)
                if r.status_code == 200 and isinstance(r.json(), dict):
                    cache.write_text(r.text, encoding="utf-8")
            except (httpx.HTTPError, ValueError):
                pass
        if cache.exists():
            try:
                data = json.loads(cache.read_text(encoding="utf-8"))
                sites.update({k: v for k, v in data.items() if not k.startswith("$") and isinstance(v, dict) and "url" in v})
            except ValueError:
                pass
    sites.update(json.loads((RESOURCES_DIR / "sites.json").read_text(encoding="utf-8")))
    _sites_cache = (time.time(), sites)
    return sites


def _as_list(x):
    if x is None:
        return []
    return x if isinstance(x, list) else [x]


async def check_site(http: httpx.AsyncClient, site: dict, username: str, timeout: float) -> str:
    rx = site.get("regexCheck")
    if rx:
        try:
            if not re.search(rx, username):
                return "invalid"
        except re.error:
            pass
    probe = (site.get("urlProbe") or site["url"]).replace("{}", username)
    payload = site.get("request_payload")
    if payload is not None:
        payload = json.loads(json.dumps(payload).replace("{}", username))
    types = _as_list(site.get("errorType"))
    method = (site.get("request_method") or "GET").upper()
    try:
        r = await http.request(
            method, probe, json=payload, headers=site.get("headers") or None, timeout=timeout,
            follow_redirects="response_url" not in types,
        )
    except (httpx.HTTPError, ValueError):
        return "error"
    text = r.text if len(r.content) < 3_000_000 else r.text[:3_000_000]
    if r.status_code == 429 or any(m in text for m in WAF_MARKERS):
        return "blocked"
    for t in types:
        if t == "message":
            if any(m and m in text for m in _as_list(site.get("errorMsg"))):
                return "missing"
        elif t == "status_code":
            codes = _as_list(site.get("errorCode"))
            if r.status_code in codes or not 200 <= r.status_code < 300:
                return "missing"
        elif t == "response_url":
            if not 200 <= r.status_code < 300:
                return "missing"
    return "found"


def _random_username(site: dict) -> str | None:
    rx = site.get("regexCheck")
    for _ in range(5):
        cand = "zq" + "".join(random.choices(string.ascii_lowercase, k=10))
        try:
            if not rx or re.search(rx, cand):
                return cand
        except re.error:
            return cand
    return None


def sweep_targets(sites: dict) -> dict:
    nsfw = settings.get("include_nsfw", False)
    return {
        name: s for name, s in sites.items()
        if (nsfw or not s.get("isNSFW")) and name.lower() not in COVERED_BY_PROFILES
    }


async def sweep_sites(ctx, sites: dict, u: str, concurrency: int, timeout: float, pause: float = 0) -> dict:
    """Comprueba el usuario en cada sitio; lo que no se pudo comprobar queda en stats["pending"] (sitio → URL)."""
    sem = asyncio.Semaphore(concurrency)
    stats = {"found": 0, "blocked": 0, "error": 0, "false_positive": 0, "pending": {}}

    async def one(name, site):
        async with sem:
            if pause:
                await asyncio.sleep(pause)
            res = await check_site(ctx.http, site, u, timeout)
            url = site["url"].replace("{}", u)
            if res == "found":
                fake = _random_username(site)
                if fake and await check_site(ctx.http, site, fake, timeout) == "found":
                    stats["false_positive"] += 1
                    return
                stats["found"] += 1
                ctx.add(
                    "account", url,
                    {"Plataforma": name, "Usuario": u, "_links": [["Abrir perfil", url]],
                     "Verificación": "Existe (comprobado contra usuario inventado)"},
                    rel="cuenta", pivot=False,
                )
            elif res in ("blocked", "error"):
                stats[res] += 1
                stats["pending"][name] = url

    await asyncio.gather(*(one(n, s) for n, s in sites.items()))
    return stats


@register
class UsernameSweep(Module):
    name = "username_sweep"
    title = "Barrido de usuario (400+ sitios)"
    description = "Comprueba si el usuario existe en cientos de webs y descarta falsos positivos repitiendo la prueba con un usuario inventado."
    inputs = ("username",)
    sources = ("Base de sitios de Sherlock", "Lista propia")
    timeout = 300

    async def run(self, ctx):
        u = ctx.value
        if not re.match(r"^[\w.\-]{2,40}$", u, re.UNICODE):
            raise Skip("El usuario contiene caracteres que las webs no aceptan")
        selected = sweep_targets(await load_sites(ctx.http))
        stats = await sweep_sites(ctx, selected, u, 48, float(settings.get("username_timeout", 15)))
        ctx.enrich({"_bloq_sitios": stats["pending"]}, replace=True)
        ctx.message = (
            f"{stats['found']} perfiles en {len(selected)} sitios · {stats['false_positive']} falsos positivos descartados"
            f" · {stats['blocked']} bloqueados · {stats['error']} sin respuesta"
        )


@register
class RetryBlocked(Module):
    name = "retry_blocked"
    title = "Reintentar lo bloqueado"
    description = ("Vuelve a probar, más despacio y en varias rondas, las redes y sitios que limitaron o bloquearon la "
                   "búsqueda. Lo que siga bloqueado (protecciones anti-bots) queda en una lista para que lo abras tú.")
    inputs = ("username",)
    sources = ("Perfiles con datos", "Barrido de usuario (400+ sitios)")
    timeout = 300
    deep = True

    async def run(self, ctx):
        u = ctx.value
        a = ctx.entity.get("attrs") or {}
        before = set(ctx.job.created)
        # sin registro de lo bloqueado (casos analizados con versiones anteriores) se repite todo

        async def profiles():
            pending = [p for p in (a["_bloq_perfiles"] if "_bloq_perfiles" in a else PROFILE_CHECKS) if p in PROFILE_CHECKS]
            for wait in (0, 8, 20):
                if not pending:
                    break
                await asyncio.sleep(wait)
                res = await asyncio.gather(*(PROFILE_CHECKS[p](ctx, u) for p in pending), return_exceptions=True)
                still = []
                for p, r in zip(pending, res):
                    if isinstance(r, dict):
                        add_profile(ctx, r)
                    elif isinstance(r, Blocked):
                        still.append(p)
                pending = still
            return pending

        async def sites():
            if not re.match(r"^[\w.\-]{2,40}$", u, re.UNICODE):
                return {}
            every = sweep_targets(await load_sites(ctx.http))
            if "_bloq_sitios" in a:
                pending = {n: s for n, s in every.items() if n in a["_bloq_sitios"]}
            else:
                pending = {n: every[n] for n in (await sweep_sites(ctx, every, u, 48, 15))["pending"]}
                await asyncio.sleep(5)
            return (await sweep_sites(ctx, pending, u, 6, 25, pause=0.3))["pending"] if pending else {}

        left_profiles, left_sites = await asyncio.gather(profiles(), sites())
        ctx.enrich({"_bloq_perfiles": left_profiles, "_bloq_sitios": left_sites}, replace=True)
        new = [x for x in ctx.job.created if x not in before and x.startswith("account:")]
        msg = [f"{len(new)} cuentas nuevas" if new else "Nada nuevo"]
        if left_profiles:
            msg.append(f"siguen limitando: {', '.join(left_profiles)}")
        if left_sites:
            msg.append(f"{len(left_sites)} sitios con protección anti-bots: revísalos a mano en el panel")
        ctx.message = " · ".join(msg)


# ---------------------------------------------------------------------------
# Variantes del usuario (búsqueda a fondo, a petición)
# ---------------------------------------------------------------------------

STRIP_PREFIXES = ("private", "priv", "official", "oficial", "real", "its", "iam", "the", "soy", "not")
STRIP_SUFFIXES = ("private", "priv", "official", "oficial", "real", "backup", "bkp", "alt", "spam", "fake", "xx")
EXPANSIONS = (
    "{c}_", "_{c}", "{c}__", "priv.{c}", "priv_{c}", "{c}.priv", "{c}_priv", "{c}priv", "real{c}", "real.{c}",
    "its{c}", "{c}.oficial", "{c}_oficial", "{c}official", "{c}.official", "{c}2", "{c}_2", "{c}x", "x{c}", "the{c}",
)
VARIANT_CHECKS = {
    "Instagram": p_instagram, "TikTok": p_tiktok, "X/Twitter": p_twitter,
    "Telegram": p_telegram, "Twitch": p_twitch, "YouTube": p_youtube,
}
VALID_USER = re.compile(r"^(?!.*\.\.)[a-z0-9_][a-z0-9_.]{1,29}(?<!\.)$")


def _strip_once(c: str, digits: bool = True) -> set[str]:
    out = set()
    for p in STRIP_PREFIXES:
        for sep in (".", "_", "-", ""):
            rest = c[len(p + sep):]
            if c.startswith(p + sep) and len(rest) >= 3 and (sep or len(p) >= 4):
                out.add(rest)
    for s in STRIP_SUFFIXES:
        for sep in (".", "_", "-", ""):
            rest = c[: -len(sep + s)]
            if c.endswith(sep + s) and len(rest) >= 3 and (sep or len(s) >= 4):
                out.add(rest)
    if digits and re.search(r"[a-z]\d{1,4}$", c):
        out.add(re.sub(r"\d+$", "", c))
    return {x.strip("._-") for x in out if len(x.strip("._-")) >= 3}


# ---- familias de alias: el mismo apodo escrito de distintas formas (xxlunaxx, luunna, lun4_…)

LEET = {"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s"}
TO_LEET = {v: k for k, v in LEET.items() if k.isdigit()}


def alias_key(u: str) -> str:
    """Esqueleto del alias: sin «priv.», separadores, números de adorno, números en lugar de letras ni letras repetidas."""
    s = u.lower().strip().lstrip("@")
    for _ in range(2):
        st = _strip_once(s, digits=False)
        if st:
            s = min(st, key=len)
    s = re.sub(r"[^a-z0-9@$]", "", s)
    s = re.sub(r"\d{2,}$", "", s)
    s = "".join(LEET.get(c, c) for c in s)
    return re.sub(r"\d", "", re.sub(r"(.)\1+", r"\1", s))


def _common(a: str, b: str) -> str:
    best = ""
    for i in range(len(a)):
        for j in range(i + len(best) + 1, len(a) + 1):
            if a[i:j] not in b:
                break
            best = a[i:j]
    return best


def alias_related(a: str, b: str) -> bool:
    ka, kb = alias_key(a), alias_key(b)
    n = len(_common(ka, kb))
    return n >= 4 and n >= 0.6 * min(len(ka), len(kb))


def alias_root(members: list[str]) -> str:
    keys = [alias_key(m) for m in members]
    root = keys[0]
    for k in keys[1:]:
        root = _common(root, k)
    return root if len(root) >= 3 else min(keys, key=len)


def alias_families(names: list[str]) -> list[list[str]]:
    names = list(dict.fromkeys(n for n in names if alias_key(n)))
    parent = list(range(len(names)))

    def find(i):
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i

    for i in range(len(names)):
        for j in range(i + 1, len(names)):
            if alias_related(names[i], names[j]):
                parent[find(i)] = find(j)
    groups: dict[int, list[str]] = {}
    for i, n in enumerate(names):
        groups.setdefault(find(i), []).append(n)
    return [g for g in groups.values() if len(g) >= 2]


def family_variants(members: list[str]) -> list[str]:
    """Combina lo que se repite en la familia: raíz + los prefijos/sufijos vistos + su forma de escribir (0 por o, letras dobles)."""
    root = alias_root(members)
    if len(root) < 3:
        return []
    pres, sufs = {""}, {""}
    for k in (alias_key(m) for m in members):
        i = k.find(root)
        if i >= 0:
            pres.add(k[:i])
            sufs.add(k[i + len(root):])
    low = [m.lower() for m in members]
    leet = {LEET[d] for m in low for d in m if d in LEET and d.isdigit()}
    doubles = {c for m in low for c in re.findall(r"([a-z])\1", m)}
    out: list[str] = []
    for b in sorted({p + root + s for p in pres for s in sufs}, key=lambda x: (len(x), x)):
        forms = [b, "".join(TO_LEET[c] if c in leet else c for c in b)]
        for f in dict.fromkeys(forms):
            out.append(f)
            out += [f[:i] + d + f[i:] for d in sorted(doubles) if (i := f.find(d, 1)) > 0]
    return out


def _mutations(u: str) -> list[str]:
    """Cambios de una letra típicos de los alias: quitar o duplicar letras y números en lugar de letras."""
    out = [re.sub(r"(.)\1+", r"\1", u), "".join(LEET.get(c, c) if c.isdigit() else c for c in u)]
    for i, c in enumerate(u):
        if c in TO_LEET:
            out.append(u[:i] + TO_LEET[c] + u[i + 1:])
        elif c in LEET and c.isdigit():
            out.append(u[:i] + LEET[c] + u[i + 1:])
    for i, c in enumerate(u):
        if i and c.isalpha() and (i + 1 >= len(u) or u[i + 1] != c) and u[i - 1] != c:
            out.append(u[:i + 1] + c + u[i + 1:])
    return out


def _name_tokens(s: str | None) -> list[str]:
    """Palabras de un nombre visible, sin letras decorativas (𝔉𝔯𝔞𝔫𝔫𝔶 → frany), tildes ni letras repetidas."""
    s = unicodedata.normalize("NFKD", unicodedata.normalize("NFKC", s or "")).lower()
    s = "".join(c if c.isalpha() else " " for c in s if not unicodedata.combining(c))
    return [re.sub(r"(.)\1+", r"\1", t) for t in s.split()]


def known_names(entities: list[dict]) -> dict[str, str]:
    """Palabras de los nombres ya reunidos en el caso (personas y nombres de sus cuentas) → nombre original."""
    out: dict[str, str] = {}
    for e in entities:
        a = e.get("attrs") or {}
        if a.get("_verdict") == "descartada":
            continue
        if e["type"] == "person" or (e["type"] == "username" and not re.match(r"^[\w.\-]+$", e["value"])):
            names = [e["value"]]  # un «usuario» con espacios o símbolos es en realidad un nombre visible
        elif e["type"] == "account":
            names = [a.get(k) for k in ("Nombre", "Nombre visible", "Nombre real")]
        else:
            names = []
        for n in names:
            if isinstance(n, str):
                for t in _name_tokens(n):
                    if len(t) >= 4:
                        out.setdefault(t, n.strip())
    return out


def name_match(name: str | None, known: dict[str, str], ignore: str) -> str | None:
    """Nombre del caso con el que coincide el nombre visible; no cuenta lo que sólo repite el propio alias."""
    for t in _name_tokens(name):
        if len(t) < 4 or t in ignore:
            continue
        for k, orig in known.items():
            if k not in ignore and (k == t or (min(len(k), len(t)) >= 5 and (k in t or t in k))):
                return orig
    return None


def username_variants(u: str, limit: int = 36, family: list[str] | None = None, skip: set[str] | None = None) -> list[str]:
    """Formas en que la misma persona pudo escribir su usuario en otra red (o antes de cambiarlo)."""
    u = u.lower().strip().lstrip("@")
    cores = [u]
    for _ in range(2):
        for c in list(cores):
            cores += [x for x in sorted(_strip_once(c)) if x not in cores]
    stripped = cores[1:]
    ordered: list[str] = family_variants(family)[:30] if family else []
    ordered += stripped
    ordered += _mutations(stripped[0] if stripped else u)
    for c in cores:
        parts = [p for p in re.split(r"[._\-]+", c) if p]
        if len(parts) > 1:
            for seq in (parts, parts[::-1]):
                ordered += [".".join(seq), "_".join(seq), "".join(seq)]
    base = stripped[:2] or [re.sub(r"[._\-]", "", u)]
    for c in base:
        ordered += [t.format(c=c) for t in EXPANSIONS]
    seen, out = {u} | (skip or set()), []
    for v in ordered:
        if v not in seen and VALID_USER.match(v):
            seen.add(v)
            out.append(v)
    return out[:limit]


@register
class UsernameVariants(Module):
    name = "username_variants"
    title = "Variantes del usuario"
    description = ("Prueba formas parecidas del usuario (sin «priv.», con guion bajo, con puntos, letras dobles, 0 por o…) "
                   "en Instagram, TikTok, X, Telegram, Twitch y YouTube. Si en el caso hay otros alias de la misma familia, "
                   "combina lo que tienen en común. No llena el grafo: deja la lista en el panel para que añadas sólo las que "
                   "te interesen.")
    inputs = ("username",)
    sources = tuple(VARIANT_CHECKS)
    timeout = 240
    deep = True

    async def run(self, ctx):
        entities = db.graph(ctx.case_id)["entities"]
        in_case = {e["value"].lower() for e in entities if e["type"] == "username"}
        family = next((f for f in alias_families(sorted(in_case)) if ctx.value.lower() in f), None)
        known = known_names(entities)
        root = alias_root(family) if family else alias_key(ctx.value)
        variants = username_variants(ctx.value, 48, family, in_case)
        if not variants:
            raise Skip("No se me ocurren variantes para este usuario")
        sems = {p: asyncio.Semaphore(3) for p in VARIANT_CHECKS}
        found: dict[str, list] = {}
        blocked: set[str] = set()

        async def one(v, platform, check):
            async with sems[platform]:
                try:
                    res = await check(ctx, v)
                except Blocked:
                    blocked.add(platform)
                    return
                except (httpx.HTTPError, ValueError, KeyError, TypeError, AttributeError):
                    return
            if not isinstance(res, dict):
                return
            a = res.get("attrs") or {}
            name = a.get("Nombre") or a.get("Nombre visible") or res.get("name")
            found.setdefault(v, []).append({
                "platform": platform, "url": res["url"], "user": res.get("user") or v, "name": name,
                "followers": a.get("Seguidores") or a.get("Suscriptores"),
                "private": a.get("Privada"), "avatar": a.get("_avatar"),
                "match": name_match(name, known, f"{alias_key(v)}|{root}"),
            })

        await asyncio.gather(*(one(v, p, f) for v in variants for p, f in VARIANT_CHECKS.items()))
        hits = {v: sorted(found[v], key=lambda x: (not x["match"], x["platform"])) for v in variants if v in found}
        likely = [v for v, h in hits.items() if any(x["match"] for x in h)]
        hits = {v: hits[v] for v in likely + [v for v in hits if v not in likely]}
        ctx.enrich({
            "_variantes": hits or None,
            "_variantes_probadas": len(variants),
            "_variantes_bloqueadas": sorted(blocked) or None,
        }, replace=True)
        ctx.enriched = bool(hits)
        ctx.message = (f"{len(hits)} de {len(variants)} variantes existen en alguna red" if hits
                       else f"Ninguna de las {len(variants)} variantes existe en las redes probadas")
        if likely:
            ctx.message += f" · {len(likely)} con un nombre que ya está en el caso"
        if family:
            ctx.message += f" · familia «{root}» ({len(family)} alias)"
        if blocked:
            ctx.message += f" · limitado: {', '.join(sorted(blocked))}"
