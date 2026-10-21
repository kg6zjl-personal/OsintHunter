import asyncio
import base64
import hashlib
import html
import re
from collections import Counter

import httpx

from ..db import db
from .base import Module, Skip, register
from .username import PROFILE_URLS, add_profile


def _gh_headers(ctx) -> dict:
    h = {"Accept": "application/vnd.github+json"}
    if ctx.key("github"):
        h["Authorization"] = f"Bearer {ctx.key('github')}"
    return h


def ssh_fingerprints(text: str) -> dict[str, str]:
    """{huella SHA256: tipo} de un fichero tipo authorized_keys."""
    out = {}
    for line in (text or "").splitlines():
        parts = line.split()
        if len(parts) < 2 or not parts[0].startswith(("ssh-", "ecdsa-", "sk-")):
            continue
        try:
            blob = base64.b64decode(parts[1])
        except ValueError:
            continue
        fp = "SHA256:" + base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip("=")
        out[fp] = parts[0]
    return out


def find_account(case_id: int, platform: str, user: str) -> dict | None:
    user = user.lower()
    for e in db.graph(case_id)["entities"]:
        a = e["attrs"]
        if e["type"] == "account" and a.get("Plataforma") == platform and str(a.get("Usuario") or "").lower() == user:
            return e
    return None


@register
class GithubDeep(Module):
    name = "github_deep"
    title = "GitHub a fondo"
    description = ("Organizaciones, repositorios y lenguajes, cuentas enlazadas, emails de sus claves GPG y "
                   "claves SSH (si GitLab tiene la misma clave, es la misma persona)")
    inputs = ("username",)
    optional_keys = ("github",)
    sources = ("api.github.com",)

    async def run(self, ctx):
        h = _gh_headers(ctx)
        st, user = await ctx.get_json(f"https://api.github.com/users/{ctx.value.strip().lstrip('@')}", headers=h)
        if st in (403, 429):
            raise Skip("Límite de la API de GitHub alcanzado (60/hora sin clave): añade un token gratuito en Ajustes")
        if st != 200 or not isinstance(user, dict):
            return
        login = user["login"]
        api = f"https://api.github.com/users/{login}"
        (st_s, social), (st_o, orgs), (st_r, repos), (st_g, gpg) = await asyncio.gather(
            ctx.get_json(f"{api}/social_accounts", headers=h),
            ctx.get_json(f"{api}/orgs", headers=h),
            ctx.get_json(f"{api}/repos?per_page=100&sort=pushed&type=owner", headers=h),
            ctx.get_json(f"{api}/gpg_keys", headers=h),
        )
        gh_keys, gl_keys = await asyncio.gather(
            self._text(ctx, f"https://github.com/{login}.keys"),
            self._text(ctx, f"https://gitlab.com/{login}.keys"),
        )

        attrs: dict = {"_avatar": user.get("avatar_url")}
        urls = [x.get("url") for x in social if isinstance(x, dict)] if st_s == 200 and isinstance(social, list) else []

        if st_r == 200 and isinstance(repos, list):
            own = [r for r in repos if not r.get("fork")]
            langs = Counter(r["language"] for r in own if r.get("language"))
            top = sorted(own, key=lambda r: -(r.get("stargazers_count") or 0))[:6]
            attrs.update({
                "Repos propios (últimos 100)": len(own),
                "Forks": len(repos) - len(own) or None,
                "Estrellas recibidas": sum(r.get("stargazers_count") or 0 for r in own) or None,
                "Lenguajes": [f"{lang} ({n})" for lang, n in langs.most_common(8)] or None,
                "Repos destacados": [f"{r['name']} ★{r.get('stargazers_count', 0)}"
                                     + (f" — {r['description'][:90]}" if r.get("description") else "") for r in top] or None,
                "Último push": (own[0].get("pushed_at") or "")[:10] or None if own else None,
            })
            urls += [r.get("homepage") for r in own if r.get("homepage")][:15]

        gpg_emails: list[str] = []
        if st_g == 200 and isinstance(gpg, list) and gpg:
            for k in gpg:
                for sub in [k] + (k.get("subkeys") or []):
                    gpg_emails += [e["email"] for e in sub.get("emails") or [] if e.get("email")]
            attrs["Claves GPG"] = [k.get("key_id") for k in gpg if k.get("key_id")]

        fps = ssh_fingerprints(gh_keys)
        if fps:
            attrs["Claves SSH"] = [f"{t} {fp}" for fp, t in fps.items()]

        acc = add_profile(ctx, {
            "platform": "GitHub", "user": login, "url": user["html_url"], "attrs": attrs,
            "emails": gpg_emails, "urls": urls,
        })
        if not acc:
            return

        if st_o == 200 and isinstance(orgs, list):
            for o in orgs:
                ctx.add("organization", f"GitHub: {o['login']}", {
                    "Descripción": o.get("description"), "_avatar": o.get("avatar_url"),
                    "_links": [["Abrir en GitHub", f"https://github.com/{o['login']}"]],
                }, rel="miembro de", parent=acc, pivot=False)

        shared = set(fps) & set(ssh_fingerprints(gl_keys))
        if shared:
            url = f"https://gitlab.com/{login}"
            ctx.add("account", url, {
                "Plataforma": "GitLab", "Usuario": login, "_links": [["Abrir perfil", url]],
                "Verificación": "Misma clave SSH que GitHub",
                "Claves SSH en común": sorted(shared),
            }, rel="misma clave SSH", parent=acc, pivot=False)

    @staticmethod
    async def _text(ctx, url: str) -> str:
        try:
            r = await ctx.http.get(url, timeout=15)
        except httpx.HTTPError:
            return ""
        return r.text if r.status_code == 200 and "<html" not in r.text[:200].lower() else ""


# ---------------------------------------------------------------- Wayback: perfiles archivados

ARCHIVE_TARGETS = [
    ("X/Twitter", "twitter.com/{}"), ("Instagram", "instagram.com/{}/"), ("TikTok", "tiktok.com/@{}"),
    ("Facebook", "facebook.com/{}"), ("Reddit", "reddit.com/user/{}"), ("YouTube", "youtube.com/@{}"),
    ("Twitch", "twitch.tv/{}"), ("Telegram", "t.me/{}"), ("GitHub", "github.com/{}"),
    ("LinkedIn", "linkedin.com/in/{}"), ("Pinterest", "pinterest.com/{}/"), ("Tumblr", "{}.tumblr.com"),
    ("Threads", "threads.net/@{}"), ("Medium", "medium.com/@{}"),
]


# compartido entre todos los usuarios investigados a la vez: Internet Archive limita las consultas
_CDX_SEM = asyncio.Semaphore(4)


def _ts(ts: str) -> str:
    return f"{ts[:4]}-{ts[4:6]}-{ts[6:8]}"


async def wait_for_module(ctx, module: str, limit: float = 90) -> None:
    """Espera a que otro módulo que corre en paralelo sobre la misma entidad termine."""
    eid = ctx.entity["id"]

    def running() -> bool:
        started = done = False
        for e in ctx.job.events:
            if e.get("type") == "run_start" and e.get("entity_id") == eid and e.get("module") == module:
                started = True
            elif e.get("type") == "run" and e["run"]["entity_id"] == eid and e["run"]["module"] == module:
                done = True
        return started and not done

    for _ in range(int(limit * 2)):
        if not running():
            return
        await asyncio.sleep(0.5)


@register
class WaybackProfiles(Module):
    name = "wayback_profiles"
    title = "Perfiles archivados (Wayback)"
    description = ("Busca copias de sus perfiles en Internet Archive: sirve para ver cuentas borradas o "
                   "cómo eran antes")
    inputs = ("username",)
    sources = ("web.archive.org",)
    timeout = 180

    async def run(self, ctx):
        u = ctx.value.strip().lstrip("@")
        if not re.fullmatch(r"[\w.\-]{2,40}", u):
            raise Skip("El usuario tiene caracteres que no forman parte de una URL de perfil")

        async def one(platform, tpl):
            target = tpl.format(u)
            async with _CDX_SEM:
                for attempt in range(2):
                    try:
                        r = await ctx.http.get("https://web.archive.org/cdx/search/cdx", timeout=40, params={
                            "url": target, "output": "json", "fl": "timestamp", "filter": "statuscode:200",
                            "collapse": "timestamp:6", "limit": "2000",
                        })
                    except httpx.HTTPError:
                        return platform, target, None
                    if r.status_code in (429, 503) and attempt == 0:
                        await asyncio.sleep(4)
                        continue
                    break
            if r.status_code != 200:
                return platform, target, None
            try:
                rows = r.json()[1:]
            except ValueError:
                return platform, target, None
            return platform, target, [x[0] for x in rows]

        results = await asyncio.gather(*(one(p, t) for p, t in ARCHIVE_TARGETS))
        # si a la vez se están comprobando los perfiles en vivo, hay que saber cuáles existen antes de marcar
        # una cuenta como "sólo vista en archivo"
        await wait_for_module(ctx, "username_profiles")
        failed = [p for p, _, s in results if s is None]
        found = [(p, t, s) for p, t, s in results if s]
        for platform, target, stamps in found:
            first, last = stamps[0], stamps[-1]
            attrs = {
                "Wayback: primera captura": _ts(first),
                "Wayback: última captura": _ts(last),
                "Wayback: meses con capturas": len(stamps),
                "_links": [["Primera copia archivada", f"https://web.archive.org/web/{first}/https://{target}"],
                           ["Última copia archivada", f"https://web.archive.org/web/{last}/https://{target}"],
                           ["Todas las copias", f"https://web.archive.org/web/*/{target}*"]],
            }
            existing = find_account(ctx.case_id, platform, u)
            if existing:
                ctx.enrich(attrs, existing["id"])
                continue
            url = PROFILE_URLS.get(platform, "https://{}").format(u) if platform in PROFILE_URLS else f"https://{target}"
            attrs.update({"Plataforma": platform, "Usuario": u,
                          "Verificación": "Sólo vista en archivo (puede estar borrada o no se comprobó en vivo)"})
            ctx.add("account", url, attrs, rel="archivada", pivot=False)
        if failed and not found:
            raise Skip(f"Internet Archive no respondió ({len(failed)} consultas fallidas); prueba más tarde")
        ctx.message = f"Copias en {len(found)} plataformas" + (f": {', '.join(p for p, _, _ in found)}" if found else "") \
            + (f" · sin respuesta: {', '.join(failed)}" if failed else "")


# ---------------------------------------------------------------- menciones en foros

def _snippet(text: str, term: str, n: int = 160) -> str:
    text = re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", html.unescape(text or ""))).strip()
    i = text.lower().find(term.lower())
    if i < 0:
        return text[:n]
    start = max(0, i - n // 3)
    return ("…" if start else "") + text[start:start + n] + ("…" if start + n < len(text) else "")


@register
class ForumMentions(Module):
    name = "forum_mentions"
    title = "Menciones en foros (Hacker News)"
    description = "Comentarios y publicaciones de Hacker News que mencionan el dato, con autor, fecha y enlace"
    inputs = ("username", "email", "person", "domain")
    sources = ("hn.algolia.com",)

    async def run(self, ctx):
        term = ctx.value.strip().lstrip("@")
        if len(term) < 4:
            raise Skip("Término demasiado corto para buscar menciones sin ruido")
        base = "https://hn.algolia.com/api/v1/search"
        if ctx.entity["type"] == "domain":
            params = {"query": term, "restrictSearchableAttributes": "url", "tags": "story", "hitsPerPage": 50}
        else:
            params = {"query": f'"{term}"', "tags": "(comment,story)", "hitsPerPage": 50, "typoTolerance": "false"}
        st, d = await ctx.get_json(base, params=params)
        if st != 200 or not isinstance(d, dict):
            raise RuntimeError(f"Hacker News respondió {st}")
        hits = []
        for h in d.get("hits") or []:
            text = " ".join(str(h.get(k) or "") for k in ("comment_text", "story_text", "title", "url"))
            if term.lower() not in text.lower():
                continue
            if ctx.entity["type"] == "username" and (h.get("author") or "").lower() == term.lower():
                continue
            hits.append(h)
        if not hits:
            return
        hits.sort(key=lambda h: -(h.get("created_at_i") or 0))
        lines, links = [], []
        for h in hits[:12]:
            item = f"https://news.ycombinator.com/item?id={h['objectID']}"
            date = (h.get("created_at") or "")[:10]
            what = h.get("title") or _snippet(h.get("comment_text") or h.get("story_text") or "", term)
            lines.append(f"{date} · {h.get('author')}: {what}")
            links.append([f"HN {date} · {h.get('author')}", item])
        authors = Counter(h.get("author") for h in hits if h.get("author"))
        ctx.message = f"{d.get('nbHits') or len(hits)} menciones en Hacker News"
        ctx.enrich({
            "Menciones en Hacker News": d.get("nbHits") or len(hits),
            "Menciones recientes (HN)": lines,
            "Quién lo menciona más (HN)": [f"{a} ({n})" for a, n in authors.most_common(5)] if len(authors) > 1 else None,
            "Primera mención (HN)": min((h.get("created_at") or "")[:10] for h in hits),
            "_links": links[:8],
        })
        ctx.found += len(hits)
