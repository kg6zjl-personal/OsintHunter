import asyncio
import ipaddress
import re

import httpx

from ..util import find_analytics_ids, parse_page, resolve, tech_from_response
from .base import Module, register


def _vcard(entity: dict) -> dict:
    out = {}
    for item in (entity.get("vcardArray") or [None, []])[1]:
        if len(item) >= 4 and item[0] in ("fn", "org", "email", "tel", "adr"):
            val = item[3]
            if item[0] == "adr" and isinstance(val, list):
                val = ", ".join(str(x) for x in val if x)
            if val and not re.search(r"redacted|privacy|withheld|not disclosed", str(val), re.I):
                out[item[0]] = val
    return out


ROLE_NAMES = {"registrant": "Titular", "administrative": "Administrativo", "technical": "Técnico",
              "registrar": "Registrador", "abuse": "Abuso", "billing": "Facturación"}


def add_page(ctx, page: dict, headers, html: str, parent: str | None = None) -> None:
    """Vuelca lo encontrado en una página web al grafo."""
    from .username import PROFILE_URLS

    ctx.enrich({
        "Título web": page["title"],
        "Descripción web": page["description"],
        "Tecnologías": tech_from_response(headers, html) + ([page["generator"]] if page["generator"] else []),
        "IDs de analítica/publicidad": find_analytics_ids(html),
    }, eid=parent)
    from .enrich import DISCORD_INVITE

    for e in page["emails"][:30]:
        ctx.add("email", e, rel="email en la web", parent=parent)
    for rut, context in page.get("ruts", [])[:20]:
        ctx.add("rut", rut, {"Contexto en la web": [context]}, rel="RUT en la web", parent=parent, pivot=False)
    for l in [l for l in page["external_links"] if DISCORD_INVITE.match(l)][:5]:
        ctx.add("url", l, {"_links": [["Abrir", l]]}, rel="invitación de Discord", parent=parent, pivot=False)
    for platform, user, url in page["socials"][:30]:
        tpl = PROFILE_URLS.get(platform)
        acc = ctx.add("account", tpl.format(user) if tpl else url,
                      {"Plataforma": platform, "Usuario": user, "_links": [["Abrir perfil", url]]},
                      rel="red social en la web", parent=parent, pivot=False)
        if acc and platform not in ("LinkedIn", "Facebook"):
            ctx.add("username", user, rel="usuario", parent=acc, pivot=False)


@register
class DnsRecords(Module):
    name = "dns_records"
    title = "Registros DNS"
    description = "A, AAAA, MX, NS, TXT, SOA, CAA y DMARC; extrae IPs, servidores y servicios verificados en TXT."
    inputs = ("domain",)
    sources = ("DNS",)

    async def run(self, ctx):
        d = ctx.value
        types = ("A", "AAAA", "MX", "NS", "TXT", "SOA", "CAA", "CNAME")
        results = dict(zip(types, await asyncio.gather(*(resolve(d, t) for t in types))))
        dmarc = await resolve(f"_dmarc.{d}", "TXT")
        ctx.enrich({f"DNS {t}": v for t, v in results.items() if v} | ({"DMARC": dmarc} if dmarc else {}))
        for ip in results["A"] + results["AAAA"]:
            ctx.add("ip", ip, rel="resuelve a")
        for mx in results["MX"]:
            host = mx.split()[-1].rstrip(".")
            if host and host != d:
                ctx.add("domain", host, {"Rol": "Servidor de correo"}, rel="MX", pivot=False)
        for ns in results["NS"]:
            ctx.add("domain", ns.rstrip("."), {"Rol": "Servidor DNS"}, rel="NS", pivot=False)
        verified = []
        for txt in results["TXT"]:
            m = re.match(r"^([a-z0-9\-_]+)-(?:site-)?verification=", txt, re.I)
            if m:
                verified.append(m.group(1))
            for inc in re.findall(r"include:([^\s]+)", txt):
                ctx.add("domain", inc, {"Rol": "Proveedor autorizado en SPF"}, rel="SPF", pivot=False)
        if verified:
            ctx.enrich({"Servicios verificados (TXT)": sorted(set(verified))})
        for rec in dmarc:
            for mail in re.findall(r"mailto:([^,;\s!]+)", rec):
                ctx.add("email", mail.lower(), {"Rol": "Recibe informes DMARC"}, rel="DMARC", pivot=False)


@register
class Rdap(Module):
    name = "rdap"
    title = "WHOIS (RDAP)"
    description = "Registrador, fechas de alta y caducidad, estado y contactos no ocultos."
    inputs = ("domain",)
    sources = ("RDAP (rdap.org)",)

    async def run(self, ctx):
        st, d = await ctx.get_json(f"https://rdap.org/domain/{ctx.value}")
        if st != 200 or not isinstance(d, dict):
            ctx.message = "El registro no publica RDAP para este dominio" if st == 404 else f"RDAP respondió {st}"
            return
        events = {e.get("eventAction"): (e.get("eventDate") or "")[:10] for e in d.get("events") or []}
        attrs = {
            "Alta": events.get("registration"),
            "Caduca": events.get("expiration"),
            "Última modificación": events.get("last changed"),
            "Estado": d.get("status"),
            "DNSSEC": "Sí" if (d.get("secureDNS") or {}).get("delegationSigned") else None,
        }
        for ent in d.get("entities") or []:
            roles = ent.get("roles") or []
            card = _vcard(ent)
            nested = [_vcard(x) for x in ent.get("entities") or []]
            if "registrar" in roles:
                attrs["Registrador"] = card.get("fn") or card.get("org")
                for n in nested:
                    if n.get("email"):
                        attrs["Email abuso registrador"] = n["email"]
                continue
            label = "/".join(ROLE_NAMES.get(r, r) for r in roles)
            org = card.get("org") or card.get("fn")
            if org:
                ctx.add("organization", org, {"Rol WHOIS": label, "Dirección": card.get("adr"), "Teléfono": card.get("tel")},
                        rel=f"WHOIS {label}")
            if card.get("email"):
                ctx.add("email", card["email"], {"Rol WHOIS": label}, rel=f"WHOIS {label}")
        ctx.enrich(attrs)


@register
class Subdomains(Module):
    name = "subdomains"
    title = "Subdominios (certificados)"
    description = "Subdominios descubiertos en los registros públicos de certificados TLS."
    inputs = ("domain",)
    sources = ("crt.sh", "CertSpotter")
    timeout = 90

    async def run(self, ctx):
        d = ctx.value
        names: set[str] = set()
        try:
            r = await ctx.http.get("https://crt.sh/", params={"q": f"%.{d}", "output": "json"}, timeout=60)
            if r.status_code == 200:
                for row in r.json():
                    for n in (row.get("name_value") or "").split("\n"):
                        names.add(n.strip().lower().lstrip("*."))
        except (httpx.HTTPError, ValueError):
            pass
        if not names:
            st, data = await ctx.get_json(
                "https://api.certspotter.com/v1/issuances",
                params={"domain": d, "include_subdomains": "true", "expand": "dns_names"},
            )
            if st == 200 and isinstance(data, list):
                for row in data:
                    for n in row.get("dns_names") or []:
                        names.add(n.lower().lstrip("*."))
        subs = sorted(n for n in names if n.endswith("." + d) and n != d and " " not in n)
        if not subs:
            return
        ctx.enrich({"Subdominios": subs, "Nº subdominios": len(subs)})
        interesting = re.compile(r"(admin|vpn|dev|test|stag|intranet|mail|portal|api|panel|git|jenkins|old|backup|beta|internal)")
        ordered = sorted(subs, key=lambda s: (not interesting.search(s), s))
        for s in ordered[:60]:
            ctx.add("domain", s, {"Rol": "Subdominio"}, rel="subdominio", pivot=False)
        if len(subs) > 60:
            ctx.message = f"{len(subs)} subdominios (60 en el grafo, lista completa en la ficha)"


@register
class Website(Module):
    name = "website"
    title = "Sitio web"
    description = "Título, tecnologías, emails, redes sociales e IDs de analítica de la web del dominio."
    inputs = ("domain",)
    sources = ("HTTP directo",)

    async def run(self, ctx):
        r = None
        for scheme in ("https", "http"):
            try:
                r = await ctx.http.get(f"{scheme}://{ctx.value}", timeout=20)
                break
            except httpx.HTTPError:
                continue
        if r is None:
            ctx.message = "La web no responde"
            return
        html = r.text[:2_000_000]
        page = parse_page(html, str(r.url))
        ctx.enrich({"Web: estado HTTP": r.status_code, "Web: URL final": str(r.url)})
        add_page(ctx, page, r.headers, html)


@register
class Wayback(Module):
    name = "wayback"
    title = "Archivo histórico (Wayback)"
    description = "Primera y última captura en archive.org y número de capturas."
    inputs = ("domain", "url")
    sources = ("Internet Archive",)
    timeout = 45

    async def run(self, ctx):
        target = ctx.value
        params = {"url": target, "output": "json", "fl": "timestamp", "collapse": "timestamp:6"}
        st, rows = await ctx.get_json("https://web.archive.org/cdx/search/cdx", params=params, timeout=40)
        if st != 200 or not isinstance(rows, list) or len(rows) < 2:
            return
        stamps = [r[0] for r in rows[1:]]
        fmt = lambda s: f"{s[:4]}-{s[4:6]}-{s[6:8]}"  # noqa: E731
        ctx.enrich({
            "Wayback: primera captura": fmt(stamps[0]),
            "Wayback: última captura": fmt(stamps[-1]),
            "Wayback: meses con capturas": len(stamps),
            "_links": [
                ["Primera captura", f"https://web.archive.org/web/{stamps[0]}/{target}"],
                ["Todas las capturas", f"https://web.archive.org/web/*/{target}*"],
            ],
        })


def is_public_ip(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False
