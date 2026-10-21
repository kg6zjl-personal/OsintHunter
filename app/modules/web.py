import base64
import time
from urllib.parse import urlparse

from ..util import parse_page
from .base import Module, register
from .domain import add_page

SHORTENERS = {"bit.ly", "t.co", "tinyurl.com", "goo.gl", "ow.ly", "is.gd", "buff.ly", "cutt.ly", "rebrand.ly",
              "shorturl.at", "tiny.cc", "rb.gy", "lnkd.in", "s.id", "t.ly"}


@register
class UrlFetch(Module):
    name = "url_fetch"
    title = "Análisis de la URL"
    description = "Sigue las redirecciones (desacorta enlaces) y extrae título, emails y redes sociales de la página."
    inputs = ("url",)
    sources = ("HTTP directo",)

    async def run(self, ctx):
        r = await ctx.http.get(ctx.value, timeout=20)
        chain = [str(h.url) for h in r.history] + [str(r.url)]
        host = urlparse(str(r.url)).hostname or ""
        orig_host = urlparse(ctx.value).hostname or ""
        ctx.enrich({
            "Estado HTTP": r.status_code,
            "Acortador": "Sí" if orig_host in SHORTENERS else None,
            "Redirecciones": chain if len(chain) > 1 else None,
            "URL final": str(r.url) if len(chain) > 1 else None,
            "Tipo de contenido": r.headers.get("content-type"),
        })
        if host:
            ctx.add("domain", host.removeprefix("www."), rel="alojada en")
        if len(chain) > 1:
            ctx.add("url", str(r.url), {"_links": [["Abrir", str(r.url)]]}, rel="redirige a", pivot=False)
        if "html" in (r.headers.get("content-type") or ""):
            html = r.text[:2_000_000]
            add_page(ctx, parse_page(html, str(r.url)), r.headers, html)


def _vt_stats(attrs: dict) -> dict:
    s = attrs.get("last_analysis_stats") or {}
    total = sum(v for v in s.values() if isinstance(v, int))
    return {
        "VirusTotal: detecciones": f"{s.get('malicious', 0)} maliciosos, {s.get('suspicious', 0)} sospechosos de {total}" if total else None,
        "VirusTotal: reputación": attrs.get("reputation"),
    }


@register
class VirusTotal(Module):
    name = "virustotal"
    title = "VirusTotal"
    description = "Detecciones de antivirus y reputación para dominios, IPs, URLs y archivos (hash)."
    inputs = ("domain", "ip", "url", "hash")
    keys = ("virustotal",)
    sources = ("VirusTotal",)

    async def run(self, ctx):
        t, v = ctx.entity["type"], ctx.value
        path = {
            "domain": f"domains/{v}",
            "ip": f"ip_addresses/{v}",
            "url": "urls/" + base64.urlsafe_b64encode(v.encode()).decode().rstrip("="),
            "hash": f"files/{v}",
        }[t]
        st, d = await ctx.get_json(f"https://www.virustotal.com/api/v3/{path}", headers={"x-apikey": ctx.key("virustotal")})
        if st == 404:
            ctx.message = "VirusTotal no lo conoce"
            return
        if st != 200 or not isinstance(d, dict):
            ctx.message = f"VirusTotal respondió {st}"
            return
        a = (d.get("data") or {}).get("attributes") or {}
        out = _vt_stats(a)
        gui = {"domain": f"domain/{v}", "ip": f"ip-address/{v}", "url": f"url/{path.split('/')[1]}", "hash": f"file/{v}"}[t]
        out["_links"] = [["Ver en VirusTotal", f"https://www.virustotal.com/gui/{gui}"]]
        if t == "domain":
            out["VirusTotal: categorías"] = sorted(set((a.get("categories") or {}).values())) or None
        if t == "hash":
            out.update({
                "Nombre de archivo": a.get("meaningful_name"),
                "Otros nombres": (a.get("names") or [])[:10] or None,
                "Tipo de archivo": a.get("type_description"),
                "Tamaño (bytes)": a.get("size"),
                "Clasificación": ((a.get("popular_threat_classification") or {}).get("suggested_threat_label")),
                "MD5": a.get("md5"), "SHA1": a.get("sha1"), "SHA256": a.get("sha256"),
                "Primera vez visto": a.get("first_submission_date")
                and time.strftime("%Y-%m-%d", time.gmtime(a["first_submission_date"])),
            })
        ctx.enrich(out)


@register
class UrlScan(Module):
    name = "urlscan"
    title = "URLScan.io"
    description = "Escaneos públicos anteriores del dominio: capturas, IPs y páginas vistas."
    inputs = ("domain", "url")
    optional_keys = ("urlscan",)
    sources = ("URLScan.io",)

    async def run(self, ctx):
        if ctx.entity["type"] == "domain":
            query = f"domain:{ctx.value}"
        else:
            query = 'task.url:"' + ctx.value.replace('"', "") + '"'
        headers = {"API-Key": ctx.key("urlscan")} if ctx.key("urlscan") else {}
        st, d = await ctx.get_json("https://urlscan.io/api/v1/search/", params={"q": query, "size": 20},
                                   headers=headers)
        if st in (401, 403, 429):
            ctx.message = "URLScan requiere clave o se superó el límite"
            return
        results = (d or {}).get("results") if isinstance(d, dict) else None
        if not results:
            return
        ips, links = set(), []
        for res in results:
            page = res.get("page") or {}
            if page.get("ip"):
                ips.add(page["ip"])
            if res.get("result") and len(links) < 5:
                links.append([f"Escaneo {(res.get('task') or {}).get('time', '')[:10]}",
                              res["result"].replace("/api/v1/result/", "/result/")])
        ctx.enrich({"URLScan: escaneos": (d or {}).get("total"), "_links": links})
        for ip in list(ips)[:10]:
            ctx.add("ip", ip, rel="visto en (URLScan)", pivot=False)


@register
class AbuseCh(Module):
    name = "abusech"
    title = "abuse.ch (URLhaus/ThreatFox)"
    description = "Comprueba si el dominio, IP o URL distribuye malware o es infraestructura de botnets."
    inputs = ("domain", "ip", "url")
    keys = ("abusech",)
    sources = ("URLhaus", "ThreatFox")

    async def run(self, ctx):
        h = {"Auth-Key": ctx.key("abusech")}
        t, v = ctx.entity["type"], ctx.value
        if t == "url":
            r = await ctx.http.post("https://urlhaus-api.abuse.ch/v1/url/", data={"url": v}, headers=h)
        else:
            r = await ctx.http.post("https://urlhaus-api.abuse.ch/v1/host/", data={"host": v}, headers=h)
        uh = r.json() if r.status_code == 200 else {}
        out = {}
        if uh.get("query_status") == "ok":
            out["URLhaus: URLs maliciosas"] = uh.get("url_count") or 1
            out["URLhaus: amenaza"] = uh.get("threat") or None
            tags = {tag for u in uh.get("urls") or [] for tag in (u.get("tags") or [])}
            out["URLhaus: etiquetas"] = sorted(tags) or None
        r = await ctx.http.post("https://threatfox-api.abuse.ch/api/v1/", json={"query": "search_ioc", "search_term": v},
                                headers=h)
        tf = r.json() if r.status_code == 200 else {}
        if tf.get("query_status") == "ok" and isinstance(tf.get("data"), list):
            out["ThreatFox: IOCs"] = len(tf["data"])
            out["ThreatFox: malware"] = sorted({x.get("malware_printable") for x in tf["data"] if x.get("malware_printable")})
        if out:
            ctx.enrich(out)
        else:
            ctx.message = "Sin rastro en URLhaus ni ThreatFox"
