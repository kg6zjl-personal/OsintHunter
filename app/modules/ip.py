from ..util import reverse_dns
from .base import Module, Skip, register
from .domain import is_public_ip


def _public(ctx):
    if not is_public_ip(ctx.value):
        raise Skip("IP privada o reservada: no hay datos públicos")


@register
class IpGeo(Module):
    name = "ip_geo"
    title = "Geolocalización e ISP"
    description = "País, ciudad, coordenadas aproximadas, ASN, ISP y si es proxy/VPN/hosting."
    inputs = ("ip",)
    sources = ("ipwho.is", "ip-api.com")

    async def run(self, ctx):
        _public(ctx)
        st, d = await ctx.get_json(f"https://ipwho.is/{ctx.value}")
        if st == 200 and isinstance(d, dict) and d.get("success"):
            conn = d.get("connection") or {}
            geo = {"country": d.get("country"), "region": d.get("region"), "city": d.get("city"),
                   "lat": d.get("latitude"), "lon": d.get("longitude"), "asn": conn.get("asn"),
                   "org": conn.get("org") or conn.get("isp"), "isp": conn.get("isp"), "tz": (d.get("timezone") or {}).get("id")}
        else:
            st, d = await ctx.get_json(
                f"http://ip-api.com/json/{ctx.value}?fields=status,country,regionName,city,lat,lon,timezone,isp,org,as,proxy,hosting,mobile"
            )
            if not isinstance(d, dict) or d.get("status") != "success":
                return
            asn = (d.get("as") or "").split(" ")[0].lstrip("AS")
            geo = {"country": d.get("country"), "region": d.get("regionName"), "city": d.get("city"), "lat": d.get("lat"),
                   "lon": d.get("lon"), "asn": int(asn) if asn.isdigit() else None, "org": d.get("org"), "isp": d.get("isp"),
                   "tz": d.get("timezone"), "proxy": d.get("proxy"), "hosting": d.get("hosting"), "mobile": d.get("mobile")}
        ctx.enrich({
            "País": geo["country"], "Región": geo["region"], "Ciudad": geo["city"], "ISP": geo["isp"],
            "Zona horaria": geo["tz"],
            "Proxy/VPN": "Sí" if geo.get("proxy") else None,
            "Hosting/centro de datos": "Sí" if geo.get("hosting") else None,
            "Red móvil": "Sí" if geo.get("mobile") else None,
        })
        loc = ", ".join(x for x in (geo["city"], geo["region"], geo["country"]) if x)
        if loc:
            ctx.add("location", loc, {"_lat": geo["lat"], "_lon": geo["lon"], "Precisión": "Aproximada (ciudad)",
                                      "_links": [["Ver en mapa", f"https://www.openstreetmap.org/?mlat={geo['lat']}&mlon={geo['lon']}#map=11/{geo['lat']}/{geo['lon']}"]]},
                    rel="geolocalizada en", pivot=False)
        if geo["asn"]:
            ctx.add("asn", f"AS{geo['asn']}", {"Organización": geo["org"],
                                               "_links": [["bgp.he.net", f"https://bgp.he.net/AS{geo['asn']}"]]},
                    rel="red", pivot=False)


@register
class InternetDB(Module):
    name = "internetdb"
    title = "Puertos y vulnerabilidades (InternetDB)"
    description = "Puertos abiertos, software, CVEs y nombres de host según el escaneo pasivo gratuito de Shodan."
    inputs = ("ip",)
    sources = ("Shodan InternetDB",)

    async def run(self, ctx):
        _public(ctx)
        st, d = await ctx.get_json(f"https://internetdb.shodan.io/{ctx.value}")
        if st != 200 or not isinstance(d, dict):
            return
        ctx.enrich({
            "Puertos abiertos": d.get("ports"),
            "Software (CPE)": d.get("cpes"),
            "Etiquetas": d.get("tags"),
            "Vulnerabilidades (CVE)": d.get("vulns"),
        })
        for h in (d.get("hostnames") or [])[:30]:
            ctx.add("domain", h, rel="nombre de host", pivot=False)


@register
class ReverseDns(Module):
    name = "reverse_dns"
    title = "DNS inverso"
    description = "Nombre de host asociado a la IP (registro PTR)."
    inputs = ("ip",)
    sources = ("DNS",)

    async def run(self, ctx):
        for h in await reverse_dns(ctx.value):
            ctx.add("domain", h, {"Rol": "PTR"}, rel="DNS inverso", pivot=False)


@register
class ShodanHost(Module):
    name = "shodan_host"
    title = "Shodan"
    description = "Servicios, banners, organización y sistema operativo vistos por Shodan."
    inputs = ("ip",)
    keys = ("shodan",)
    sources = ("Shodan",)

    async def run(self, ctx):
        _public(ctx)
        st, d = await ctx.get_json(f"https://api.shodan.io/shodan/host/{ctx.value}", params={"key": ctx.key("shodan")})
        if st == 404:
            return
        if st != 200 or not isinstance(d, dict):
            ctx.message = (d or {}).get("error", f"Shodan respondió {st}") if isinstance(d, dict) else f"Shodan respondió {st}"
            return
        services = [f"{s.get('port')}/{s.get('transport')} {s.get('product') or ''} {s.get('version') or ''}".strip()
                    for s in d.get("data") or []]
        ctx.enrich({"Shodan: organización": d.get("org"), "Shodan: SO": d.get("os"), "Shodan: servicios": services,
                    "Shodan: última vez": (d.get("last_update") or "")[:10],
                    "_links": [["Shodan", f"https://www.shodan.io/host/{ctx.value}"]]})
        for dom in d.get("domains") or []:
            ctx.add("domain", dom, rel="dominio (Shodan)", pivot=False)


@register
class AbuseIPDB(Module):
    name = "abuseipdb"
    title = "AbuseIPDB"
    description = "Reportes de abuso (spam, ataques, escaneos) y puntuación de confianza."
    inputs = ("ip",)
    keys = ("abuseipdb",)
    sources = ("AbuseIPDB",)

    async def run(self, ctx):
        _public(ctx)
        st, d = await ctx.get_json(
            "https://api.abuseipdb.com/api/v2/check",
            params={"ipAddress": ctx.value, "maxAgeInDays": 365},
            headers={"Key": ctx.key("abuseipdb"), "Accept": "application/json"},
        )
        data = (d or {}).get("data") if isinstance(d, dict) else None
        if not data:
            ctx.message = f"AbuseIPDB respondió {st}"
            return
        ctx.enrich({
            "AbuseIPDB: puntuación": f"{data.get('abuseConfidenceScore')}%",
            "AbuseIPDB: reportes (1 año)": data.get("totalReports"),
            "AbuseIPDB: uso": data.get("usageType"),
            "AbuseIPDB: último reporte": (data.get("lastReportedAt") or "")[:10] or None,
            "Nodo Tor": "Sí" if data.get("isTor") else None,
        })


@register
class GreyNoise(Module):
    name = "greynoise"
    title = "GreyNoise"
    description = "Indica si la IP escanea Internet de forma masiva o pertenece a un servicio conocido."
    inputs = ("ip",)
    optional_keys = ("greynoise",)
    sources = ("GreyNoise Community",)

    async def run(self, ctx):
        _public(ctx)
        headers = {"key": ctx.key("greynoise")} if ctx.key("greynoise") else {}
        st, d = await ctx.get_json(f"https://api.greynoise.io/v3/community/{ctx.value}", headers=headers)
        if st == 429:
            raise Skip("Límite de GreyNoise alcanzado; añade una clave gratuita en Ajustes")
        if st not in (200, 404) or not isinstance(d, dict) or "noise" not in d:
            return
        ctx.enrich({
            "GreyNoise: escáner masivo": "Sí" if d.get("noise") else "No",
            "GreyNoise: servicio conocido": d.get("name") if d.get("riot") else None,
            "GreyNoise: clasificación": d.get("classification"),
            "GreyNoise: visto": d.get("last_seen"),
        })
