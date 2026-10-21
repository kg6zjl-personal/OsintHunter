import re
import time
import unicodedata
from urllib.parse import quote_plus

from ..config import settings
from ..db import db
from ..models import CRYPTO_NAMES, crypto_chain
from .base import Module, register
from .people import name_variants

# ---------------------------------------------------------------------------
# Hashes
# ---------------------------------------------------------------------------

HASH_TYPES = {
    32: ["MD5", "NTLM", "MD4"],
    40: ["SHA-1", "RIPEMD-160"],
    56: ["SHA-224", "SHA3-224"],
    64: ["SHA-256", "SHA3-256", "BLAKE2s"],
    96: ["SHA-384", "SHA3-384"],
    128: ["SHA-512", "SHA3-512", "BLAKE2b", "Whirlpool"],
}


@register
class HashIdentify(Module):
    name = "hash_identify"
    title = "Identificar hash"
    description = "Algoritmos posibles según la longitud y enlaces para buscarlo."
    inputs = ("hash",)
    sources = ("Local",)

    async def run(self, ctx):
        h = ctx.value
        ctx.enrich({
            "Algoritmos posibles": HASH_TYPES.get(len(h), ["Desconocido"]),
            "_links": [
                ["Buscar en Google", f'https://www.google.com/search?q="{h}"'],
                ["VirusTotal", f"https://www.virustotal.com/gui/search/{h}"],
                ["MalwareBazaar", f"https://bazaar.abuse.ch/browse.php?search=sha256%3A{h}"],
                ["Hashes.com (contraseñas)", f"https://hashes.com/en/decrypt/hash"],
            ],
        })


@register
class MalwareBazaar(Module):
    name = "malwarebazaar"
    title = "MalwareBazaar"
    description = "Busca el hash en la base de muestras de malware de abuse.ch."
    inputs = ("hash",)
    keys = ("abusech",)
    sources = ("MalwareBazaar",)

    async def run(self, ctx):
        r = await ctx.http.post("https://mb-api.abuse.ch/api/v1/", data={"query": "get_info", "hash": ctx.value},
                                headers={"Auth-Key": ctx.key("abusech")})
        d = r.json() if r.status_code == 200 else {}
        if d.get("query_status") != "ok" or not d.get("data"):
            return
        s = d["data"][0]
        ctx.enrich({
            "Malware: familia": s.get("signature"),
            "Malware: archivo": s.get("file_name"),
            "Malware: tipo": s.get("file_type"),
            "Malware: visto": s.get("first_seen"),
            "Malware: etiquetas": s.get("tags"),
            "_links": [["MalwareBazaar", f"https://bazaar.abuse.ch/sample/{s.get('sha256_hash')}/"]],
        })


# ---------------------------------------------------------------------------
# Criptomonedas
# ---------------------------------------------------------------------------

EXPLORERS = {
    "btc": "https://mempool.space/address/{}",
    "eth": "https://etherscan.io/address/{}",
    "ltc": "https://blockchair.com/litecoin/address/{}",
    "doge": "https://blockchair.com/dogecoin/address/{}",
    "trx": "https://tronscan.org/#/address/{}",
}


@register
class CryptoWallet(Module):
    name = "crypto_wallet"
    title = "Cartera de criptomonedas"
    description = "Saldo, número de transacciones, fechas y principales contrapartes de una dirección."
    inputs = ("crypto",)
    sources = ("mempool.space", "Ethplorer", "Blockchair")

    async def run(self, ctx):
        a = ctx.value
        chain = crypto_chain(a)
        links = [["Explorador", EXPLORERS[chain].format(a)]] if chain else []
        ctx.enrich({"Red": CRYPTO_NAMES.get(chain, "Desconocida"), "_links": links})
        if chain == "btc":
            await self._btc(ctx, a)
        elif chain == "eth":
            await self._eth(ctx, a)
        elif chain in ("ltc", "doge"):
            await self._blockchair(ctx, a, {"ltc": "litecoin", "doge": "dogecoin"}[chain], 1e8)

    async def _btc(self, ctx, a):
        st, d = await ctx.get_json(f"https://mempool.space/api/address/{a}")
        if st != 200 or not isinstance(d, dict):
            return
        cs = d.get("chain_stats") or {}
        bal = (cs.get("funded_txo_sum", 0) - cs.get("spent_txo_sum", 0)) / 1e8
        ctx.enrich({"Saldo": f"{bal:.8f} BTC", "Recibido total": f"{cs.get('funded_txo_sum', 0) / 1e8:.8f} BTC",
                    "Transacciones": cs.get("tx_count")})
        if not cs.get("tx_count"):
            return
        st, txs = await ctx.get_json(f"https://mempool.space/api/address/{a}/txs")
        if st != 200 or not isinstance(txs, list):
            return
        times = [t["status"]["block_time"] for t in txs if (t.get("status") or {}).get("block_time")]
        counter: dict[str, int] = {}
        for t in txs:
            addrs = {(v.get("prevout") or {}).get("scriptpubkey_address") for v in t.get("vin") or []}
            addrs |= {v.get("scriptpubkey_address") for v in t.get("vout") or []}
            for x in addrs:
                if x and x != a:
                    counter[x] = counter.get(x, 0) + 1
        if times:
            ctx.enrich({"Última actividad (muestra)": time.strftime("%Y-%m-%d", time.gmtime(max(times)))})
        for x, n in sorted(counter.items(), key=lambda kv: -kv[1])[:8]:
            ctx.add("crypto", x, {"Red": "Bitcoin", "Transacciones en común (muestra)": n,
                                  "_links": [["Explorador", EXPLORERS["btc"].format(x)]]},
                    rel=f"contraparte ×{n}", pivot=False)

    async def _eth(self, ctx, a):
        st, d = await ctx.get_json(f"https://api.ethplorer.io/getAddressInfo/{a}?apiKey=freekey")
        if st != 200 or not isinstance(d, dict) or d.get("error"):
            return
        tokens = [f"{(t.get('tokenInfo') or {}).get('symbol') or '?'}" for t in d.get("tokens") or []]
        ctx.enrich({
            "Saldo": f"{(d.get('ETH') or {}).get('balance', 0):.6f} ETH",
            "Transacciones": d.get("countTxs"),
            "Tokens": tokens[:40] or None,
            "Es contrato": "Sí" if d.get("contractInfo") else None,
        })

    async def _blockchair(self, ctx, a, chain, unit):
        st, d = await ctx.get_json(f"https://api.blockchair.com/{chain}/dashboards/address/{a}")
        data = ((d or {}).get("data") or {}).get(a) if isinstance(d, dict) else None
        if st != 200 or not data:
            return
        ad = data.get("address") or {}
        sym = chain[:4].upper() if chain != "litecoin" else "LTC"
        ctx.enrich({
            "Saldo": f"{(ad.get('balance') or 0) / unit:.8f} {sym}",
            "Recibido total": f"{(ad.get('received') or 0) / unit:.8f} {sym}",
            "Transacciones": ad.get("transaction_count"),
            "Primera actividad": (ad.get("first_seen_receiving") or "")[:10] or None,
            "Última actividad": (ad.get("last_seen_receiving") or "")[:10] or None,
        })


# ---------------------------------------------------------------------------
# Personas y dorks
# ---------------------------------------------------------------------------

def _ascii(s: str) -> str:
    return unicodedata.normalize("NFKD", s).encode("ascii", "ignore").decode().lower()


def username_candidates(full_name: str) -> list[str]:
    parts = [re.sub(r"[^a-z0-9]", "", _ascii(p)) for p in full_name.split()]
    parts = [p for p in parts if p]
    if len(parts) < 2:
        return parts
    f = parts[0]
    # En nombres hispanos de 4 partes el apellido principal es el penúltimo;
    # con 3 partes puede ser segundo nombre o dos apellidos, así que se prueban ambos.
    if len(parts) >= 4:
        surnames = [parts[-2], parts[-1]]
    elif len(parts) == 3:
        surnames = [parts[-1], parts[1]]
    else:
        surnames = [parts[-1]]
    c = []
    for l in surnames:
        c += [f + l, f + "." + l, f + "_" + l, f[0] + l, f[0] + "." + l, f + l[0], l + f, l + "." + f, l + f[0], f + "-" + l]
    if len(parts) >= 3:
        s1, s2 = parts[-2], parts[-1]
        c += [f + s1 + s2, f[0] + s1 + s2, f + s1[0] + s2[0], f[0] + s1 + s2[0], f + s1 + s2[0]]
    if len(parts) >= 4:
        m, s1, s2 = parts[1], parts[-2], parts[-1]
        c += [f[0] + m[0] + s1, f + m + s1, f[0] + m[0] + s1 + s2[0]]
    return list(dict.fromkeys(c))


@register
class PersonSearch(Module):
    name = "person_search"
    title = "Persona: usuarios probables"
    description = "Genera los nombres de usuario más probables a partir del nombre para investigarlos con un clic."
    inputs = ("person",)
    sources = ("Local",)

    async def run(self, ctx):
        ctx.enrich({"_candidatos": username_candidates(ctx.value)})


def _g(q: str) -> str:
    return f"https://www.google.com/search?q={quote_plus(q)}"


PASTE_SITES = " OR ".join(f"site:{s}" for s in (
    "pastebin.com", "rentry.co", "justpaste.it", "controlc.com", "paste.ee", "ghostbin.co", "dpaste.org",
    "throwbin.io", "pastes.io", "hastebin.com", "privatebin.net",
))


def _sites(*sites: str) -> str:
    return " OR ".join(f"site:{s}" for s in sites)


def _bing(q: str) -> str:
    return f"https://www.bing.com/search?q={quote_plus(q)}"


def _yandex(q: str) -> str:
    return f"https://yandex.com/search/?text={quote_plus(q)}"


def _ddg(q: str) -> str:
    return f"https://duckduckgo.com/?q={quote_plus(q)}"


CLOUD_SITES = _sites("drive.google.com", "docs.google.com", "1drv.ms", "onedrive.live.com", "dropbox.com",
                     "s3.amazonaws.com", "blob.core.windows.net", "storage.googleapis.com", "notion.site", "trello.com")
INTERNAL_SITES = _sites("atlassian.net", "postman.com", "swaggerhub.com", "app.swaggerhub.com", "readme.io",
                        "gitbook.io", "airtable.com", "miro.com", "figma.com")
DOC_SITES = _sites("scribd.com", "issuu.com", "slideshare.net", "calameo.com", "academia.edu", "researchgate.net",
                   "yumpu.com", "studocu.com")
CV_SITES = _sites("linkedin.com/in", "computrabajo.com", "laborum.cl", "bumeran.com.ar", "zonajobs.com.ar",
                  "trabajando.com", "indeed.com", "about.me")

# registros oficiales por país (código ISO del ajuste «país por defecto»)
REGIONAL = {
    "CL": [
        ["Chile · Diario Oficial", _sites("diariooficial.interior.gob.cl")],
        ["Chile · Mercado Público (licitaciones)", _sites("mercadopublico.cl")],
        ["Chile · Poder Judicial y causas", _sites("pjud.cl", "tribunalconstitucional.cl")],
        ["Chile · Transparencia (plantas y sueldos públicos)", _sites("portaltransparencia.cl", "transparencia.cl", "gob.cl") + " (planta OR contrata OR honorarios)"],
        ["Chile · Empresas y sociedades", _sites("tuempresaenundia.cl", "registrodeempresasysociedades.cl", "genealog.cl")],
        ["Chile · Congreso y Contraloría", _sites("bcn.cl", "camara.cl", "senado.cl", "contraloria.cl")],
    ],
    "AR": [
        ["Argentina · Boletín Oficial", _sites("boletinoficial.gob.ar")],
        ["Argentina · Compras públicas", _sites("comprar.gob.ar", "contrataciones.gob.ar")],
        ["Argentina · Poder Judicial", _sites("pjn.gov.ar", "csjn.gov.ar", "cij.gov.ar")],
        ["Argentina · Organismos públicos", _sites("argentina.gob.ar", "gob.ar")],
        ["Argentina · Boletines provinciales", _sites("boletinoficial.gba.gob.ar", "boletinoficial.cba.gov.ar", "boletinoficial.buenosaires.gob.ar")],
    ],
    "ES": [
        ["España · BOE y boletines", _sites("boe.es", "borme.es")],
        ["España · Empresas (BORME)", _sites("librebor.me", "infoempresa.com", "empresia.es")],
    ],
    "MX": [
        ["México · DOF", _sites("dof.gob.mx")],
        ["México · Compras y gobierno", _sites("compranet.hacienda.gob.mx", "gob.mx")],
    ],
}


def _regional(q: str) -> list[list[str]]:
    region = (settings.get("default_region") or "").upper()
    groups = REGIONAL.get(region) or (REGIONAL["CL"] + REGIONAL["AR"])
    return [[label, _g(f"{q} {sites}"), "Registros oficiales"] for label, sites in groups]


def dorks_for(t: str, v: str) -> list[list[str]]:
    """[etiqueta, url, grupo] de búsquedas preparadas para el dato."""
    q = f'"{v}"'
    out: list[list[str]] = []

    def add(group: str, *items):
        out.extend([label, url, group] for label, url in items)

    if t == "username":
        add("Básicos",
            ["Menciones exactas", _g(q)],
            ["En redes sociales", _g(f'{q} {_sites("twitter.com", "x.com", "instagram.com", "tiktok.com", "facebook.com", "threads.net")}')],
            ["En foros", _g(f'{q} inurl:forum OR inurl:thread OR inurl:member OR inurl:profile OR inurl:showthread')],
            ["Con email", _g(f'{q} "@gmail.com" OR "@hotmail.com" OR "@outlook.com" OR "@yahoo.com"')],
            ["Imágenes", f"https://www.google.com/search?tbm=isch&q={quote_plus(q)}"])
        add("Filtraciones y código",
            ["Pastes", _g(f"{q} {PASTE_SITES}")],
            ["Código", _g(f'{q} {_sites("github.com", "gist.github.com", "gitlab.com", "bitbucket.org")}')],
            ["Credenciales o combos", _g(f'{q} (password OR passwd OR contraseña OR "user:pass")')],
            ["Telegram", _g(f'{q} {_sites("t.me", "tgstat.com", "telemetr.io")}')])
        add("Poco comunes",
            ["Listas de juegos y Discord", _g(f'{q} {_sites("discord.me", "disboard.org", "top.gg", "steamcommunity.com", "namemc.com")}')],
            ["Tiendas y reseñas", _g(f'{q} {_sites("mercadolibre.cl", "mercadolibre.com.ar", "ebay.com", "etsy.com", "wallapop.com")}')],
            ["Música y creadores", _g(f'{q} {_sites("soundcloud.com", "bandcamp.com", "patreon.com", "ko-fi.com", "linktr.ee", "beacons.ai")}')],
            ["Citas y comunidades", _g(f'{q} {_sites("badoo.com", "tinder.com", "okcupid.com", "meetup.com")}')])
        add("Otros buscadores",
            ["Bing", _bing(q)], ["Yandex (mejor para alias y foros rusos)", _yandex(q)], ["DuckDuckGo", _ddg(q)])
    elif t == "email":
        user, _, dom = v.partition("@")
        add("Básicos",
            ["Menciones exactas", _g(q)],
            ["Sólo la parte local", _g(f'"{user}" -"{v}"')],
            ["En redes y perfiles", _g(f'{q} {_sites("facebook.com", "linkedin.com", "twitter.com", "x.com", "instagram.com")}')])
        add("Documentos y nube",
            ["Documentos", _g(f"{q} filetype:pdf OR filetype:xlsx OR filetype:docx OR filetype:csv OR filetype:txt")],
            ["Nube expuesta (Drive, OneDrive, S3…)", _g(f"{q} {CLOUD_SITES}")],
            ["Plataformas de documentos", _g(f"{q} {DOC_SITES}")],
            ["CV y empleo", _g(f"{q} {CV_SITES}")])
        add("Filtraciones y código",
            ["Pastes", _g(f"{q} {PASTE_SITES}")],
            ["Código y tableros", _g(f"{q} {_sites('github.com', 'gitlab.com', 'trello.com', 'bitbucket.org')}")],
            ["Herramientas internas (Jira, Postman…)", _g(f"{q} {INTERNAL_SITES}")],
            ["Con contraseña cerca", _g(f'{q} (password OR contraseña OR pass OR pwd)')])
        add("Otros buscadores", ["Bing", _bing(q)], ["Yandex", _yandex(q)], ["DuckDuckGo", _ddg(q)])
    elif t == "phone":
        digits = re.sub(r"\D", "", v)
        local = digits[-9:] if len(digits) > 9 else digits
        add("Básicos",
            ["Menciones", _g(f'"{v}" OR "{digits}" OR "{local}"')],
            ["Anuncios y perfiles", _g(f'"{local}" {_sites("facebook.com", "instagram.com", "linkedin.com", "mercadolibre.cl", "yapo.cl", "olx.com")}')],
            ["WhatsApp y Telegram públicos", _g(f'"{digits}" (wa.me OR "chat.whatsapp.com" OR t.me)')],
            ["Documentos", _g(f'"{local}" filetype:pdf OR filetype:xlsx OR filetype:csv')],
            ["Nube expuesta", _g(f'"{local}" {CLOUD_SITES}')])
        add("Otros buscadores", ["Bing", _bing(f'"{local}"')], ["Yandex", _yandex(f'"{local}"')])
    elif t == "domain":
        add("Básicos",
            ["Páginas indexadas", _g(f"site:{v}")],
            ["Subdominios", _g(f"site:*.{v} -site:www.{v}")],
            ["Emails del dominio", _g(f'"@{v}" -site:{v}')],
            ["Empleados en LinkedIn", _g(f'"{v}" site:linkedin.com/in')])
        add("Documentos y nube",
            ["Documentos expuestos", _g(f"site:{v} filetype:pdf OR filetype:docx OR filetype:xlsx OR filetype:pptx OR filetype:csv")],
            ["Documentos internos", _g(f'site:{v} (confidencial OR "uso interno" OR "internal use" OR confidential) filetype:pdf OR filetype:docx')],
            ["Nube expuesta (Drive, S3, Azure…)", _g(f'"{v}" {CLOUD_SITES}')],
            ["Plataformas de documentos", _g(f'"{v}" {DOC_SITES}')])
        add("Seguridad",
            ["Paneles de acceso", _g(f"site:{v} inurl:login OR inurl:admin OR inurl:panel OR intitle:login OR inurl:wp-admin")],
            ["Ficheros de configuración", _g(f"site:{v} ext:env OR ext:log OR ext:sql OR ext:bak OR ext:conf OR ext:ini OR ext:yml")],
            ["Listados de directorios", _g(f'site:{v} intitle:"index of"')],
            ["Errores y trazas", _g(f'site:{v} ("SQL syntax" OR "Warning: mysql" OR "stack trace" OR "Traceback" OR "Fatal error")')],
            ["APIs y Swagger", _g(f'site:{v} inurl:swagger OR inurl:api-docs OR inurl:graphql OR intitle:"Swagger UI"')],
            ["Herramientas internas filtradas", _g(f'"{v}" {INTERNAL_SITES}')],
            ["Secretos en código", _g(f'"{v}" (password OR api_key OR apikey OR secret OR token) {_sites("github.com", "gitlab.com", "gist.github.com")}')],
            ["Menciones en pastes", _g(f'"{v}" {PASTE_SITES}')])
        add("Otros buscadores", ["Bing", _bing(f"site:{v}")], ["Yandex", _yandex(f"site:{v}")])
    elif t == "person":
        add("Básicos",
            ["Menciones exactas", _g(q)],
            ["LinkedIn", _g(f"{q} site:linkedin.com/in")],
            ["Redes sociales", _g(f"{q} {_sites('facebook.com', 'instagram.com', 'twitter.com', 'x.com', 'tiktok.com', 'threads.net')}")],
            ["Imágenes", f"https://www.google.com/search?tbm=isch&q={quote_plus(q)}"],
            ["Noticias", f"https://www.google.com/search?tbm=nws&q={quote_plus(q)}"])
        add("Documentos y nube",
            ["Documentos y CV", _g(f"{q} filetype:pdf OR filetype:doc OR filetype:docx OR filetype:xlsx")],
            ["Currículum", _g(f'{q} ("curriculum vitae" OR currículum OR CV OR "experiencia laboral")')],
            ["CV y portales de empleo", _g(f"{q} {CV_SITES}")],
            ["Plataformas de documentos", _g(f"{q} {DOC_SITES}")],
            ["Nube expuesta", _g(f"{q} {CLOUD_SITES}")],
            ["Tesis y trabajos académicos", _g(f'{q} (tesis OR memoria OR "trabajo de título" OR thesis) filetype:pdf')],
            ["Su RUT en documentos públicos (Chile)", _g(f'{q} ("RUT" OR "R.U.T." OR "RUN") filetype:pdf OR filetype:xlsx OR filetype:xls OR filetype:csv')])
        add("Chile: Estado y justicia",
            ["Audiencias de lobby (como lobista o autoridad)", _g(f"{q} site:leylobby.gob.cl")],
            ["Declaraciones de patrimonio", _g(f"{q} site:infoprobidad.cl")],
            ["Causas judiciales publicadas", _g(f"{q} {_sites('pjud.cl', 'tribunalconstitucional.cl', 'diarioconstitucional.cl')}")],
            ["Diario Oficial (sociedades, notificaciones)", _g(f"{q} site:diariooficial.interior.gob.cl")],
            ["Sueldos y contratos públicos (Transparencia)", _g(f"{q} {_sites('portaltransparencia.cl', 'transparencia.gob.cl', 'mercadopublico.cl')}")],
            ["Tesis en repositorios chilenos", _g(f"{q} {_sites('repositorio.uchile.cl', 'repositorio.uc.cl', 'repositorio.usm.cl', 'repositorio.udec.cl', 'repositorio.uv.cl', 'bibliotecadigital.uach.cl')}")])
        variants = name_variants(v)
        if variants:
            anyq = " OR ".join(f'"{x}"' for x in [v] + variants[:4])
            group = "Variantes del nombre (coincidencias parciales)"
            add(group,
                ["Todas las variantes a la vez", _g(anyq)],
                ["LinkedIn con cualquier variante", _g(f"({anyq}) site:linkedin.com/in")],
                ["Facebook e Instagram con cualquier variante", _g(f"({anyq}) {_sites('facebook.com', 'instagram.com')}")])
            for x in variants[:4]:
                add(group, [f"«{x}» en redes", _g(f'"{x}" {_sites("linkedin.com/in", "facebook.com", "instagram.com", "x.com", "tiktok.com")}')])
        out.extend(_regional(q))
        add("Otros buscadores",
            ["Bing", _bing(q)], ["Yandex (mejor para caras y nombres)", _yandex(q)], ["DuckDuckGo", _ddg(q)])
    elif t == "rut":
        from .chile import rut_parts

        num, dv = rut_parts(v)
        forms = f'"{v}" OR "{num}-{dv}" OR "{num}{dv}"'
        add("Básicos",
            ["Menciones (todas las formas de escribirlo)", _g(forms)],
            ["Documentos (PDF, Excel, Word)", _g(f"({forms}) filetype:pdf OR filetype:xlsx OR filetype:xls OR filetype:docx OR filetype:csv")],
            ["Nube expuesta", _g(f"({forms}) {CLOUD_SITES}")])
        add("Registros oficiales",
            ["Poder Judicial y Tribunal Constitucional", _g(f"({forms}) {_sites('pjud.cl', 'tribunalconstitucional.cl', 'tdlc.cl')}")],
            ["Diario Oficial (sociedades, notificaciones)", _g(f"({forms}) {_sites('diariooficial.interior.gob.cl')}")],
            ["Mercado Público y compras del Estado", _g(f"({forms}) {_sites('mercadopublico.cl', 'chilecompra.cl')}")],
            ["Transparencia, plantas y sueldos públicos", _g(f"({forms}) {_sites('portaltransparencia.cl', 'transparencia.cl', 'gob.cl')}")],
            ["Empresas (registro, CMF, SII)", _g(f"({forms}) {_sites('registrodeempresasysociedades.cl', 'tuempresaenundia.cl', 'cmfchile.cl', 'sii.cl')}")],
            ["Universidades y colegios (listas, resultados)", _g(f"({forms}) site:cl (lista OR nómina OR seleccionados OR resultados)")])
        add("Otros buscadores", ["Bing", _bing(forms)], ["DuckDuckGo", _ddg(forms)])
    elif t == "plate":
        from .chile import plate_display

        shown = plate_display(v)
        dashed = shown.replace("·", "-")
        forms = f'"{v}" OR "{dashed}" OR "{shown.replace("·", " ")}"'
        add("Básicos",
            ["Menciones de la patente", _g(forms)],
            ["Avisos de venta (Chileautos, MercadoLibre, Yapo…)", _g(f"({forms}) {_sites('chileautos.cl', 'mercadolibre.cl', 'autos.mercadolibre.cl', 'yapo.cl', 'autocosmos.cl', 'olx.cl')}")],
            ["En redes (grupos, denuncias, robos)", _g(f"({forms}) {_sites('facebook.com', 'instagram.com', 'x.com', 'twitter.com', 'tiktok.com')}")],
            ["Robos y denuncias", _g(f"({forms}) (robado OR robada OR encargo OR portonazo OR denuncia)")],
            ["Imágenes", f"https://www.google.com/search?tbm=isch&q={quote_plus(forms)}"])
        add("Sitios no oficiales (verifica lo que digan)",
            ["Buscadores de patentes", _g(f"({forms}) {_sites('patentechile.com', 'volanteomaleta.com', 'autofact.cl')}")])
    elif t == "ip":
        add("Básicos", ["Menciones", _g(q)], ["Censys", f"https://search.censys.io/hosts/{v}"],
            ["Shodan", f"https://www.shodan.io/host/{v}"], ["En pastes y listas negras", _g(f"{q} {PASTE_SITES} OR site:abuseipdb.com")])
    elif t == "url":
        add("Básicos", ["Enlaces a la URL", _g(q)], ["Archive.today", f"https://archive.ph/{v}"],
            ["Wayback", f"https://web.archive.org/web/*/{v}"])
    elif t == "crypto":
        add("Básicos", ["Menciones", _g(q)],
            ["En foros y pastes", _g(f"{q} site:bitcointalk.org OR site:reddit.com OR {PASTE_SITES}")],
            ["Donaciones en perfiles", _g(f'{q} (donate OR donación OR tip) {_sites("github.com", "twitter.com", "x.com")}')])
    else:
        add("Básicos", ["Menciones", _g(q)])
    return out


@register
class Dorks(Module):
    name = "dorks"
    title = "Dorks de búsqueda"
    description = "Búsquedas avanzadas de Google preparadas para el objetivo (se abren en tu navegador)."
    inputs = ("username", "email", "phone", "domain", "person", "ip", "url", "crypto", "rut", "plate")
    sources = ("Local",)

    async def run(self, ctx):
        ent = db.update_attrs(ctx.case_id, ctx.entity["id"], {"_dorks": dorks_for(ctx.entity["type"], ctx.value)},
                              replace=True)
        if ent:
            ctx.job.emit({"type": "entity", "entity": ent, "created": False})
            ctx.enriched = True
