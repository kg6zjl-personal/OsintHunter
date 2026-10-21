"""Metadatos de documentos publicados por un dominio (estilo FOCA): autores, usuarios internos y software."""
import asyncio
import io
import json
import re
import unicodedata
import zipfile
import xml.etree.ElementTree as ET
from collections import Counter
from urllib.parse import unquote, urlparse

import httpx

from ..util import EMAIL_RE
from .chile import find_ruts
from .base import Module, register

DOC_MIME = r"application/(pdf|msword|vnd\.ms-excel|vnd\.ms-powerpoint|vnd\.openxmlformats-officedocument\..*)"
EXT_BY_MIME = {
    "application/pdf": "pdf", "application/msword": "doc", "application/vnd.ms-excel": "xls",
    "application/vnd.ms-powerpoint": "ppt",
}
MAX_DOCS = 30
MAX_BYTES = 20 * 1024 * 1024

# autores genéricos que no identifican a nadie
GENERIC_AUTHORS = {
    "admin", "administrator", "administrador", "user", "usuario", "owner", "propietario", "default", "unknown",
    "author", "autor", "test", "pc", "hp", "dell", "lenovo", "acer", "asus", "windows user", "usuario de windows",
    "microsoft office user", "usuario de microsoft office", "utilisateur", "guest", "invitado", "home", "casa",
    "oficina", "office", "compaq", "toshiba", "samsung", "sony", "pc1", "user1", "usuario1", "",
}


def _ext(url: str, mime: str) -> str:
    path = urlparse(url).path.lower()
    m = re.search(r"\.(pdf|docx?|xlsx?|pptx?)$", path)
    if m:
        return m.group(1)
    if "wordprocessingml" in mime:
        return "docx"
    if "spreadsheetml" in mime:
        return "xlsx"
    if "presentationml" in mime:
        return "pptx"
    return EXT_BY_MIME.get(mime, "pdf")


def _pdf_date(v) -> str | None:
    m = re.search(r"(\d{4})(\d{2})(\d{2})", str(v or ""))
    return f"{m.group(1)}-{m.group(2)}-{m.group(3)}" if m else None


def _clean(v) -> str | None:
    if v is None:
        return None
    s = re.sub(r"\s+", " ", str(v)).strip().strip("\x00").strip()
    return s or None


def meta_pdf(data: bytes) -> dict:
    from pypdf import PdfReader

    r = PdfReader(io.BytesIO(data), strict=False)
    if r.is_encrypted:
        try:
            r.decrypt("")
        except Exception:  # noqa: BLE001
            return {}
    m = r.metadata or {}
    out = {
        "author": _clean(m.get("/Author")), "creator_tool": _clean(m.get("/Creator")),
        "producer": _clean(m.get("/Producer")), "title": _clean(m.get("/Title")),
        "created": _pdf_date(m.get("/CreationDate")), "modified": _pdf_date(m.get("/ModDate")),
        "company": _clean(m.get("/Company")), "last_modified_by": _clean(m.get("/LastModifiedBy")),
    }
    try:
        x = r.xmp_metadata
        if x is not None:
            if not out["author"] and x.dc_creator:
                out["author"] = _clean(", ".join(x.dc_creator))
            out["creator_tool"] = out["creator_tool"] or _clean(x.xmp_creator_tool)
    except Exception:  # noqa: BLE001
        pass
    parts = []
    for page in r.pages[:8]:
        try:
            parts.append(page.extract_text() or "")
        except Exception:  # noqa: BLE001
            break
    out["text"] = "\n".join(parts)[:200_000]
    return out


OOXML_TEXT_PARTS = re.compile(r"^(word/document\.xml|xl/sharedStrings\.xml|ppt/slides/slide\d+\.xml)$")


def _ooxml_text(z: zipfile.ZipFile) -> str:
    parts = []
    for n in [n for n in z.namelist() if OOXML_TEXT_PARTS.match(n)][:30]:
        xml = z.read(n).decode("utf-8", "replace")
        parts.append(re.sub(r"<[^>]+>", " ", re.sub(r"</w:p>|</a:p>|</si>", "\n", xml)))
    return " ".join(parts)[:200_000]


NS = {
    "cp": "http://schemas.openxmlformats.org/package/2006/metadata/core-properties",
    "dc": "http://purl.org/dc/elements/1.1/",
    "dcterms": "http://purl.org/dc/terms/",
    "ep": "http://schemas.openxmlformats.org/officeDocument/2006/extended-properties",
}


def meta_ooxml(data: bytes) -> dict:
    z = zipfile.ZipFile(io.BytesIO(data))
    out: dict = {}
    if "docProps/core.xml" in z.namelist():
        core = ET.fromstring(z.read("docProps/core.xml"))
        g = lambda p: _clean(core.findtext(p, namespaces=NS))  # noqa: E731
        out.update({"author": g("dc:creator"), "last_modified_by": g("cp:lastModifiedBy"), "title": g("dc:title"),
                    "created": (g("dcterms:created") or "")[:10] or None,
                    "modified": (g("dcterms:modified") or "")[:10] or None})
    if "docProps/app.xml" in z.namelist():
        app = ET.fromstring(z.read("docProps/app.xml"))
        g = lambda p: _clean(app.findtext(f"ep:{p}", namespaces=NS))  # noqa: E731
        tool = g("Application")
        if tool and g("AppVersion"):
            tool = f"{tool} {g('AppVersion')}"
        out.update({"creator_tool": tool, "company": g("Company"), "manager": g("Manager"), "template": g("Template")})
    try:
        out["text"] = _ooxml_text(z)
    except Exception:  # noqa: BLE001
        pass
    return out


def meta_ole(data: bytes) -> dict:
    import olefile

    ole = olefile.OleFileIO(io.BytesIO(data))
    try:
        m = ole.get_metadata()
    finally:
        ole.close()
    dec = lambda v: _clean(v.decode("latin-1", "replace") if isinstance(v, bytes) else v)  # noqa: E731
    date = lambda v: v.strftime("%Y-%m-%d") if hasattr(v, "strftime") else None  # noqa: E731
    return {
        "author": dec(m.author), "last_modified_by": dec(m.last_saved_by), "title": dec(m.title),
        "creator_tool": dec(m.creating_application), "company": dec(m.company), "manager": dec(m.manager),
        "template": dec(m.template), "created": date(m.create_time), "modified": date(m.last_saved_time),
    }


def extract(data: bytes, ext: str) -> dict:
    try:
        if data[:5] == b"%PDF-":
            return meta_pdf(data)
        if data[:2] == b"PK":
            return meta_ooxml(data)
        if data[:8] == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1":
            return meta_ole(data)
    except Exception:  # noqa: BLE001  documentos corruptos o raros: se ignoran
        return {}
    return {}


COMPANY_RE = re.compile(r"\b(limitada|ltda|spa|s\.?a\.?|s\.?r\.?l\.?|inc|llc|ltd|gmbh|corp|eirl|consultores|"
                        r"asociados|ministerio|municipalidad|universidad|servicio|subsecretar[ií]a)\b\.?", re.I)


def _fold(s: str) -> str:
    return unicodedata.normalize("NFKD", s).encode("ascii", "ignore").decode().lower()


def classify_author(s: str) -> tuple[str, str] | None:
    """('person'|'organization'|'username'|'email', valor) o None si el autor es genérico."""
    s = s.strip().strip("'\"")
    if not s or s.lower() in GENERIC_AUTHORS or len(s) > 60:
        return None
    if COMPANY_RE.search(s):
        return "organization", s
    if re.search(r"microsoft|office|adobe|writer|word|excel|acrobat|pdf|printer|impresora|scanner|canon|xerox|ricoh", s, re.I):
        return None
    em = EMAIL_RE.search(s)
    if em:
        return "email", em.group(0).lower()
    if "\\" in s:  # DOMINIO\usuario
        s = s.split("\\")[-1]
    tokens = s.split()
    if len(tokens) >= 2 and all(re.fullmatch(r"[A-Za-zÁÉÍÓÚÜÑáéíóúüñ.'\-]+", t) for t in tokens) and len(tokens) <= 5:
        return "person", " ".join(t.capitalize() if t.isupper() or t.islower() else t for t in tokens)
    if len(tokens) == 1 and re.fullmatch(r"[A-Za-z][\w.\-]{2,30}", s) and not s.isdigit():
        return "username", s.lower()
    return None


@register
class DocMetadata(Module):
    name = "doc_metadata"
    title = "Metadatos de documentos"
    description = ("Busca PDF, Word, Excel y PowerPoint publicados por el dominio (vía Internet Archive y Common "
                   "Crawl), los descarga y extrae autores, usuarios internos, empresa y software usado")
    inputs = ("domain",)
    sources = ("web.archive.org", "index.commoncrawl.org")
    timeout = 240

    async def run(self, ctx):
        domain = ctx.value.lower()
        docs = await self._find_wayback(ctx, domain)
        source = "Internet Archive"
        if not docs:
            docs = await self._find_commoncrawl(ctx, domain)
            source = "Common Crawl"
        if not docs:
            ctx.message = "No se encontraron documentos publicados en este dominio"
            return

        sem = asyncio.Semaphore(4)

        async def fetch(doc):
            async with sem:
                for url in doc["fetch"]:
                    try:
                        async with ctx.http.stream("GET", url, timeout=45) as r:
                            if r.status_code != 200:
                                continue
                            buf = bytearray()
                            async for chunk in r.aiter_bytes():
                                buf += chunk
                                if len(buf) > MAX_BYTES:
                                    break
                            if len(buf) > MAX_BYTES:
                                return doc, None
                            return doc, bytes(buf)
                    except httpx.HTTPError:
                        continue
            return doc, None

        results = await asyncio.gather(*(fetch(d) for d in docs))
        analysed = []
        for doc, data in results:
            if not data:
                continue
            meta = await asyncio.to_thread(extract, data, doc["ext"])
            if any(meta.values()):
                analysed.append((doc, meta))
        if not analysed:
            ctx.message = f"{len(docs)} documentos encontrados en {source}, pero ninguno se pudo descargar o no tenían metadatos"
            return

        people: dict[str, list[str]] = {}
        users: dict[str, list[str]] = {}
        emails: dict[str, list[str]] = {}
        tools, companies = Counter(), Counter()
        ruts: dict[str, dict] = {}
        dates = []
        shown: dict[str, str] = {}  # nombre sin tildes -> forma a mostrar (la que lleva tildes si existe)
        domain_label = domain.split(".")[0]
        for doc, meta in analysed:
            name = unquote(urlparse(doc["url"]).path.rsplit("/", 1)[-1])[:80] or doc["url"]
            for field in ("author", "last_modified_by", "manager"):
                for part in re.split(r"[;,]| y | and ", meta.get(field) or ""):
                    c = classify_author(part)
                    if not c:
                        continue
                    kind, value = c
                    if kind == "organization":
                        companies[value] += 1
                        continue
                    if kind == "username" and value == domain_label:
                        continue
                    if kind == "person":
                        key = _fold(value)
                        if key not in shown or value.lower() != key:
                            shown[key] = value
                        value = key
                    bucket = {"person": people, "username": users, "email": emails}[kind]
                    bucket.setdefault(value, [])
                    if name not in bucket[value]:
                        bucket[value].append(name)
            for k in ("creator_tool", "producer"):
                if meta.get(k):
                    tools[meta[k]] += 1
            if meta.get("company"):
                companies[meta["company"]] += 1
            for rut, context in find_ruts(meta.get("text") or "", limit=60):
                entry = ruts.setdefault(rut, {"files": [], "context": []})
                if name not in entry["files"]:
                    entry["files"].append(name)
                    entry["context"].append(f"{name}: …{context}…")
            dates += [d for d in (meta.get("created"), meta.get("modified")) if d and d[:4].isdigit() and 1990 < int(d[:4]) < 2100]
        people = {shown[k]: v for k, v in people.items()}

        for value, files in people.items():
            ctx.add("person", value, {"Documentos firmados": files[:15]}, rel="autor de documentos", pivot=False)
        for value, files in users.items():
            ctx.add("username", value, {"Aparece en documentos": files[:15], "Origen": "Usuario interno en metadatos"},
                    rel="usuario en metadatos", pivot=False)
        for value, files in emails.items():
            ctx.add("email", value, {"Aparece en documentos": files[:15]}, rel="email en metadatos", pivot=False)
        for rut, entry in sorted(ruts.items(), key=lambda kv: -len(kv[1]["files"]))[:80]:
            ctx.add("rut", rut, {"Aparece en documentos": entry["files"][:15], "Contexto en documentos": entry["context"][:5]},
                    rel="RUT en documentos", pivot=False)
        for company in companies:
            if company.lower() not in GENERIC_AUTHORS and len(company) > 2:
                ctx.add("organization", company, {"Documentos": companies[company]}, rel="empresa en metadatos", pivot=False)

        ctx.enrich({
            "Documentos analizados": len(analysed),
            "Software de los documentos": [f"{t} ({n})" for t, n in tools.most_common(10)] or None,
            "Autores en metadatos": sorted(people) or None,
            "Usuarios internos en metadatos": sorted(users) or None,
            "Periodo de los documentos": f"{min(dates)} → {max(dates)}" if dates else None,
            "_links": [[f"Doc: {unquote(urlparse(d['url']).path.rsplit('/', 1)[-1])[:60]}", d["view"]] for d, _ in analysed[:12]],
        })
        ctx.message = (f"{len(analysed)} documentos analizados ({source}) · {len(people)} autores · "
                       f"{len(users)} usuarios internos · {len(emails)} emails · {len(ruts)} RUT")

    async def _find_wayback(self, ctx, domain: str) -> list[dict]:
        try:
            st, rows = await ctx.get_json("https://web.archive.org/cdx/search/cdx", timeout=75, params={
                "url": domain, "matchType": "domain", "output": "json", "fl": "original,mimetype,timestamp",
                "filter": [f"mimetype:{DOC_MIME}", "statuscode:200"], "collapse": "urlkey", "limit": "400",
            })
        except httpx.HTTPError:
            return []
        if st != 200 or not isinstance(rows, list) or len(rows) < 2:
            return []
        rows = sorted(rows[1:], key=lambda r: r[2], reverse=True)
        return self._pick([{
            "url": url, "ext": _ext(url, mime),
            "fetch": [f"https://web.archive.org/web/{ts}id_/{url}", url],
            "view": f"https://web.archive.org/web/{ts}/{url}",
        } for url, mime, ts in rows])

    async def _find_commoncrawl(self, ctx, domain: str) -> list[dict]:
        try:
            st, colls = await ctx.get_json("https://index.commoncrawl.org/collinfo.json", timeout=20)
            if st != 200 or not colls:
                return []
            api = colls[0]["cdx-api"]
            r = await ctx.http.get(api, timeout=75, params={
                "url": f"*.{domain}", "output": "json", "filter": ["mime:application/(pdf|msword|vnd\\..*)", "status:200"],
                "limit": "300",
            })
        except (httpx.HTTPError, KeyError, IndexError):
            return []
        if r.status_code != 200:
            return []
        rows = []
        for line in r.text.splitlines():
            try:
                rows.append(json.loads(line))
            except ValueError:
                continue
        seen, docs = set(), []
        for x in rows:
            url = x.get("url")
            if not url or url in seen:
                continue
            seen.add(url)
            docs.append({"url": url, "ext": _ext(url, x.get("mime", "")), "fetch": [url], "view": url})
        return self._pick(docs)

    @staticmethod
    def _pick(docs: list[dict]) -> list[dict]:
        """Hasta MAX_DOCS, repartidos entre formatos para no quedarse sólo con PDF."""
        by_ext: dict[str, list[dict]] = {}
        for d in docs:
            by_ext.setdefault(d["ext"], []).append(d)
        out: list[dict] = []
        while len(out) < MAX_DOCS and any(by_ext.values()):
            for ext in list(by_ext):
                if by_ext[ext] and len(out) < MAX_DOCS:
                    out.append(by_ext[ext].pop(0))
        return out
