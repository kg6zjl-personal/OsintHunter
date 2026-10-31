"""Fuentes públicas chilenas con datos descargables: InfoProbidad, Registro de Empresas y Sociedades, tesis."""

import asyncio
import csv
import io
import json
import re
import sqlite3
import time
from collections import defaultdict

import httpx

from ..config import DATA_DIR
from .base import Module, Skip, register as _register
from ..config import settings

def register(cls):
    if settings.chile_enabled():
        return _register(cls)
    return cls

from .chile import rut_fmt, rut_parts
from .people import name_match, name_variants, same_name, tokens

UA = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Safari/537.36"}
RESERVED = {"", "RESERVADO", "NO APLICA", "NINGUNO", "NINGUNA", "0"}


def _ok(v) -> bool:
    return isinstance(v, str) and v.strip().upper() not in RESERVED


def _name(d: dict | None) -> str | None:
    return (d or {}).get("nombre") if isinstance(d, dict) else None


def _date(s: str | None) -> str | None:
    m = re.match(r"(\d{4})[/-](\d{2})[/-](\d{2})", s or "")
    return f"{m.group(3)}-{m.group(2)}-{m.group(1)}" if m and m.group(1) != "0001" else None


def _title(s: str) -> str:
    small = {"de", "del", "y", "e"}
    return " ".join(w.lower() if w.lower() in small and i else w.capitalize() for i, w in enumerate((s or "").split()))


# ---------------------------------------------------------------- InfoProbidad

IP_LIST = "https://www.infoprobidad.cl/Home/Listado"
IP_JSON = "https://www.infoprobidad.cl/Declaracion/descargarDeclaracionJSon"
IP_PAGE = "https://www.infoprobidad.cl/Declaracion/Declaracion?ID={}"
_ip_lock = asyncio.Lock()
_ip_cache: tuple[float, list] | None = None


async def infoprobidad_index(http) -> list[dict]:
    """Listado completo de declaraciones (≈120.000); se descarga una vez por semana."""
    global _ip_cache
    async with _ip_lock:
        if _ip_cache and time.time() - _ip_cache[0] < 3600:
            return _ip_cache[1]
        path = DATA_DIR / "infoprobidad.json"
        if not path.exists() or time.time() - path.stat().st_mtime > 7 * 86400:
            try:
                r = await http.get(IP_LIST, headers=UA, timeout=180)
                start = r.text.find("[", r.text.find("var datos ="))
                rows, _ = json.JSONDecoder().raw_decode(r.text, start)
                keep = ("IdDeclaracion", "FechaDeclaracion", "TipoDeclaracion", "Nombres", "ApellidoPaterno",
                        "ApellidoMaterno", "ServicioEntidad", "Cargo")
                path.write_text(json.dumps([{k: d.get(k) for k in keep} for d in rows], ensure_ascii=False),
                                encoding="utf-8")
            except Exception:
                if not path.exists():
                    raise
        rows = json.loads(path.read_text(encoding="utf-8"))
        for d in rows:
            d["_full"] = " ".join(x for x in (d.get("Nombres"), d.get("ApellidoPaterno"), d.get("ApellidoMaterno")) if x)
            d["_tok"] = tokens(d["_full"])
        _ip_cache = (time.time(), rows)
        return rows


def _razones(obj, out: list, path: str = ""):
    """Recorre la declaración y junta toda entidad con razón social (empresas, empleadores, sociedades)."""
    if isinstance(obj, dict):
        razon = next((v for k, v in obj.items() if "Razon_Social" in k and _ok(v)), None)
        if razon:
            rut = obj.get("RUT") or obj.get("Rut") or obj.get("RUT_Sociedad")
            rubro = _name(obj.get("Rubro")) or _name(obj.get("Titulo_Documento")) or _name(obj.get("Tipo_Obligacion_Deuda"))
            out.append((razon.strip(), rut if _ok(rut) else None, rubro, path))
        for k, v in obj.items():
            _razones(v, out, k if not path else path)
    elif isinstance(obj, list):
        for x in obj:
            _razones(x, out, path)


SECTION_REL = {
    "Actividades_Profesionales_A_La_Fecha": "trabaja en (InfoProbidad)",
    "Actividades_Profesionales_Ultimos_12_Meses": "trabajó en (InfoProbidad)",
    "Actividades_Profesionales_Conyuge": "cónyuge trabaja en (InfoProbidad)",
    "Derechos_Acciones_Chile": "socio o accionista (InfoProbidad)",
    "Acciones_Derechos_Chile": "socio o accionista (InfoProbidad)",
    "Instrumentos_Valor_TransableChile": "inversiones en (InfoProbidad)",
    "Pasivos": "deuda con (InfoProbidad)",
    "Patrimonio_Conyuge": "cónyuge relacionado con (InfoProbidad)",
}


@register
class InfoProbidad(Module):
    name = "infoprobidad"
    title = "InfoProbidad (declaraciones de patrimonio, Chile)"
    description = ("Funcionarios, autoridades y candidatos chilenos: cargo, institución, cónyuge, empresas, "
                   "propiedades, vehículos y deudas según su declaración de patrimonio e intereses")
    inputs = ("person",)
    sources = ("infoprobidad.cl",)
    timeout = 240

    async def run(self, ctx):
        name = ctx.value.strip()
        qt = tokens(name)
        if len(qt) < 2:
            raise Skip("Hace falta nombre y apellido")
        rows = await infoprobidad_index(ctx.http)
        exact, compatible, similar = defaultdict(list), defaultdict(list), defaultdict(list)
        variants = name_variants(name)
        for d in rows:
            dt = d["_tok"]
            if dt == qt or (len(qt) >= 3 and set(qt) <= set(dt) and dt[0] == qt[0]):
                exact[d["_full"]].append(d)
            elif same_name(name, d["_full"]):
                compatible[d["_full"]].append(d)
            elif name_match(d["_full"], name, variants):
                similar[d["_full"]].append(d)
        if not exact and len(compatible) == 1:
            exact = compatible
        else:
            similar.update(compatible)
        if not exact and not similar:
            ctx.message = f"No aparece entre las {len(rows):,} declaraciones".replace(",", ".")
            return
        if similar:
            items = sorted(similar.items(), key=lambda kv: -len(kv[1]))[:15]
            ctx.enrich({"InfoProbidad: nombres parecidos": [
                f"{_title(n)} · {_title(ds[-1]['Cargo'])} · {_title(ds[-1]['ServicioEntidad'])} ({ds[-1]['FechaDeclaracion'][:4]})"
                for n, ds in items]})
        if len(exact) > 3:
            ctx.enrich({"InfoProbidad: homónimos": [f"{_title(n)} · {_title(ds[-1]['Cargo'])}" for n, ds in exact.items()]})
            ctx.message = f"{len(exact)} declarantes con ese nombre: agrega el segundo apellido para distinguirlos"
            return
        for full, decls in exact.items():
            decls.sort(key=lambda d: d["FechaDeclaracion"] or "")
            await self._declarant(ctx, full, decls, own=len(exact) == 1)
        ctx.message = (f"{sum(len(v) for v in exact.values())} declaraciones de {len(exact)} persona(s)"
                       + (f" · {len(similar)} con nombre parecido" if similar else ""))

    async def _declarant(self, ctx, full, decls, own):
        last = decls[-1]
        cargos = list(dict.fromkeys(f"{_title(d['Cargo'])} — {_title(d['ServicioEntidad'])} ({(d['FechaDeclaracion'] or '')[:4]})"
                                    for d in reversed(decls)))
        pid = ctx.entity["id"] if own else ctx.add("person", _title(full), {"Fuente": "InfoProbidad"},
                                                    rel="mismo nombre (InfoProbidad)", pivot=False)
        if not pid:
            return
        r = await ctx.http.post(IP_JSON, data={"ID": last["IdDeclaracion"]}, headers=UA, timeout=60)
        try:
            dec = r.json()
        except ValueError:
            dec = {}
        who = dec.get("Datos_del_Declarante") or {}
        ent = dec.get("Datos_Entidad_Por_La_Que_Declara") or {}
        vehicles = [" ".join(x for x in (_name(v.get("Tipo_Vehiculo")), _name(v.get("Marca")), v.get("Modelo"),
                                         v.get("Annio_Fabricacion")) if _ok(x))
                    for v in dec.get("Vehiculos_Motorizados") or []]
        pas = dec.get("Pasivos") or {}
        ctx.enrich({
            "Cargo (InfoProbidad)": f"{_title(last['Cargo'])} — {_title(last['ServicioEntidad'])}",
            "Historial de cargos": cargos[:20],
            "Profesión": _title(_name(who.get("Profesion_Oficio")) or ""),
            "Estado civil": _title(_name(who.get("Estado_Civil")) or ""),
            "Renta o grado": ent.get("Grado_Renta_Mensual") if _ok(ent.get("Grado_Renta_Mensual")) else None,
            "Asumió el cargo": _date(ent.get("Fecha_Asuncion_Cargo")),
            "Comuna declarada": _title(", ".join(x for x in (_name(who.get("Comuna")), _name(who.get("Region"))) if x)),
            "Vehículos declarados": [_title(v) for v in vehicles if v],
            "Deudas declaradas": f"${int(pas['Monto_Global_Pesos']):,}".replace(",", ".") if str(pas.get("Monto_Global_Pesos", "")).isdigit() and int(pas["Monto_Global_Pesos"]) else None,
            "_links": [["Declaración en InfoProbidad", IP_PAGE.format(last["IdDeclaracion"])]]
                      + [[f"Declaración {d['FechaDeclaracion'][:10]}", IP_PAGE.format(d["IdDeclaracion"])] for d in reversed(decls[:-1][-5:])],
        }, eid=pid)
        ctx.found += 1
        if rut_parts(who.get("RUN") or ""):
            ctx.add("rut", who["RUN"], {"Fuente": "InfoProbidad"}, rel="RUT (InfoProbidad)", parent=pid, pivot=False)
        org = ctx.add("organization", _title(last["ServicioEntidad"]), {"Tipo": "Institución pública"},
                      rel=f"{_title(last['Cargo']).lower()} (InfoProbidad)", parent=pid, pivot=False)
        spouse = dec.get("Datos_del_Conyuge") or {}
        sname = " ".join(x for x in (spouse.get("nombre"), spouse.get("Apellido_Paterno"), spouse.get("Apellido_Materno")) if _ok(x))
        sid = None
        if len(sname.split()) >= 2:
            sid = ctx.add("person", _title(sname), {"Fuente": "InfoProbidad"}, rel="cónyuge (InfoProbidad)", parent=pid, pivot=False)
        for prop in (dec.get("Bienes_Inmuebles_Situados_En_Chile") or [])[:15]:
            addr = ", ".join(x for x in (prop.get("Direccion"), _name(prop.get("Comuna")), _name(prop.get("Region"))) if _ok(x))
            if addr and _ok(prop.get("Direccion")):
                ctx.add("location", _title(addr) + ", Chile", {"Rol de avalúo": prop.get("Rol_Avaluo"),
                                                               "Inscripción": prop.get("Annio")},
                        rel="propiedad declarada (InfoProbidad)", parent=pid, pivot=False)
        found: list = []
        _razones(dec, found)
        seen = set()
        for razon, rut, rubro, section in found:
            key = razon.lower()
            if key in seen or (org and key == _title(last["ServicioEntidad"]).lower()):
                continue
            seen.add(key)
            # trabajo independiente: la «razón social» es la propia persona o su cónyuge, y el RUT es el personal
            rt = set(tokens(razon))
            owner = (pid if len(rt) >= 2 and rt <= set(tokens(full))
                     else sid if sid and len(rt) >= 2 and rt <= set(tokens(sname)) else None)
            if owner:
                if rut and rut_parts(rut):
                    ctx.add("rut", rut, {"Fuente": "InfoProbidad"}, rel="RUT (InfoProbidad)", parent=owner, pivot=False)
                continue
            attrs = {"RUT": rut_fmt(*rut_parts(rut)) if rut and rut_parts(rut) else None, "Rubro": _title(rubro or "")}
            oid = ctx.add("organization", razon, attrs, rel=SECTION_REL.get(section, "relacionado (InfoProbidad)"),
                          parent=pid, pivot=False)
            if oid and rut and rut_parts(rut):
                ctx.add("rut", rut, {}, rel="RUT", parent=oid, pivot=False)


# ---------------------------------------------------------------- Registro de Empresas y Sociedades

RES_DATASET = "https://datos.gob.cl/api/3/action/package_show?id=363edd60-4919-4ff1-b85f-f8e14d61285a"
_res_lock = asyncio.Lock()


def _res_db() -> sqlite3.Connection:
    con = sqlite3.connect(DATA_DIR / "empresas_cl.db")
    con.executescript("""
        CREATE TABLE IF NOT EXISTS archivo (n INTEGER PRIMARY KEY, id TEXT UNIQUE, modificado TEXT);
        CREATE TABLE IF NOT EXISTS actuacion (rut INTEGER, dv TEXT, razon TEXT, tipo TEXT, actuacion TEXT,
            fecha TEXT, comuna TEXT, capital INTEGER, archivo INTEGER);
        CREATE INDEX IF NOT EXISTS ix_rut ON actuacion(rut);
        CREATE VIRTUAL TABLE IF NOT EXISTS razon_fts USING fts5(razon, content='actuacion', content_rowid='rowid',
            tokenize='unicode61 remove_diacritics 2');
    """)
    return con


def _search(con, query: str, limit: int) -> list[tuple[int, str]]:
    return con.execute("SELECT a.rut, a.razon FROM razon_fts JOIN actuacion a ON a.rowid = razon_fts.rowid "
                       "WHERE razon_fts MATCH ? LIMIT ?", (query, limit)).fetchall()


async def empresas_ready(http) -> tuple[sqlite3.Connection, list[str]]:
    """Descarga (una vez) los archivos anuales del Registro de Empresas y Sociedades a una base local."""
    async with _res_lock:
        con = _res_db()
        have = dict(con.execute("SELECT id, modificado FROM archivo"))
        checked = have.get("_check")
        if checked and checked >= time.strftime("%Y-%m-%d", time.localtime(time.time() - 7 * 86400)):
            return con, []
        try:
            r = await http.get(RES_DATASET, headers=UA, timeout=60)
            resources = [x for x in r.json()["result"]["resources"] if (x.get("format") or "").lower() == "csv"]
        except (httpx.HTTPError, ValueError, KeyError):
            if have:
                return con, []
            raise
        changed = False
        missing: list[str] = []
        for res in resources:
            if have.get(res["id"]) == res.get("last_modified"):
                continue
            changed = True
            con.execute("INSERT OR IGNORE INTO archivo (id) VALUES (?)", (res["id"],))
            n = con.execute("SELECT n FROM archivo WHERE id = ?", (res["id"],)).fetchone()[0]
            raw = None
            for attempt in range(4):
                try:
                    async with http.stream("GET", res["url"], headers=UA, timeout=600, follow_redirects=True) as resp:
                        if resp.status_code == 200:
                            raw = b"".join([c async for c in resp.aiter_bytes()])
                except httpx.HTTPError:
                    pass
                if raw:
                    break
                await asyncio.sleep(3 * (attempt + 1))
            if not raw:
                missing.append(res.get("name") or res["id"])
                continue
            text = raw.decode("utf-8-sig", errors="replace")
            rows = []
            for row in csv.DictReader(io.StringIO(text), delimiter=";"):
                p = rut_parts(row.get("RUT") or "")
                if not p:
                    continue
                cap = re.sub(r"\D", "", row.get("Capital") or "")
                rows.append((p[0], p[1], (row.get("Razon Social") or "").strip(), row.get("Codigo de sociedad"),
                             row.get("Tipo de actuacion"), row.get("Fecha de registro (ultima firma)") or row.get("Fecha de actuacion (1era firma)"),
                             (row.get("Comuna Social") or row.get("Comuna Tributaria") or "").strip(), int(cap) if cap else None, n))
            if not rows:
                missing.append(res.get("name") or res["id"])
                continue
            con.execute("DELETE FROM actuacion WHERE archivo = ?", (n,))
            con.executemany("INSERT INTO actuacion VALUES (?,?,?,?,?,?,?,?,?)", rows)
            con.execute("UPDATE archivo SET modificado = ? WHERE n = ?", (res.get("last_modified"), n))
            con.commit()
        if changed:
            con.execute("INSERT INTO razon_fts (razon_fts) VALUES ('rebuild')")
        if not missing:
            con.execute("INSERT OR REPLACE INTO archivo (n, id, modificado) VALUES "
                        "((SELECT n FROM archivo WHERE id = '_check'), '_check', ?)", (time.strftime("%Y-%m-%d"),))
        con.commit()
        return con, missing


def _company(con, num: int) -> dict | None:
    acts = con.execute("SELECT dv, razon, tipo, actuacion, fecha, comuna, capital FROM actuacion WHERE rut = ? "
                       "ORDER BY substr(fecha,7,4)||substr(fecha,4,2)||substr(fecha,1,2)", (num,)).fetchall()
    if not acts:
        return None
    first, last = acts[0], acts[-1]
    return {
        "rut": rut_fmt(num, first[0]),
        "razon": last[1],
        "attrs": {
            "RUT": rut_fmt(num, first[0]),
            "Tipo de sociedad": last[2],
            "Constituida": next((a[4] for a in acts if "CONSTITU" in (a[3] or "").upper()), first[4]),
            "Comuna": _title(last[5]),
            "Capital": f"${last[6]:,}".replace(",", ".") if last[6] else None,
            "Disuelta": next((a[4] for a in acts if "DISOLU" in (a[3] or "").upper()), None),
            "Historial (Registro de Empresas)": [f"{a[4]} · {_title(a[3] or '')}" for a in acts][-20:] if len(acts) > 1 else None,
            "Nombres anteriores": list(dict.fromkeys(a[1] for a in acts if a[1] != last[1])) or None,
            "_links": [["Registro de Empresas y Sociedades", "https://www.registrodeempresasysociedades.cl/",
                        [["RUT", f"{num}-{first[0]}"]]]],
        },
    }


@register
class EmpresasChile(Module):
    name = "empresas_cl"
    title = "Empresas chilenas (Registro de Empresas y Sociedades)"
    description = ("Razón social, tipo, fecha de constitución, comuna, capital e historial de una empresa por su RUT; "
                   "para personas, sociedades con su nombre completo o sus dos apellidos (empresas creadas desde 2013)")
    inputs = ("rut", "person", "organization")
    sources = ("datos.gob.cl",)
    timeout = 900

    async def run(self, ctx):
        first_time = not (DATA_DIR / "empresas_cl.db").exists()
        con, missing = await empresas_ready(ctx.http)
        try:
            t = ctx.entity["type"]
            if t == "rut":
                p = rut_parts(ctx.value)
                if not p or p[0] < 50_000_000:
                    raise Skip("Sólo aplica a RUT de empresas (50 millones o más)")
                c = _company(con, p[0])
                if not c:
                    ctx.message = "No figura entre las empresas creadas por el Registro (desde 2013)"
                    return
                ctx.add("organization", c["razon"], c["attrs"], rel="razón social", pivot=False)
                ctx.found += 1
            elif t == "organization":
                q = " ".join(f'"{w}"' for w in tokens(ctx.value) if len(w) > 1)
                if not q:
                    return
                for num, _ in _search(con, q, 5):
                    c = _company(con, num)
                    if c and tokens(c["razon"]) == tokens(ctx.value):
                        ctx.enrich({k: v for k, v in c["attrs"].items() if k != "_links"})
                        ctx.add("rut", c["rut"], {}, rel="RUT", pivot=False)
                        ctx.found += 1
                        break
            else:
                await self._person(ctx, con)
        finally:
            con.close()
        if missing:
            ctx.message = ((ctx.message + " · ") if ctx.message else "") + \
                f"datos.gob.cl no entregó {len(missing)} de los archivos anuales; se reintentará en la próxima búsqueda"
        elif first_time and not ctx.message:
            ctx.message = "Base de empresas descargada (sólo la primera vez)"

    async def _person(self, ctx, con):
        parts = [w for w in tokens(ctx.value) if len(w) > 1]
        if len(parts) < 2:
            raise Skip("Hace falta nombre y apellido")
        full_q = " ".join(f'"{w}"' for w in parts)
        named = [(n, r) for n, r in _search(con, full_q, 40) if name_match(r, ctx.value, [])]
        surname = []
        if len(parts) >= 3:
            sq = f'"{parts[-2]}" "{parts[-1]}"'
            surname = [(n, r) for n, r in _search(con, sq, 60)
                       if (n, r) not in named and re.search(rf"\b{parts[-2]}\W+{parts[-1]}\b", " ".join(tokens(r)))]
        for num, _ in named[:10]:
            c = _company(con, num)
            if c:
                c["attrs"]["Verificación"] = "Su nombre completo está en la razón social"
                oid = ctx.add("organization", c["razon"], c["attrs"], rel="empresa con su nombre", pivot=False)
                if oid:
                    ctx.add("rut", c["rut"], {}, rel="RUT", parent=oid, pivot=False)
                ctx.found += 1
        if surname:
            ctx.enrich({"Sociedades con sus dos apellidos (posibles familiares)": [
                f"{r} · {_company(con, n)['rut']}" for n, r in surname[:20]]})
        ctx.message = (f"{len(named)} empresa(s) con su nombre completo"
                       + (f" · {len(surname)} sociedades con sus dos apellidos (posibles familiares)" if surname else ""))


# ---------------------------------------------------------------- Tesis (LA Referencia)

@register
class TesisLatam(Module):
    name = "tesis_latam"
    title = "Tesis y publicaciones (LA Referencia)"
    description = ("Tesis de pregrado, magíster y doctorado, y artículos de repositorios universitarios de Chile y "
                   "Latinoamérica firmados con ese nombre: universidad, año, tema y enlace")
    inputs = ("person",)
    sources = ("lareferencia.info",)

    async def run(self, ctx):
        name = ctx.value.strip()
        if len(tokens(name)) < 2:
            raise Skip("Hace falta nombre y apellido")
        variants = name_variants(name)[:2]
        records = {}
        for q in [name] + variants:
            st, d = await ctx.get_json("https://buscador.lareferencia.info/api/v1/search", params={
                "lookfor": q, "type": "Author", "limit": 40,
                "field[]": ["id", "title", "primaryAuthors", "secondaryAuthors", "formats", "publicationDates", "urls",
                            "institutions", "subjects", "rawData"]}, headers=UA, timeout=40)
            for rec in (d or {}).get("records") or []:
                records.setdefault(rec["id"], rec)
        kinds = {"bachelorThesis": "Tesis de pregrado", "masterThesis": "Tesis de magíster", "doctoralThesis": "Tesis de doctorado",
                 "article": "Artículo", "book": "Libro", "conferenceObject": "Ponencia", "report": "Informe"}
        exact, partial = [], []
        for rec in records.values():
            authors = [" ".join(reversed([p.strip() for p in a.split(",", 1)])) for a in rec.get("primaryAuthors") or []]
            match = next((m for m in (name_match(a, name, variants) for a in authors) if m), None)
            if not match:
                continue
            if match[0] == "exacta" and not any(same_name(a, name) for a in authors):
                match = ("parcial", match[1])
            raw = rec.get("rawData") or {}
            item = {
                "title": rec.get("title"),
                "kind": kinds.get((rec.get("formats") or [""])[0], (rec.get("formats") or ["Documento"])[0]),
                "year": (rec.get("publicationDates") or [None])[0],
                "inst": (rec.get("institutions") or [None])[0],
                "country": raw.get("network_name_str"),
                "url": next((u.get("url") for u in rec.get("urls") or [] if u.get("url")), None),
                "advisor": [" ".join(reversed([p.strip() for p in a.split(",", 1)])) for a in rec.get("secondaryAuthors") or []][:2],
                "subjects": [s[0] for s in rec.get("subjects") or [] if s][:5],
            }
            (exact if match[0] == "exacta" else partial).append(item)
        if not exact and not partial:
            ctx.message = "Sin tesis ni publicaciones con ese nombre"
            return
        line = lambda it: f"{it['title']} · {it['kind']} · {it['inst'] or ''} ({it['year'] or 's/f'})"  # noqa: E731
        theses = [it for it in exact if it["kind"].startswith("Tesis") and it["url"]]
        for it in theses[:15]:
            ctx.add("url", it["url"], {
                "Título": it["title"], "Tipo": it["kind"], "Año": it["year"], "Institución": it["inst"],
                "País": it["country"], "Profesor guía": it["advisor"] or None, "Temas": it["subjects"] or None,
                "_links": [["Abrir tesis", it["url"]]],
            }, rel=it["kind"].lower(), pivot=False)
            if it["inst"] and not it["inst"].startswith("Agencia Nacional"):
                ctx.add("organization", it["inst"], {"Tipo": "Universidad"},
                        rel=f"estudió en ({it['year']})" if it["year"] else "estudió en", pivot=False)
        others = [it for it in exact if it not in theses]
        ctx.enrich({"Publicaciones (LA Referencia)": [line(it) for it in others[:25]],
                    "Tesis con nombre parecido": [line(it) for it in partial[:15]]})
        ctx.message = (f"{len(theses)} tesis y {len(others)} publicaciones con su nombre completo"
                       + (f" · {len(partial)} con nombre parecido" if partial else ""))
