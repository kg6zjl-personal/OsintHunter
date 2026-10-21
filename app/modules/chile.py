"""Fuentes y tipos de dato chilenos: RUT, patentes de vehículos y WHOIS de NIC Chile (.cl)."""
import html
import re

from .base import Module, register

# ---------------------------------------------------------------- RUT


def rut_dv(num: int) -> str:
    s, m = 0, 2
    for d in reversed(str(num)):
        s += int(d) * m
        m = 2 if m == 7 else m + 1
    r = 11 - s % 11
    return {11: "0", 10: "K"}.get(r, str(r))


def rut_parts(value: str) -> tuple[int, str] | None:
    v = re.sub(r"[.\s]", "", value or "").upper()
    m = re.fullmatch(r"(\d{6,9})-?([\dK])", v)
    return (int(m.group(1)), m.group(2)) if m else None


def rut_fmt(num: int, dv: str) -> str:
    return f"{num:,}".replace(",", ".") + f"-{dv}"


def rut_valid(value: str) -> bool:
    p = rut_parts(value)
    return bool(p) and rut_dv(p[0]) == p[1]


# con guion obligatorio: sin él hay demasiados números que pasan por RUT
RUT_TEXT_RE = re.compile(r"(?<![\d.\-])(\d{1,2}\.\d{3}\.\d{3}|\d{7,8})\s?-\s?([\dkK])(?![\w])")


def find_ruts(text: str, limit: int = 40) -> list[tuple[str, str]]:
    """[(rut formateado, contexto)] de los RUT válidos que aparecen en un texto."""
    out: dict[str, str] = {}
    for m in RUT_TEXT_RE.finditer(text or ""):
        num = int(m.group(1).replace(".", ""))
        dv = m.group(2).upper()
        if num < 1_000_000 or rut_dv(num) != dv:
            continue
        rut = rut_fmt(num, dv)
        if rut not in out:
            ctx = " ".join(text[max(0, m.start() - 70):m.end() + 40].split())
            out[rut] = ctx
        if len(out) >= limit:
            break
    return list(out.items())


def rut_kind(num: int) -> str:
    if 60_000_000 <= num < 62_000_000:
        return "Persona jurídica: probablemente organismo o servicio público"
    if num >= 50_000_000:
        return "Persona jurídica (empresa, sociedad u organización)"
    return "Persona natural"


@register
class RutInfo(Module):
    name = "rut_info"
    title = "RUT chileno"
    description = ("Valida el dígito verificador, indica si es persona natural o jurídica y prepara las consultas "
                   "en SII, Registro de Empresas, Poder Judicial, Mercado Público y otras fuentes oficiales")
    inputs = ("rut",)
    sources = ("Local",)
    auto = True

    async def run(self, ctx):
        p = rut_parts(ctx.value)
        if not p:
            ctx.message = "No tiene formato de RUT"
            return
        num, dv = p
        good = rut_dv(num)
        if good != dv:
            ctx.enrich({"Dígito verificador": f"Inválido: con {num} el dígito correcto es {good}"})
            ctx.message = f"Dígito verificador inválido (debería ser {good})"
            return
        plain = f"{num}-{dv}"
        split = [["RUT sin dígito", str(num)], ["Dígito", dv]]
        links = [
            ["SII · situación tributaria de terceros (nombre o razón social, actividades)", "https://zeus.sii.cl/cvc/stc/stc.html", split],
            ["Registro de Empresas y Sociedades", "https://www.registrodeempresasysociedades.cl/", [["RUT", plain]]],
            ["Poder Judicial · consulta unificada de causas", "https://oficinajudicialvirtual.pjud.cl/indexN.php", split],
            ["Mercado Público (proveedores del Estado)", "https://www.mercadopublico.cl/Home", [["RUT", rut_fmt(num, dv)]]],
        ]
        if num >= 50_000_000:
            links.append(["CMF · entidades fiscalizadas", "https://www.cmfchile.cl/portal/principal/613/w3-channel.html",
                          [["RUT sin dígito", str(num)]]])
        ctx.enrich({
            "Dígito verificador": "Válido",
            "Tipo": rut_kind(num),
            "Formas de escribirlo": [rut_fmt(num, dv), plain, f"{num}{dv}", str(num)],
            "_links": links,
        })
        ctx.found += 1


# ---------------------------------------------------------------- patentes

PLATE_LETTERS = "BCDFGHJKLPRSTVWXYZ"
PLATE_NEW = re.compile(rf"^[{PLATE_LETTERS}]{{4}}\d{{2}}$")
PLATE_OLD = re.compile(r"^[A-Z]{2}\d{4}$")
PLATE_MOTO_NEW = re.compile(rf"^[{PLATE_LETTERS}]{{3}}\d{{2}}$")
PLATE_MOTO_OLD = re.compile(r"^[A-Z]{2}\d{3}$")


def plate_clean(value: str) -> str:
    return re.sub(r"[\s.\-·•]", "", value or "").upper()


def plate_kind(value: str) -> str | None:
    p = plate_clean(value)
    if PLATE_NEW.match(p):
        return "Vehículo, formato nuevo (desde 2007): 4 letras y 2 números"
    if PLATE_OLD.match(p):
        return "Vehículo, formato antiguo (antes de 2007): 2 letras y 4 números"
    if PLATE_MOTO_NEW.match(p):
        return "Motocicleta, formato nuevo: 3 letras y 2 números"
    if PLATE_MOTO_OLD.match(p):
        return "Motocicleta, formato antiguo: 2 letras y 3 números"
    return None


def plate_display(value: str) -> str:
    p = plate_clean(value)
    if PLATE_NEW.match(p):
        return f"{p[:2]}·{p[2:4]}·{p[4:]}"
    if PLATE_OLD.match(p):
        return f"{p[:2]}·{p[2:]}"
    return f"{p[:-2]}·{p[-2:]}" if len(p) > 3 else p


@register
class PlateInfo(Module):
    name = "plate_info"
    title = "Patente de vehículo (Chile)"
    description = ("Reconoce el formato de la placa y prepara las consultas oficiales (encargo por robo, multas "
                   "impagas, certificado de anotaciones) y búsquedas en avisos y redes")
    inputs = ("plate",)
    sources = ("Local",)
    auto = True

    async def run(self, ctx):
        kind = plate_kind(ctx.value)
        if not kind:
            ctx.message = "No coincide con ningún formato de patente chilena"
            return
        fill = [["Patente", plate_clean(ctx.value)]]
        ctx.enrich({
            "Formato": kind,
            "Escrita": plate_display(ctx.value),
            "_links": [
                ["Autoseguro · ¿tiene encargo por robo?", "https://www.autoseguro.gob.cl/", fill],
                ["Registro Civil · multas de tránsito impagas", "https://consultamultas.srcei.cl/ConsultaMultas/", fill],
                ["Registro Civil · certificado de anotaciones vigentes (dueño; de pago)", "https://www.registrocivil.cl/principal/servicios-en-linea", fill],
            ],
        })
        ctx.found += 1


# ---------------------------------------------------------------- NIC Chile

NIC_FIELD = re.compile(r"<b>\s*([^<:]+?)\s*:\s*</b>\s*</div>\s*<div[^>]*>(.*?)</div>", re.S | re.I)


def _nic_text(s: str) -> str:
    return " ".join(html.unescape(re.sub(r"<[^>]+>", " ", s)).split())


def clean_holder(s: str) -> str:
    """«Servicio Nacional del Consumidor (SERNAC) (SERVICIO NACIONAL DEL CONSUMIDOR)» -> sin la repetición en mayúsculas."""
    m = re.match(r"^(.*\S)\s*\(([^()]*)\)$", s)
    if m and m.group(2).isupper() and m.group(2).lower() in m.group(1).lower():
        return m.group(1).strip()
    return s


@register
class NicChile(Module):
    name = "nic_chile"
    title = "WHOIS .cl (NIC Chile)"
    description = "Titular del dominio .cl (persona u organización), agente registrador, fechas y servidores DNS"
    inputs = ("domain",)
    sources = ("nic.cl",)

    def applies(self, entity: dict) -> bool:
        return entity["type"] == "domain" and entity["value"].lower().endswith(".cl")

    async def run(self, ctx):
        from .documents import classify_author

        d = ctx.value.lower()
        r = await ctx.http.get("https://www.nic.cl/registry/Whois.do", params={"d": d}, timeout=25)
        if r.status_code != 200:
            raise RuntimeError(f"NIC Chile respondió {r.status_code}")
        fields: dict[str, list[str]] = {}
        for label, val in NIC_FIELD.findall(r.text):
            fields.setdefault(_nic_text(label), []).append(_nic_text(val))
        if not fields.get("Titular"):
            ctx.message = "El dominio no está inscrito en NIC Chile" if "no existe" in r.text.lower() or "disponible" in r.text.lower() else "NIC Chile no devolvió titular"
            return
        holder = clean_holder(fields["Titular"][0])
        first = lambda k: (fields.get(k) or [None])[0]  # noqa: E731
        ctx.enrich({
            "Titular (NIC Chile)": holder,
            "Agente registrador": first("Agente Registrador"),
            "Alta (NIC Chile)": first("Fecha de creación"),
            "Última modificación (NIC Chile)": first("Fecha de última modificación"),
            "Caduca (NIC Chile)": first("Fecha de expiración"),
            "Servidores DNS (NIC Chile)": fields.get("Servidor de Nombre"),
            "_links": [["Ficha en NIC Chile", f"https://www.nic.cl/registry/Whois.do?d={d}"],
                       ["Otros dominios .cl que contengan el nombre (marca «Contenga»)", "https://www.nic.cl/registry/BuscarDominio.do",
                        [["Nombre", d.removesuffix(".cl").split(".")[-1]]]]],
        })
        kind = classify_author(holder)
        etype = "person" if kind and kind[0] == "person" else "organization"
        ctx.add(etype, kind[1] if kind and kind[0] == "person" else holder,
                {"Rol": "Titular de dominio .cl"}, rel="titular (NIC Chile)", pivot=False)
        ctx.found += 1
