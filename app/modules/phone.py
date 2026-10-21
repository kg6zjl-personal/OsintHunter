import phonenumbers
from phonenumbers import carrier, geocoder, timezone
from phonenumbers.phonenumberutil import NumberParseException, PhoneNumberType

from .base import Module, Skip, register

TYPE_NAMES = {
    PhoneNumberType.MOBILE: "Móvil",
    PhoneNumberType.FIXED_LINE: "Fijo",
    PhoneNumberType.FIXED_LINE_OR_MOBILE: "Fijo o móvil",
    PhoneNumberType.TOLL_FREE: "Gratuito",
    PhoneNumberType.PREMIUM_RATE: "Tarificación especial",
    PhoneNumberType.SHARED_COST: "Coste compartido",
    PhoneNumberType.VOIP: "VoIP",
    PhoneNumberType.PERSONAL_NUMBER: "Número personal",
    PhoneNumberType.PAGER: "Buscapersonas",
    PhoneNumberType.UAN: "UAN",
    PhoneNumberType.VOICEMAIL: "Buzón de voz",
}


def parse(ctx) -> phonenumbers.PhoneNumber:
    region = (ctx.settings.get("default_region") or "").upper() or None
    raw = ctx.value
    try:
        return phonenumbers.parse(raw, None if raw.startswith("+") else region)
    except NumberParseException as e:
        raise Skip(
            "No se pudo interpretar el número. Escríbelo con prefijo internacional (+34…, +54…) "
            "o define tu país por defecto en Ajustes."
        ) from e


@register
class PhoneInfo(Module):
    name = "phone_info"
    title = "Análisis del teléfono"
    description = "País, región, operador original, tipo de línea y zona horaria (sin conexión, base de Google libphonenumber)."
    inputs = ("phone",)
    sources = ("libphonenumber",)

    async def run(self, ctx):
        n = parse(ctx)
        e164 = phonenumbers.format_number(n, phonenumbers.PhoneNumberFormat.E164)
        digits = e164.lstrip("+")
        region = phonenumbers.region_code_for_number(n)
        country = geocoder.country_name_for_number(n, "es")
        place = geocoder.description_for_number(n, "es")
        ctx.enrich({
            "Válido": "Sí" if phonenumbers.is_valid_number(n) else "No (formato posible pero no asignado)",
            "E.164": e164,
            "Internacional": phonenumbers.format_number(n, phonenumbers.PhoneNumberFormat.INTERNATIONAL),
            "Nacional": phonenumbers.format_number(n, phonenumbers.PhoneNumberFormat.NATIONAL),
            "País": f"{country} ({region})" if country else region,
            "Zona": place if place and place != country else None,
            "Operador original": carrier.name_for_number(n, "es") or None,
            "Tipo de línea": TYPE_NAMES.get(phonenumbers.number_type(n), "Desconocido"),
            "Zona horaria": list(timezone.time_zones_for_number(n)) or None,
            "_links": [
                ["WhatsApp", f"https://wa.me/{digits}"],
                ["Telegram", f"https://t.me/+{digits}"],
                ["Buscar en Google", f'https://www.google.com/search?q="{e164}" OR "{digits}"'],
                ["Sync.me", f"https://sync.me/search/?number={digits}"],
            ],
        })
        loc = ", ".join(x for x in (place if place != country else None, country) if x)
        if loc:
            ctx.add("location", loc, rel="ubicación del prefijo", pivot=False)


@register
class Numverify(Module):
    name = "numverify"
    title = "Numverify"
    description = "Validación en línea del número y operador actual."
    inputs = ("phone",)
    keys = ("numverify",)
    sources = ("Numverify",)

    async def run(self, ctx):
        n = parse(ctx)
        e164 = phonenumbers.format_number(n, phonenumbers.PhoneNumberFormat.E164)
        st, d = await ctx.get_json(
            "http://apilayer.net/api/validate", params={"access_key": ctx.key("numverify"), "number": e164.lstrip("+")}
        )
        if not isinstance(d, dict) or d.get("error"):
            ctx.message = str((d or {}).get("error", {}).get("info", f"Respuesta {st}"))
            return
        ctx.enrich({
            "Numverify: válido": d.get("valid"),
            "Numverify: operador": d.get("carrier"),
            "Numverify: tipo": d.get("line_type"),
            "Numverify: ubicación": d.get("location"),
        })
