import asyncio
import hashlib
import random
import string
import time

import httpx

from ..config import DATA_DIR, settings
from ..util import FREE_EMAIL_PROVIDERS, resolve
from .base import Module, register
from .username import _txt, add_profile

DISPOSABLE_URL = "https://raw.githubusercontent.com/disposable-email-domains/disposable-email-domains/main/disposable_email_blocklist.conf"
_disposable: set[str] | None = None


async def disposable_domains(http: httpx.AsyncClient) -> set[str]:
    global _disposable
    if _disposable is not None:
        return _disposable
    cache = DATA_DIR / "disposable.txt"
    if not cache.exists() or time.time() - cache.stat().st_mtime > 7 * 86400:
        try:
            r = await http.get(DISPOSABLE_URL, timeout=20)
            if r.status_code == 200:
                cache.write_text(r.text, encoding="utf-8")
        except httpx.HTTPError:
            pass
    base = {"mailinator.com", "10minutemail.com", "guerrillamail.com", "tempmail.com", "yopmail.com", "trashmail.com"}
    if cache.exists():
        base |= {l.strip().lower() for l in cache.read_text(encoding="utf-8").splitlines() if l.strip()}
    _disposable = base
    return base


@register
class EmailBasics(Module):
    name = "email_basics"
    title = "Análisis del email"
    description = "Valida el dominio (MX), detecta proveedores gratuitos y desechables y extrae dominio y posible usuario."
    inputs = ("email",)
    sources = ("DNS", "Lista de dominios desechables")

    async def run(self, ctx):
        local, _, domain = ctx.value.partition("@")
        mx = await resolve(domain, "MX")
        mx_hosts = sorted({m.split()[-1].rstrip(".") for m in mx if m})
        free = domain in FREE_EMAIL_PROVIDERS
        disposable = domain in await disposable_domains(ctx.http)
        provider = None
        joined = " ".join(mx_hosts).lower()
        for needle, name in (("google", "Google Workspace / Gmail"), ("outlook", "Microsoft 365 / Outlook"),
                             ("protection.outlook", "Microsoft 365"), ("zoho", "Zoho Mail"), ("proton", "Proton Mail"),
                             ("yahoodns", "Yahoo"), ("icloud", "iCloud"), ("mimecast", "Mimecast"),
                             ("pphosted", "Proofpoint"), ("secureserver", "GoDaddy"), ("ovh", "OVH")):
            if needle in joined:
                provider = name
                break
        ctx.enrich({
            "Dominio": domain,
            "Acepta correo (MX)": "Sí" if mx_hosts else "No: el dominio no tiene servidores de correo",
            "Servidores MX": mx_hosts,
            "Proveedor de correo": provider,
            "Tipo": "Desechable/temporal" if disposable else ("Proveedor gratuito" if free else "Dominio propio/corporativo"),
        })
        if not free and not disposable:
            ctx.add("domain", domain, rel="dominio")
        if len(local) >= 3:
            ctx.add("username", local.split("+")[0], {"Origen": "Parte local del email"}, rel="posible usuario")


@register
class Gravatar(Module):
    name = "gravatar"
    title = "Gravatar"
    description = "Perfil público asociado al email: nombre, foto, ubicación y cuentas verificadas."
    inputs = ("email",)
    sources = ("Gravatar",)

    async def run(self, ctx):
        email = ctx.value.strip().lower()
        sha = hashlib.sha256(email.encode()).hexdigest()
        md5 = hashlib.md5(email.encode()).hexdigest()
        st, d = await ctx.get_json(f"https://api.gravatar.com/v3/profiles/{sha}")
        if st == 200 and isinstance(d, dict) and d.get("profile_url"):
            res = {
                "platform": "Gravatar",
                "user": d.get("display_name"),
                "url": d["profile_url"],
                "attrs": {
                    "Nombre": d.get("display_name"),
                    "Bio": d.get("description"),
                    "Puesto": d.get("job_title"),
                    "Empresa": d.get("company"),
                    "Pronombres": d.get("pronouns"),
                    "_avatar": d.get("avatar_url"),
                },
                "name": d.get("display_name"),
                "location": d.get("location"),
                "urls": [a.get("url") for a in d.get("verified_accounts") or []] + [l.get("url") for l in d.get("links") or []],
            }
            add_profile(ctx, res)
            return
        st, d = await ctx.get_json(f"https://en.gravatar.com/{md5}.json")
        entry = ((d or {}).get("entry") or [None])[0] if isinstance(d, dict) else None
        if st != 200 or not entry:
            r = await ctx.http.get(f"https://gravatar.com/avatar/{md5}?d=404&s=200")
            if r.status_code == 200:
                ctx.enrich({"Gravatar": "Tiene foto de perfil", "_avatar": f"https://gravatar.com/avatar/{md5}?s=200"})
            return
        name = (entry.get("name") or {}).get("formatted") or entry.get("displayName")
        add_profile(ctx, {
            "platform": "Gravatar",
            "user": entry.get("preferredUsername"),
            "url": entry.get("profileUrl") or f"https://gravatar.com/{md5}",
            "attrs": {"Nombre": name, "Bio": _txt(entry.get("aboutMe")), "_avatar": entry.get("thumbnailUrl")},
            "name": name,
            "location": entry.get("currentLocation"),
            "urls": [a.get("url") for a in entry.get("accounts") or []] + [u.get("value") for u in entry.get("urls") or []],
        })


@register
class XposedOrNot(Module):
    name = "xposedornot"
    title = "Filtraciones (XposedOrNot)"
    description = "Comprueba si el email aparece en brechas de datos públicas y qué tipo de datos se filtraron."
    inputs = ("email",)
    sources = ("XposedOrNot",)

    async def run(self, ctx):
        st, d = await ctx.get_json(f"https://api.xposedornot.com/v1/breach-analytics?email={ctx.value}")
        if st == 404 or not isinstance(d, dict):
            return
        exposed = d.get("ExposedBreaches") or {}
        details = exposed.get("breaches_details") or []
        for b in details:
            ctx.add("breach", b.get("breach") or "Desconocida", {
                "Fecha": b.get("xposed_date"),
                "Datos expuestos": [x.strip() for x in (b.get("xposed_data") or "").split(";") if x.strip()],
                "Registros": b.get("xposed_records"),
                "Dominio": b.get("domain"),
                "Sector": b.get("industry"),
                "Riesgo contraseña": b.get("password_risk"),
                "Descripción": b.get("details"),
                "_avatar": b.get("logo"),
            }, rel="aparece en", pivot=False)
        metrics = d.get("BreachMetrics") or {}
        risk = (metrics.get("risk") or [{}])[0] if isinstance(metrics.get("risk"), list) else {}
        if details:
            ctx.enrich({"Filtraciones": len(details), "Riesgo (XposedOrNot)": risk.get("risk_label")})


# ---------------------------------------------------------------------------
# ¿En qué servicios está registrado el email? Sólo endpoints que NO avisan al dueño
# (nada de "recuperar contraseña"). Cada uno devuelve (existe: bool | None, extras).
# ---------------------------------------------------------------------------


async def c_twitter(http, em):
    r = await http.get("https://api.twitter.com/i/users/email_available.json", params={"email": em})
    d = r.json() if r.status_code == 200 else {}
    return (bool(d["taken"]) if "taken" in d else None), {}


async def c_wordpress(http, em):
    r = await http.get(f"https://public-api.wordpress.com/rest/v1.1/users/{em}/auth-options", params={"http_envelope": 1})
    d = r.json() if r.status_code == 200 else {}
    err = (d.get("body") or {}).get("error")
    if err == "unknown_user":
        return False, {}
    if d.get("code") in (200, 403):
        return True, {}
    return None, {}


async def c_duolingo(http, em):
    r = await http.get("https://www.duolingo.com/2017-06-30/users", params={"email": em})
    if r.status_code != 200:
        return None, {}
    users = r.json().get("users") or []
    if not users:
        return False, {}
    u = users[0]
    return True, {"Usuario": u.get("username"), "Nombre": u.get("name")}


async def c_chesscom(http, em):
    r = await http.get("https://www.chess.com/callback/email/available", params={"email": em})
    d = r.json() if r.status_code in (200, 226) else {}
    return (not d["isEmailAvailable"] if "isEmailAvailable" in d else None), {}


async def c_lastpass(http, em):
    r = await http.get("https://lastpass.com/create_account.php",
                       params={"check": "avail", "skipcontent": 1, "mistype": 1, "username": em})
    t = r.text.strip()
    return ({"no": True, "ok": False}.get(t)), {}


async def c_spotify(http, em):
    r = await http.get("https://spclient.wg.spotify.com/signup/public/v1/account", params={"validate": 1, "email": em})
    st = (r.json() if r.status_code == 200 else {}).get("status")
    return ({20: True, 1: False}.get(st)), {}


async def c_microsoft(http, em):
    r = await http.post("https://login.microsoftonline.com/common/GetCredentialType", json={"Username": em})
    d = r.json() if r.status_code == 200 else {}
    if d.get("ThrottleStatus") == 1:
        return None, {}
    res = d.get("IfExistsResult")
    if res in (0, 5, 6):
        return True, {"Tipo": "Cuenta corporativa federada" if res in (5, 6) else "Cuenta Microsoft / Office 365"}
    return (False if res == 1 else None), {}


def _json(r):
    try:
        return r.json()
    except ValueError:
        return None


async def c_adobe(http, em):
    r = await http.post("https://auth.services.adobe.com/signin/v2/users/accounts",
                        headers={"X-IMS-ClientId": "adobedotcom2"}, json={"username": em})
    d = _json(r)
    if not isinstance(d, list):
        return None, {}
    if not d:
        return False, {}
    acc = d[0]
    kinds = {"individual": "Personal", "enterprise": "Empresa", "federated": "Empresa (federada)"}
    login = {"password": "contraseña", "google": "Google", "apple": "Apple", "facebook": "Facebook", "otp": "código por email"}
    methods = [login.get(m.get("id"), m.get("id")) for m in acc.get("authenticationMethods") or [] if m.get("id")]
    return True, {"Tipo": kinds.get(acc.get("type"), acc.get("type")),
                  "Inicio de sesión": ", ".join(methods) or None,
                  "Incluye": "Behance, Photoshop, Acrobat y demás servicios de Adobe"}


async def c_freelancer(http, em):
    r = await http.post("https://www.freelancer.com/api/users/0.1/users/check?compact=true&new_errors=true",
                        json={"user": {"email": em}})
    return {409: True, 200: False}.get(r.status_code), {}


async def c_snapchat(http, em):
    r = await http.post("https://bitmoji.api.snapchat.com/api/user/find", data={"email": em})
    if r.status_code == 204:
        return False, {}
    d = _json(r) if r.status_code == 200 else None
    if not isinstance(d, dict) or "account_type" not in d:
        return None, {}
    return True, {"Tipo": "Snapchat con Bitmoji" if d["account_type"] == "bitmoji" else d["account_type"]}


async def c_mewe(http, em):
    r = await http.get("https://mewe.com/api/v2/auth/checkEmail", params={"email": em})
    d = _json(r) if r.status_code == 200 else None
    if not isinstance(d, dict):
        return None, {}
    if d.get("errorCode") == 109:
        return True, {}
    return (False if d.get("message") == "ok" else None), {}


async def c_myfitnesspal(http, em):
    r = await http.get("https://www.myfitnesspal.com/api/idm/user-exists", params={"email": em})
    d = _json(r) if r.status_code == 200 else None
    return (d.get("emailExists") if isinstance(d, dict) else None), {}


async def c_plurk(http, em):
    r = await http.post("https://www.plurk.com/Users/isEmailFound", data={"email": em})
    return {"True": True, "False": False}.get(r.text.strip()), {}


async def c_anydo(http, em):
    r = await http.post("https://sm-prod2.any.do/check_email", json={"email": em})
    d = _json(r) if r.status_code == 200 else None
    return (d.get("user_exists") if isinstance(d, dict) else None), {}


async def c_bandlab(http, em):
    r = await http.get("https://www.bandlab.com/api/v1.3/validation/user", params={"email": em})
    d = _json(r) if r.status_code == 200 else None
    return ((not d["isAvailable"]) if isinstance(d, dict) and "isAvailable" in d else None), {}


async def c_vrbo(http, em):
    r = await http.post("https://www.vrbo.com/auth/aam/v3/status", json={"emailAddress": em, "country": "US"})
    d = _json(r) if r.status_code == 200 else None
    types = (d or {}).get("authType") if isinstance(d, dict) else None
    if not types:
        return None, {}
    if types == ["SIGNUP"]:
        return False, {}
    login = {"LOGIN_UMS": "contraseña", "LOGIN_GOOGLE": "Google", "LOGIN_APPLE": "Apple", "LOGIN_FACEBOOK": "Facebook"}
    return True, {"Inicio de sesión": ", ".join(login.get(t, t) for t in types),
                  "Incluye": "Cuenta compartida con Expedia y Hotels.com"}


async def c_kahoot(http, em):
    r = await http.get("https://create.kahoot.it/rest/users/emailavailable", params={"email": em})
    d = _json(r) if r.status_code == 200 else None
    return ((not d["isEmailAvailable"]) if isinstance(d, dict) and "isEmailAvailable" in d else None), {}


async def c_disney(http, em):
    base = "https://registerdisney.go.com/jgc/v8/client/ESPN-ONESITE.WEB-PROD"
    r = await http.post(f"{base}/api-key?langPref=es-CL")
    key = r.headers.get("api-key")
    if not key:
        return None, {}
    r = await http.post(f"{base}/guest-flow?langPref=es-CL", json={"email": em}, headers={"Authorization": f"APIKEY {key}"})
    flow = (((_json(r) or {}).get("data") or {}).get("guestFlow")) if r.status_code == 200 else None
    found = {"LOGIN_FLOW": True, "REGISTRATION_FLOW": False}.get(flow)
    return found, ({"Incluye": "Disney+, ESPN y demás servicios de Disney"} if found else {})


async def c_deezer(http, em):
    params = {"input": 3, "api_version": "1.0"}
    r = await http.post("https://www.deezer.com/ajax/gw-light.php", params={**params, "method": "deezer.getUserData", "api_token": ""})
    token = (((_json(r) or {}).get("results") or {}).get("checkForm"))
    if not token:
        return None, {}
    r = await http.post("https://www.deezer.com/ajax/gw-light.php",
                        params={**params, "method": "deezer.emailCheck", "api_token": token}, json={"EMAIL": em})
    res = (_json(r) or {}).get("results") or {}
    return ((not res["availability"]) if "availability" in res else None), {}


async def c_xvideos(http, em):
    r = await http.get("https://www.xvideos.com/account/checkemail", params={"email": em})
    d = _json(r) if r.status_code == 200 else None
    if not isinstance(d, dict) or "result" not in d:
        return None, {}
    return (not d["result"]), {}


EMAIL_CHECKS = {
    "X/Twitter": c_twitter, "WordPress.com": c_wordpress, "Duolingo": c_duolingo, "Chess.com": c_chesscom,
    "LastPass": c_lastpass, "Spotify": c_spotify, "Microsoft": c_microsoft,
    "Adobe": c_adobe, "Snapchat": c_snapchat, "Disney": c_disney, "Deezer": c_deezer, "Vrbo / Expedia": c_vrbo,
    "Freelancer": c_freelancer, "MyFitnessPal": c_myfitnesspal, "Kahoot!": c_kahoot, "BandLab": c_bandlab,
    "Any.do": c_anydo, "MeWe": c_mewe, "Plurk": c_plurk,
}
ADULT_EMAIL_CHECKS = {"XVideos": c_xvideos}


@register
class EmailAccounts(Module):
    name = "email_accounts"
    title = "Servicios donde está registrado"
    description = "Comprueba en qué servicios hay una cuenta con este email, sin enviar ningún aviso a su dueño."
    inputs = ("email",)
    sources = tuple(EMAIL_CHECKS)
    timeout = 75

    async def run(self, ctx):
        email = ctx.value
        fake = "zq" + "".join(random.choices(string.ascii_lowercase, k=12)) + "@" + email.split("@")[1]

        async def safe(check, em):
            try:
                return await check(ctx.http, em)
            except (httpx.HTTPError, ValueError, KeyError, TypeError, AttributeError):
                return None, {}

        checks = {**EMAIL_CHECKS, **(ADULT_EMAIL_CHECKS if settings.get("include_nsfw", False) else {})}
        names = list(checks)
        results = await asyncio.gather(*(safe(checks[n], email) for n in names))
        controls = await asyncio.gather(*(safe(checks[n], fake) for n in names))
        yes, no, unknown = [], [], []
        for name, (exists, extra), (ctrl, _) in zip(names, results, controls):
            if exists is None or (exists and ctrl):
                unknown.append(name)
                continue
            if not exists:
                no.append(name)
                continue
            yes.append(name)
            attrs = {"Plataforma": name, "Registro": "Email registrado",
                     "Verificación": "Registro confirmado (contrastado con un email inventado)",
                     **{k: v for k, v in extra.items() if k not in ("Usuario",)}}
            if extra.get("Usuario"):
                attrs["Usuario"] = extra["Usuario"]
            acc = ctx.add("account", f"{name} · {email}", attrs, rel="registrado en", pivot=False)
            if extra.get("Usuario") and acc:
                ctx.add("username", extra["Usuario"], rel=f"usuario en {name}", parent=acc)
        ctx.enrich({"Registrado en": yes, "No registrado en": no})
        ctx.message = (f"Registrado en {len(yes)}: {', '.join(yes) or '—'}"
                       + (f" · sin respuesta fiable: {', '.join(unknown)}" if unknown else ""))


@register
class HIBP(Module):
    name = "hibp"
    title = "Have I Been Pwned"
    description = "Brechas en las que aparece el email según HIBP (requiere clave de pago)."
    inputs = ("email",)
    keys = ("hibp",)
    sources = ("Have I Been Pwned",)

    async def run(self, ctx):
        r = await ctx.http.get(
            f"https://haveibeenpwned.com/api/v3/breachedaccount/{ctx.value}?truncateResponse=false",
            headers={"hibp-api-key": ctx.key("hibp"), "user-agent": "OsintHunter"},
        )
        if r.status_code == 404:
            return
        r.raise_for_status()
        for b in r.json():
            ctx.add("breach", b.get("Title") or b.get("Name"), {
                "Fecha": b.get("BreachDate"),
                "Datos expuestos": b.get("DataClasses"),
                "Registros": b.get("PwnCount"),
                "Dominio": b.get("Domain"),
                "Descripción": _txt(b.get("Description")),
                "_avatar": b.get("LogoPath"),
            }, rel="aparece en", pivot=False)


@register
class HunterVerify(Module):
    name = "hunter_verify"
    title = "Hunter.io verificador"
    description = "Comprueba si el buzón existe y cuántas fuentes web publican el email."
    inputs = ("email",)
    keys = ("hunter",)
    sources = ("Hunter.io",)

    async def run(self, ctx):
        st, d = await ctx.get_json(
            "https://api.hunter.io/v2/email-verifier", params={"email": ctx.value, "api_key": ctx.key("hunter")}
        )
        data = (d or {}).get("data") if isinstance(d, dict) else None
        if st != 200 or not data:
            ctx.message = f"Hunter respondió {st}"
            return
        ctx.enrich({
            "Hunter: estado": data.get("status"),
            "Hunter: puntuación": data.get("score"),
            "Hunter: SMTP válido": data.get("smtp_check"),
            "Hunter: acepta todo": data.get("accept_all"),
        })
        for s in data.get("sources") or []:
            if s.get("uri"):
                ctx.add("url", s["uri"], {"Visto": s.get("last_seen_on"), "_links": [["Abrir", s["uri"]]]},
                        rel="publicado en", pivot=False)
