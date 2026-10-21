import json
import os
import sys
import threading
from pathlib import Path

if getattr(sys, "frozen", False):
    # ejecutable de PyInstaller: los ficheros empaquetados están en _MEIPASS y los datos junto al .exe
    BUNDLE = Path(sys._MEIPASS)
    ROOT = Path(sys.executable).resolve().parent
    WEB_DIR = BUNDLE / "web"
    RESOURCES_DIR = BUNDLE / "app" / "resources"
else:
    ROOT = Path(__file__).resolve().parent.parent
    WEB_DIR = ROOT / "web"
    RESOURCES_DIR = Path(__file__).resolve().parent / "resources"


def _data_dir() -> Path:
    for d in (ROOT / "data", Path(os.environ.get("LOCALAPPDATA") or Path.home()) / "OsintHunter" / "data"):
        try:
            d.mkdir(parents=True, exist_ok=True)
            probe = d / ".write-test"
            probe.write_text("ok")
            probe.unlink()
            return d
        except OSError:
            continue
    raise RuntimeError("No hay ninguna carpeta con permiso de escritura para guardar los datos")


DATA_DIR = _data_dir()

SETTINGS_FILE = DATA_DIR / "settings.json"

# clave -> (nombre visible, dónde conseguirla)
API_KEYS: dict[str, tuple[str, str]] = {
    "shodan": ("Shodan", "https://account.shodan.io/"),
    "virustotal": ("VirusTotal", "https://www.virustotal.com/gui/my-apikey"),
    "hunter": ("Hunter.io", "https://hunter.io/api-keys"),
    "abuseipdb": ("AbuseIPDB", "https://www.abuseipdb.com/account/api"),
    "abusech": ("abuse.ch Auth-Key (URLhaus, ThreatFox, MalwareBazaar)", "https://auth.abuse.ch/"),
    "urlscan": ("URLScan.io", "https://urlscan.io/user/profile/"),
    "greynoise": ("GreyNoise Community", "https://viz.greynoise.io/account/api-key"),
    "github": ("GitHub token (sube el límite de 60 a 5000 peticiones/h)", "https://github.com/settings/tokens"),
    "numverify": ("Numverify", "https://numverify.com/product"),
    "hibp": ("Have I Been Pwned (de pago)", "https://haveibeenpwned.com/API/Key"),
    "serper": ("Serper.dev (Google; 2500 búsquedas gratis, mejora la búsqueda de personas)", "https://serper.dev/api-key"),
    "brave": ("Brave Search API (alternativa a Serper)", "https://api-dashboard.search.brave.com/app/keys"),
    "ai": ("Clave del proveedor de IA (no hace falta con Ollama local)", "https://console.groq.com/keys"),
}

DEFAULT_SETTINGS = {
    "api_keys": {},
    "ai_base_url": "",
    "ai_model": "",
    "default_region": "",
    "sherlock_db": True,
    "include_nsfw": False,
    "username_timeout": 15,
    "max_pivot_entities": 25,
    "lang": "es",
}


class Settings:
    def __init__(self, path: Path = SETTINGS_FILE):
        self.path = path
        self._lock = threading.Lock()
        self.data = dict(DEFAULT_SETTINGS)
        if path.exists():
            try:
                self.data.update(json.loads(path.read_text(encoding="utf-8")))
            except (OSError, ValueError):
                pass

    def get(self, name: str, default=None):
        return self.data.get(name, default)

    def key(self, name: str) -> str | None:
        return (self.data.get("api_keys") or {}).get(name) or None

    def update(self, changes: dict) -> None:
        with self._lock:
            keys = dict(self.data.get("api_keys") or {})
            for k, v in (changes.pop("api_keys", None) or {}).items():
                if k not in API_KEYS:
                    continue
                v = (v or "").strip()
                if v:
                    keys[k] = v
                else:
                    keys.pop(k, None)
            self.data["api_keys"] = keys
            for k, v in changes.items():
                if k in DEFAULT_SETTINGS and k != "api_keys":
                    self.data[k] = v
            self.path.write_text(json.dumps(self.data, indent=2, ensure_ascii=False), encoding="utf-8")

    def public(self) -> dict:
        keys = self.data.get("api_keys") or {}
        out = {k: v for k, v in self.data.items() if k != "api_keys"}
        out["api_keys"] = {
            k: {
                "label": label,
                "url": url,
                "set": bool(keys.get(k)),
                "masked": (keys[k][:3] + "…" + keys[k][-3:]) if len(keys.get(k) or "") > 8 else ("•••" if keys.get(k) else ""),
            }
            for k, (label, url) in API_KEYS.items()
        }
        return out


settings = Settings()
