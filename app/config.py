import json
import os
import sys
import threading
from pathlib import Path

if getattr(sys, "frozen", False):
    BUNDLE = Path(sys._MEIPASS)
    ROOT = Path(sys.executable).resolve().parent
    WEB_DIR = BUNDLE / "web"
    RESOURCES_DIR = BUNDLE / "app" / "resources"
else:
    ROOT = Path(__file__).resolve().parent.parent
    WEB_DIR = ROOT / "web"
    RESOURCES_DIR = Path(__file__).resolve().parent / "resources"


def _env_bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None or raw.strip() == "":
        return default
    return raw.strip().lower() in ("1", "true", "yes", "on")


def _env_lang() -> str | None:
    raw = (os.environ.get("OSINT_LANG") or "").strip().lower()
    return raw if raw in ("en", "es") else None


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
    raise RuntimeError("No writable data directory")


DATA_DIR = _data_dir()
SETTINGS_FILE = DATA_DIR / "settings.json"

API_KEYS: dict[str, tuple[str, str]] = {
    "shodan": ("Shodan", "https://account.shodan.io/"),
    "virustotal": ("VirusTotal", "https://www.virustotal.com/gui/my-apikey"),
    "hunter": ("Hunter.io", "https://hunter.io/api-keys"),
    "abuseipdb": ("AbuseIPDB", "https://www.abuseipdb.com/account/api"),
    "abusech": ("abuse.ch Auth-Key (URLhaus, ThreatFox, MalwareBazaar)", "https://auth.abuse.ch/"),
    "urlscan": ("URLScan.io", "https://urlscan.io/user/profile/"),
    "greynoise": ("GreyNoise Community", "https://viz.greynoise.io/account/api-key"),
    "github": ("GitHub token (raises limit 60 → 5000 req/h)", "https://github.com/settings/tokens"),
    "numverify": ("Numverify", "https://numverify.com/product"),
    "hibp": ("Have I Been Pwned (paid)", "https://haveibeenpwned.com/API/Key"),
    "serper": ("Serper.dev (Google; 2500 free searches)", "https://serper.dev/api-key"),
    "brave": ("Brave Search API", "https://api-dashboard.search.brave.com/app/keys"),
    "ai": ("AI provider key (not needed with local Ollama)", "https://console.groq.com/keys"),
}

# Fork defaults: English UI, Chile modules off. Override with OSINT_LANG / OSINT_ENABLE_CHILE.
DEFAULT_SETTINGS = {
    "api_keys": {},
    "ai_base_url": "",
    "ai_model": "",
    "default_region": "",
    "sherlock_db": True,
    "include_nsfw": False,
    "username_timeout": 15,
    "max_pivot_entities": 25,
    "lang": "en",
    "enable_chile": False,
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
        self._apply_env()

    def _apply_env(self) -> None:
        lang = _env_lang()
        if lang:
            self.data["lang"] = lang
        if "OSINT_ENABLE_CHILE" in os.environ:
            self.data["enable_chile"] = _env_bool("OSINT_ENABLE_CHILE", False)

    def get(self, name: str, default=None):
        return self.data.get(name, default)

    def key(self, name: str) -> str | None:
        return (self.data.get("api_keys") or {}).get(name) or None

    def chile_enabled(self) -> bool:
        return bool(self.data.get("enable_chile"))

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
                    if k == "lang" and v not in ("en", "es"):
                        continue
                    if k == "enable_chile":
                        v = bool(v)
                    self.data[k] = v
            self.path.write_text(json.dumps(self.data, indent=2, ensure_ascii=False), encoding="utf-8")
            self._apply_env()

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
        out["lang_locked"] = _env_lang() is not None
        out["chile_locked"] = "OSINT_ENABLE_CHILE" in os.environ
        return out


settings = Settings()
