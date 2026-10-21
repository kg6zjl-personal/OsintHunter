import os
import socket
import sys
import threading
import webbrowser

import uvicorn


def _in_use(host: str, port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.5)
        return s.connect_ex((host, port)) == 0


def main() -> None:
    host = "127.0.0.1"
    port = int(os.environ.get("OSINT_PORT", "8787"))
    url = f"http://{host}:{port}"
    open_browser = "--no-browser" not in sys.argv
    if _in_use(host, port):
        print(f"\n  OsintHunter ya está abierto en {url}\n")
        if open_browser:
            webbrowser.open(url)
        return
    from app.main import app

    if open_browser:
        threading.Timer(1.5, lambda: webbrowser.open(url)).start()
    print(f"\n  OsintHunter funcionando en {url}\n  Cierra esta ventana para detenerlo.\n")
    uvicorn.run(app, host=host, port=port, log_level="warning")


if __name__ == "__main__":
    main()
