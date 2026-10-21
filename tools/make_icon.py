"""Genera build/osinthunter.ico (una mira naranja sobre fondo negro) para el ejecutable."""
from pathlib import Path

from PIL import Image, ImageDraw

out = Path(__file__).resolve().parent.parent / "build" / "osinthunter.ico"
out.parent.mkdir(exist_ok=True)

ORANGE = (255, 122, 26, 255)
S = 256
img = Image.new("RGBA", (S, S), (0, 0, 0, 0))
d = ImageDraw.Draw(img)
d.rounded_rectangle((8, 8, S - 8, S - 8), radius=56, fill=(13, 10, 7, 255), outline=(58, 42, 26, 255), width=8)
c = S // 2
d.ellipse((c - 76, c - 76, c + 76, c + 76), outline=ORANGE, width=16)
d.ellipse((c - 36, c - 36, c + 36, c + 36), outline=(255, 122, 26, 180), width=12)
d.ellipse((c - 14, c - 14, c + 14, c + 14), fill=(255, 176, 102, 255))
for x0, y0, x1, y1 in ((c - 8, 24, c + 8, 72), (c - 8, S - 72, c + 8, S - 24), (24, c - 8, 72, c + 8), (S - 72, c - 8, S - 24, c + 8)):
    d.rounded_rectangle((x0, y0, x1, y1), radius=8, fill=ORANGE)
img.save(out, sizes=[(16, 16), (24, 24), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)])
print(f"Icono: {out}")
