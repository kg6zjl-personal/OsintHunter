import hashlib
import io

from PIL import ExifTags, Image

WANTED = {
    "Make": "Marca cámara", "Model": "Modelo cámara", "LensModel": "Objetivo", "Software": "Software",
    "DateTime": "Fecha modificación", "DateTimeOriginal": "Fecha captura", "Artist": "Autor",
    "Copyright": "Copyright", "ImageDescription": "Descripción", "BodySerialNumber": "Nº serie cámara",
    "CameraOwnerName": "Propietario cámara", "XPAuthor": "Autor (Windows)", "XPComment": "Comentario (Windows)",
    "HostComputer": "Equipo",
}


def _ratio(x) -> float:
    try:
        return float(x)
    except (TypeError, ValueError, ZeroDivisionError):
        return 0.0


def _dms(vals, ref) -> float | None:
    try:
        d, m, s = (_ratio(v) for v in vals)
    except (TypeError, ValueError):
        return None
    out = d + m / 60 + s / 3600
    return -out if ref in ("S", "W") else out


def _clean(v):
    if isinstance(v, bytes):
        try:
            return v.decode("utf-16-le" if b"\x00" in v else "utf-8", "ignore").strip("\x00 ").strip()
        except UnicodeDecodeError:
            return None
    return str(v).strip("\x00 ").strip() if v is not None else None


def analyze_image(data: bytes, filename: str) -> dict:
    """Devuelve metadatos, hashes y coordenadas GPS (si existen) de una imagen."""
    out: dict = {
        "Archivo": filename,
        "Tamaño (bytes)": len(data),
        "SHA256": hashlib.sha256(data).hexdigest(),
        "MD5": hashlib.md5(data).hexdigest(),
    }
    img = Image.open(io.BytesIO(data))
    out["Formato"] = img.format
    out["Dimensiones"] = f"{img.width}×{img.height}"
    exif = img.getexif()
    tags = {ExifTags.TAGS.get(k, str(k)): v for k, v in exif.items()}
    try:
        tags.update({ExifTags.TAGS.get(k, str(k)): v for k, v in exif.get_ifd(0x8769).items()})
    except (KeyError, AttributeError):
        pass
    for k, label in WANTED.items():
        v = _clean(tags.get(k))
        if v:
            out[label] = v
    try:
        gps = {ExifTags.GPSTAGS.get(k, str(k)): v for k, v in exif.get_ifd(0x8825).items()}
    except (KeyError, AttributeError):
        gps = {}
    if gps.get("GPSLatitude") and gps.get("GPSLongitude"):
        lat = _dms(gps["GPSLatitude"], gps.get("GPSLatitudeRef"))
        lon = _dms(gps["GPSLongitude"], gps.get("GPSLongitudeRef"))
        if lat is not None and lon is not None and (lat or lon):
            out["_lat"], out["_lon"] = round(lat, 6), round(lon, 6)
            if gps.get("GPSAltitude") is not None:
                out["Altitud (m)"] = round(_ratio(gps["GPSAltitude"]), 1)
    if "xmp" in img.info or b"<x:xmpmeta" in data[:200_000]:
        out["XMP"] = "Contiene metadatos XMP (posible historial de edición)"
    if len(out) <= 8 and "_lat" not in out:
        out["Aviso"] = "Sin metadatos EXIF: probablemente se subió a una red social que los elimina"
    return out
