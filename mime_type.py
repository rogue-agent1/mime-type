#!/usr/bin/env python3
"""mime_type - MIME type detection by extension and magic bytes."""
import sys

EXT_MAP = {
    ".html": "text/html", ".css": "text/css", ".js": "application/javascript",
    ".json": "application/json", ".xml": "application/xml", ".txt": "text/plain",
    ".png": "image/png", ".jpg": "image/jpeg", ".jpeg": "image/jpeg",
    ".gif": "image/gif", ".svg": "image/svg+xml", ".webp": "image/webp",
    ".pdf": "application/pdf", ".zip": "application/zip",
    ".gz": "application/gzip", ".tar": "application/x-tar",
    ".mp3": "audio/mpeg", ".wav": "audio/wav", ".mp4": "video/mp4",
    ".py": "text/x-python", ".md": "text/markdown", ".csv": "text/csv",
}

MAGIC = [
    (b"\x89PNG\r\n\x1a\n", "image/png"),
    (b"\xff\xd8\xff", "image/jpeg"),
    (b"GIF87a", "image/gif"), (b"GIF89a", "image/gif"),
    (b"%PDF", "application/pdf"),
    (b"PK\x03\x04", "application/zip"),
    (b"\x1f\x8b", "application/gzip"),
]

def from_extension(path):
    for ext, mime in sorted(EXT_MAP.items(), key=lambda x: -len(x[0])):
        if path.lower().endswith(ext):
            return mime
    return "application/octet-stream"

def from_bytes(data):
    for magic, mime in MAGIC:
        if data[:len(magic)] == magic:
            return mime
    if all(32 <= b < 127 or b in (9, 10, 13) for b in data[:512]):
        return "text/plain"
    return "application/octet-stream"

def test():
    assert from_extension("style.css") == "text/css"
    assert from_extension("photo.JPG") == "image/jpeg"
    assert from_extension("data.unknown") == "application/octet-stream"
    assert from_bytes(b"\x89PNG\r\n\x1a\n" + b"\x00" * 10) == "image/png"
    assert from_bytes(b"%PDF-1.4") == "application/pdf"
    assert from_bytes(b"Hello world\n") == "text/plain"
    assert from_bytes(b"\x00\x01\x02\xff") == "application/octet-stream"
    print("mime_type: all tests passed")

if __name__ == "__main__":
    test() if "--test" in sys.argv else print("Usage: mime_type.py --test")
