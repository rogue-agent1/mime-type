#!/usr/bin/env python3
"""mime_type - MIME type detection from file extensions and magic bytes."""
import sys

EXT_MAP = {
    ".html": "text/html", ".htm": "text/html", ".css": "text/css", ".js": "application/javascript",
    ".json": "application/json", ".xml": "application/xml", ".txt": "text/plain",
    ".csv": "text/csv", ".md": "text/markdown",
    ".png": "image/png", ".jpg": "image/jpeg", ".jpeg": "image/jpeg", ".gif": "image/gif",
    ".svg": "image/svg+xml", ".webp": "image/webp", ".ico": "image/x-icon",
    ".mp3": "audio/mpeg", ".wav": "audio/wav", ".ogg": "audio/ogg", ".flac": "audio/flac",
    ".mp4": "video/mp4", ".webm": "video/webm", ".avi": "video/x-msvideo",
    ".pdf": "application/pdf", ".zip": "application/zip", ".gz": "application/gzip",
    ".tar": "application/x-tar", ".wasm": "application/wasm",
    ".py": "text/x-python", ".rs": "text/x-rust", ".go": "text/x-go",
    ".c": "text/x-c", ".cpp": "text/x-c++", ".java": "text/x-java",
    ".sh": "application/x-sh", ".yaml": "text/yaml", ".yml": "text/yaml",
    ".toml": "application/toml", ".woff2": "font/woff2", ".ttf": "font/ttf",
}

MAGIC = [
    (b"\x89PNG\r\n\x1a\n", "image/png"),
    (b"\xff\xd8\xff", "image/jpeg"),
    (b"GIF87a", "image/gif"), (b"GIF89a", "image/gif"),
    (b"%PDF", "application/pdf"),
    (b"PK\x03\x04", "application/zip"),
    (b"\x1f\x8b", "application/gzip"),
    (b"RIFF", "audio/wav"),
    (b"ID3", "audio/mpeg"),
    (b"\x00\x00\x00", "video/mp4"),
]

def from_extension(filename):
    dot = filename.rfind(".")
    if dot < 0:
        return "application/octet-stream"
    ext = filename[dot:].lower()
    return EXT_MAP.get(ext, "application/octet-stream")

def from_magic(data):
    for sig, mime in MAGIC:
        if data[:len(sig)] == sig:
            return mime
    if all(32 <= b < 127 or b in (9, 10, 13) for b in data[:512]):
        return "text/plain"
    return "application/octet-stream"

def is_text(mime):
    return mime.startswith("text/") or mime in ("application/json", "application/xml", "application/javascript")

def is_image(mime):
    return mime.startswith("image/")

def test():
    assert from_extension("index.html") == "text/html"
    assert from_extension("style.CSS") == "text/css"
    assert from_extension("photo.jpg") == "image/jpeg"
    assert from_extension("data.json") == "application/json"
    assert from_extension("noext") == "application/octet-stream"
    assert from_extension("archive.tar.gz") == "application/gzip"
    assert from_magic(b"\x89PNG\r\n\x1a\n" + b"\x00"*100) == "image/png"
    assert from_magic(b"\xff\xd8\xff\xe0") == "image/jpeg"
    assert from_magic(b"%PDF-1.4") == "application/pdf"
    assert from_magic(b"Hello world\n") == "text/plain"
    assert from_magic(b"\x00\x01\x02\x80\xff") == "application/octet-stream"
    assert is_text("text/html")
    assert is_text("application/json")
    assert not is_text("image/png")
    assert is_image("image/png")
    assert not is_image("text/plain")
    print("All tests passed!")

if __name__ == "__main__":
    test() if "--test" in sys.argv else print("mime_type: MIME type detection. Use --test")
