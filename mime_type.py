#!/usr/bin/env python3
"""MIME type detector by extension and magic bytes. Zero dependencies."""
import sys, os

EXT_MAP = {
    ".html": "text/html", ".htm": "text/html", ".css": "text/css",
    ".js": "application/javascript", ".json": "application/json",
    ".xml": "application/xml", ".csv": "text/csv", ".txt": "text/plain",
    ".md": "text/markdown", ".py": "text/x-python", ".sh": "text/x-shellscript",
    ".png": "image/png", ".jpg": "image/jpeg", ".jpeg": "image/jpeg",
    ".gif": "image/gif", ".svg": "image/svg+xml", ".webp": "image/webp",
    ".ico": "image/x-icon", ".bmp": "image/bmp", ".tiff": "image/tiff",
    ".mp3": "audio/mpeg", ".wav": "audio/wav", ".ogg": "audio/ogg",
    ".mp4": "video/mp4", ".webm": "video/webm", ".avi": "video/x-msvideo",
    ".pdf": "application/pdf", ".zip": "application/zip",
    ".gz": "application/gzip", ".tar": "application/x-tar",
    ".wasm": "application/wasm", ".woff": "font/woff", ".woff2": "font/woff2",
    ".ttf": "font/ttf", ".otf": "font/otf", ".yaml": "text/yaml",
    ".yml": "text/yaml", ".toml": "application/toml",
}

MAGIC = [
    (b"\x89PNG\r\n\x1a\n", "image/png"),
    (b"\xff\xd8\xff", "image/jpeg"),
    (b"GIF87a", "image/gif"), (b"GIF89a", "image/gif"),
    (b"RIFF", "audio/wav"),  # could be avi too
    (b"PK\x03\x04", "application/zip"),
    (b"\x1f\x8b", "application/gzip"),
    (b"%PDF", "application/pdf"),
    (b"\x00\x00\x01\x00", "image/x-icon"),
    (b"ID3", "audio/mpeg"), (b"\xff\xfb", "audio/mpeg"),
    (b"OggS", "audio/ogg"),
]

def from_extension(filename):
    _, ext = os.path.splitext(filename.lower())
    return EXT_MAP.get(ext, "application/octet-stream")

def from_magic(data):
    for magic, mime in MAGIC:
        if data[:len(magic)] == magic:
            return mime
    if data[:5] == b"<?xml" or data[:14] == b"<?xml version":
        return "application/xml"
    try:
        data[:1024].decode("utf-8")
        return "text/plain"
    except:
        return "application/octet-stream"

def detect(path):
    ext_type = from_extension(path)
    if ext_type != "application/octet-stream":
        return ext_type
    try:
        with open(path, "rb") as f:
            return from_magic(f.read(32))
    except:
        return ext_type

def extension_for(mime):
    for ext, m in EXT_MAP.items():
        if m == mime: return ext
    return ""

if __name__ == "__main__":
    for f in sys.argv[1:]:
        print(f"{f}: {detect(f)}")
