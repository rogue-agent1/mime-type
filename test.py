from mime_type import from_extension, from_magic, extension_for
assert from_extension("test.png") == "image/png"
assert from_extension("test.json") == "application/json"
assert from_magic(b"\x89PNG\r\n\x1a\n" + b"\x00"*20) == "image/png"
assert from_magic(b"\xff\xd8\xff" + b"\x00"*20) == "image/jpeg"
assert from_magic(b"%PDF-1.4" + b"\x00"*20) == "application/pdf"
assert extension_for("image/png") == ".png"
print("MIME type tests passed")