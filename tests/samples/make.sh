#!/usr/bin/env bash
# Generate the small real sample files under tests/samples/ from self-made
# content, one per format the carver should recover whole and grade
# `verified`. Every file stays under 24 KiB. A format whose generator is
# missing on this machine is skipped with a note; the committed file from a
# previous run is then left as it is.
#
# Generators: Python 3 with Pillow (JPEG, PNG, GIF, PDF) and olefile (CFBF),
# the `wave` module (WAV), `zip`, `ffmpeg` (MP4), `sqlite3`.
#
# Run from the repository root: bash tests/samples/make.sh
set -u
cd "$(dirname "$0")"
PY=${PYTHON:-python3}

have() { command -v "$1" >/dev/null 2>&1; }
skip() { echo "skip: $1 ($2)"; }

if $PY -c 'import PIL' 2>/dev/null; then
  $PY - <<'PYEOF'
from PIL import Image, ImageDraw
import io, struct

def scene(size, seed):
    im = Image.new("RGB", size, (40 + seed * 20, 90, 160))
    d = ImageDraw.Draw(im)
    w, h = size
    for i in range(6):
        x = 2 + i * (w // 6)
        d.rectangle([x, 2, x + max(2, w // 12), h - 3], fill=(220 - i * 30, 60 + i * 25, 30))
    d.ellipse([w // 3, h // 3, w * 2 // 3, h * 2 // 3], outline=(255, 255, 255))
    return im

# JPEG with a JFIF header (Pillow writes it) and an EXIF block whose IFD1
# carries a JPEG thumbnail, built by hand: Pillow reads thumbnails but
# does not write them.
thumb = io.BytesIO()
scene((24, 16), 2).save(thumb, "JPEG", quality=50)
thumb = thumb.getvalue()
def ifd(entries, next_ifd):
    out = struct.pack("<H", len(entries))
    for tag, typ, count, value in entries:
        out += struct.pack("<HHI", tag, typ, count) + value
    return out + struct.pack("<I", next_ifd)
make = b"unearth\0"
# Layout: header(8) IFD0(2+12+4=18) make(8) IFD1(2+24+4=30) thumbnail.
ifd0_off, make_off = 8, 8 + 18
ifd1_off = make_off + len(make)
thumb_off = ifd1_off + 30
ifd0 = ifd([(0x010F, 2, len(make), struct.pack("<I", make_off))], ifd1_off)
ifd1 = ifd([(0x0201, 4, 1, struct.pack("<I", thumb_off)), (0x0202, 4, 1, struct.pack("<I", len(thumb)))], 0)
tiff = b"II*\0" + struct.pack("<I", ifd0_off) + ifd0 + make + ifd1 + thumb
assert len(b"II*\0") + 4 + len(ifd0) == make_off and make_off + len(make) == ifd1_off
scene((96, 64), 1).save("sample.jpg", "JPEG", quality=70, exif=b"Exif\0\0" + tiff)
print("jpg")

scene((80, 48), 3).save("sample.png", "PNG", optimize=True)
print("png")

frames = [scene((48, 32), 4), scene((48, 32), 5)]
frames[0].save("sample.gif", "GIF", save_all=True, append_images=frames[1:], duration=100, loop=0)
print("gif")

scene((60, 40), 6).save("sample.pdf", "PDF", resolution=72)
print("pdf")
PYEOF
else
  skip "jpg png gif pdf" "Pillow is not installed"
fi

if $PY -c 'import wave' 2>/dev/null; then
  $PY - <<'PYEOF'
import wave, struct, math
with wave.open("sample.wav", "wb") as w:
    w.setnchannels(1)
    w.setsampwidth(2)
    w.setframerate(8000)
    frames = b"".join(struct.pack("<h", int(12000 * math.sin(i / 8000 * 2 * math.pi * 440))) for i in range(4000))
    w.writeframes(frames)
print("wav")
PYEOF
else
  skip "wav" "Python wave module missing"
fi

if have zip; then
  rm -f sample.zip
  printf 'first member: the quick brown fox\n' > member1.txt
  printf 'second member: %s\n' "$(seq 1 40 | tr '\n' ' ')" > member2.txt
  zip -q -X sample.zip member1.txt member2.txt
  printf 'unearth sample archive' | zip -q -z sample.zip
  rm -f member1.txt member2.txt
  echo zip
else
  skip "zip" "zip is not installed"
fi

if have ffmpeg; then
  ffmpeg -y -loglevel error -f lavfi -i color=c=black:s=32x32:r=1 -frames:v 1 \
    -c:v libx264 -pix_fmt yuv420p -movflags +faststart sample.mp4 && echo mp4
else
  skip "mp4" "ffmpeg is not installed"
fi

if have sqlite3; then
  rm -f sample.sqlite
  sqlite3 sample.sqlite "PRAGMA page_size=1024; CREATE TABLE notes(id INTEGER PRIMARY KEY, body TEXT); INSERT INTO notes(body) VALUES ('first note'), ('second note'), ('third note'); VACUUM;"
  echo sqlite
else
  skip "sqlite" "sqlite3 is not installed"
fi

if $PY -c 'import olefile' 2>/dev/null; then
  $PY - <<'PYEOF'
import olefile
# olefile writes an OLE2 (CFBF) container from a template; build a minimal
# one by hand with olefile's own writer support for stream data.
import struct, io
# Minimal CFBF: header + FAT sector + directory sector + one stream sector.
SEC = 512
hdr = bytearray(SEC)
hdr[0:8] = b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1"
hdr[0x18:0x1A] = struct.pack("<H", 0x3E)   # minor version
hdr[0x1A:0x1C] = struct.pack("<H", 3)      # major version 3
hdr[0x1C:0x1E] = struct.pack("<H", 0xFFFE) # byte order
hdr[0x1E:0x20] = struct.pack("<H", 9)      # sector shift (512)
hdr[0x20:0x22] = struct.pack("<H", 6)      # mini sector shift
hdr[0x2C:0x30] = struct.pack("<I", 1)      # number of FAT sectors
hdr[0x30:0x34] = struct.pack("<I", 1)      # first directory sector
hdr[0x38:0x3C] = struct.pack("<I", 4096)   # mini stream cutoff
hdr[0x3C:0x40] = struct.pack("<I", 0xFFFFFFFE) # first mini FAT sector: none
hdr[0x44:0x48] = struct.pack("<I", 0xFFFFFFFE) # first DIFAT sector: none
difat = bytearray(b"\xFF" * 436)
difat[0:4] = struct.pack("<I", 0)          # FAT sector 0
hdr[0x4C:0x4C + 436] = difat
# A stream under 4096 bytes would live in the mini stream; this one is
# larger, so it occupies a chain of regular sectors 2..=10.
body = b"unearth CFBF sample stream " * 160
stream_sectors = -(-len(body) // SEC)
fat = bytearray(b"\xFF" * SEC)
fat[0:4] = struct.pack("<I", 0xFFFFFFFD)   # sector 0: FAT itself
fat[4:8] = struct.pack("<I", 0xFFFFFFFE)   # sector 1: directory, end of chain
for s in range(stream_sectors):
    nxt = 2 + s + 1 if s + 1 < stream_sectors else 0xFFFFFFFE
    fat[(2 + s) * 4:(2 + s) * 4 + 4] = struct.pack("<I", nxt)
def dirent(name, typ, start, size, left=0xFFFFFFFF, right=0xFFFFFFFF, child=0xFFFFFFFF):
    e = bytearray(128)
    n = name.encode("utf-16-le") + b"\x00\x00"
    e[0:len(n)] = n
    e[0x40:0x42] = struct.pack("<H", len(n))
    e[0x42] = typ
    e[0x43] = 1
    e[0x44:0x48] = struct.pack("<I", left)
    e[0x48:0x4C] = struct.pack("<I", right)
    e[0x4C:0x50] = struct.pack("<I", child)
    e[0x74:0x78] = struct.pack("<I", start)
    e[0x78:0x7C] = struct.pack("<I", size)
    return e
stream = bytearray(stream_sectors * SEC)
stream[0:len(body)] = body
directory = bytearray(SEC)
directory[0:128] = dirent("Root Entry", 5, 0xFFFFFFFE, 0, child=1)
directory[128:256] = dirent("Contents", 2, 2, len(body))
with open("sample.cfbf", "wb") as f:
    f.write(bytes(hdr) + bytes(fat) + bytes(directory) + bytes(stream))
assert olefile.isOleFile("sample.cfbf")
with olefile.OleFileIO("sample.cfbf") as ole:
    assert ole.openstream("Contents").read() == body
print("cfbf")
PYEOF
else
  skip "cfbf" "olefile is not installed"
fi

ls -l sample.* 2>/dev/null | awk '{ if ($5 > 24576) print "WARNING: " $9 " is over 24 KiB" }'
