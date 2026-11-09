#!/usr/bin/env python3
"""Генерирует packaging/sign-everything.png без внешних ассетов."""
from pathlib import Path
from PIL import Image, ImageDraw, ImageFont

SIZE = 1024
OUT = Path(__file__).with_name("sign-everything.png")

img = Image.new("RGBA", (SIZE, SIZE), (0, 0, 0, 0))
pixels = img.load()
start = (16, 44, 85)
end = (47, 107, 255)
for y in range(SIZE):
    for x in range(SIZE):
        t = (x + y) / (2 * (SIZE - 1))
        r = int(start[0] * (1 - t) + end[0] * t)
        g = int(start[1] * (1 - t) + end[1] * t)
        b = int(start[2] * (1 - t) + end[2] * t)
        pixels[x, y] = (r, g, b, 255)

mask = Image.new("L", (SIZE, SIZE), 0)
ImageDraw.Draw(mask).rounded_rectangle((32, 32, SIZE - 32, SIZE - 32), radius=210, fill=255)
img.putalpha(mask)

font_paths = [
    "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
    r"C:\Windows\Fonts\segoeuib.ttf",
    r"C:\Windows\Fonts\arialbd.ttf",
]
font = None
for path in font_paths:
    try:
        font = ImageFont.truetype(path, 600)
        break
    except OSError:
        continue
if font is None:
    font = ImageFont.load_default()

draw = ImageDraw.Draw(img)
text = "S"
bbox = draw.textbbox((0, 0), text, font=font)
x = (SIZE - (bbox[2] - bbox[0])) / 2 - bbox[0]
y = (SIZE - (bbox[3] - bbox[1])) / 2 - bbox[1] - 26
draw.text((x, y), text, font=font, fill=(255, 255, 255, 255))

img.resize((256, 256), Image.Resampling.LANCZOS).save(OUT)
print(OUT)
