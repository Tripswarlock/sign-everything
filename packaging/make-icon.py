#!/usr/bin/env python3
"""Генерирует packaging/sign-everything.png в стиле Material 3."""
from pathlib import Path
from PIL import Image, ImageDraw, ImageFont

SIZE = 1024
OUT = Path(__file__).with_name("sign-everything.png")

img = Image.new("RGBA", (SIZE, SIZE), (0, 0, 0, 0))
draw = ImageDraw.Draw(img)
draw.rounded_rectangle(
    (32, 32, SIZE - 32, SIZE - 32),
    radius=210,
    fill=(11, 87, 208, 255),
)

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

text = "S"
bbox = draw.textbbox((0, 0), text, font=font)
x = (SIZE - (bbox[2] - bbox[0])) / 2 - bbox[0]
y = (SIZE - (bbox[3] - bbox[1])) / 2 - bbox[1] - 26
draw.text((x, y), text, font=font, fill=(255, 255, 255, 255))

img.resize((256, 256), Image.Resampling.LANCZOS).save(OUT)
print(OUT)
