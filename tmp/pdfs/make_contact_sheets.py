from pathlib import Path

from PIL import Image, ImageDraw


directory = Path(r"tmp\pdfs\b20-infinity-final-2")
pages = sorted(directory.glob("page-*.png"))

for offset in range(0, len(pages), 4):
    batch = pages[offset : offset + 4]
    images = [Image.open(path).convert("RGB") for path in batch]
    width = max(image.width for image in images)
    height = max(image.height for image in images)
    sheet = Image.new("RGB", (2 * width, 2 * (height + 34)), "white")
    draw = ImageDraw.Draw(sheet)

    for index, (image, path) in enumerate(zip(images, batch)):
        x = (index % 2) * width
        y = (index // 2) * (height + 34) + 34
        sheet.paste(image, (x, y))
        draw.text((x + 10, y - 27), path.stem, fill="black")

    sheet.save(directory / f"sheet-{offset // 4 + 1}.png")
