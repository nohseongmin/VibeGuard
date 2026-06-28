"""런처/앱 아이콘 생성 (Pillow).

assets/icon.svg 와 동일한 디자인을 래스터로 그려 icon.png / icon.ico 를 만든다.
디자인: 검은 스퀘어클 배경 + 흰 방패 + 그린 체크(보안 시그니처).
사용: python packaging/generate_icon.py
"""

import os

from PIL import Image, ImageDraw

OUT = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "assets")
BG = (11, 11, 15, 255)
WHITE = (255, 255, 255, 255)
GREEN = (41, 209, 127, 255)

S = 1024
SS = S * 3  # 3x 슈퍼샘플링 후 축소(안티앨리어싱)


def _s(points):
    return [(x * 3, y * 3) for x, y in points]


def render():
    img = Image.new("RGBA", (SS, SS), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)

    # 배경 스퀘어클
    d.rounded_rectangle([0, 0, SS - 1, SS - 1], radius=int(0.225 * SS), fill=BG)

    # 방패 (icon.svg 경로를 다각형으로 근사)
    shield = [
        (300, 256), (724, 256), (740, 272), (740, 528),
        (712, 596), (660, 662), (596, 720), (512, 786),
        (428, 720), (364, 662), (312, 596), (284, 528),
        (284, 272),
    ]
    d.polygon(_s(shield), fill=WHITE)

    # 체크
    check = [(430, 508), (492, 566), (612, 438)]
    d.line(_s(check), fill=GREEN, width=48 * 3, joint="curve")
    for x, y in (check[0], check[-1]):
        r = 24 * 3
        d.ellipse([x * 3 - r, y * 3 - r, x * 3 + r, y * 3 + r], fill=GREEN)

    img = img.resize((S, S), Image.LANCZOS)
    os.makedirs(OUT, exist_ok=True)
    img.save(os.path.join(OUT, "icon.png"))
    img.save(
        os.path.join(OUT, "icon.ico"),
        sizes=[(16, 16), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)],
    )
    print("wrote", os.path.join(OUT, "icon.png"), "and icon.ico")


if __name__ == "__main__":
    render()
