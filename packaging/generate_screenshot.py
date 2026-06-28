"""보고서용 GUI 결과 화면 이미지를 생성한다 (Pillow, 맑은고딕).

브랜드(검정 #0B0B0F / 그린 #29D17F / 플랫)에 맞춘 결과 화면 목업을 그려
assets/screenshot.png 로 저장한다. 결과보고서 '구동 및 시연'에 삽입한다.
"""

import os

from PIL import Image, ImageDraw, ImageFont

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ASSETS = os.path.join(ROOT, "assets")

BG = "#0B0B0F"
SURF = "#15161A"
SURF2 = "#1B1D22"
LINE = "#25272E"
TEXT = "#FFFFFF"
MUTED = "#9BA0A8"
GREEN = "#29D17F"
CRIT = "#FF4D4D"
SLOP = "#C8A2FF"
INK = "#0B0B0F"

W, H = 980, 624

_F = "C:/Windows/Fonts/malgun.ttf"
_FB = "C:/Windows/Fonts/malgunbd.ttf"
_FM = "C:/Windows/Fonts/consola.ttf"


def font(path, size):
    try:
        return ImageFont.truetype(path, size)
    except OSError:
        return ImageFont.load_default()


def main():
    img = Image.new("RGB", (W, H), BG)
    d = ImageDraw.Draw(img)
    f_title = font(_FB, 30)
    f_h = font(_FB, 20)
    f_b = font(_F, 17)
    f_s = font(_F, 15)
    f_m = font(_FM, 14)
    f_score = font(_FB, 40)

    # 헤더: 아이콘 + 제목
    try:
        ic = Image.open(os.path.join(ASSETS, "icon.png")).convert("RGBA").resize((52, 52), Image.LANCZOS)
        img.paste(ic, (28, 26), ic)
    except OSError:
        pass
    d.text((92, 26), "VibeGuard", font=f_title, fill=TEXT)
    d.text((93, 62), "바이브코딩 보안 스캐너 · AI 생성 코드의 취약점과 환각 패키지를 잡아냅니다", font=f_s, fill=MUTED)

    # 요약 카드
    d.rounded_rectangle([28, 100, W - 28, 248], radius=16, fill=SURF, outline=LINE, width=1)
    # 점수 링 (빨강, 등급 F)
    cx, cy, r = 104, 174, 46
    d.ellipse([cx - r, cy - r, cx + r, cy + r], outline=LINE, width=8)
    d.arc([cx - r, cy - r, cx + r, cy + r], start=-90, end=-90 + 6, fill=CRIT, width=8)
    d.text((cx, cy - 6), "0", font=f_score, fill=TEXT, anchor="mm")
    d.text((cx, cy + 26), "/ 100", font=f_s, fill=MUTED, anchor="mm")
    # 등급 배지
    bx = 184
    d.rounded_rectangle([bx, 128, bx + 92, 156], radius=14, fill=CRIT)
    d.text((bx + 46, 142), "등급 F", font=f_h, fill=INK, anchor="mm")
    d.text((bx, 170), "치명적 문제가 있습니다. 배포 전에 반드시 고치세요.", font=f_b, fill=TEXT)
    d.text((bx, 198), "스캔 경로: examples/vibe_coded_app · 파일 3개 · 발견 19건", font=f_s, fill=MUTED)
    # 칩
    chips = [("치명적 4", CRIT), ("높음 8", "#FF8A3D"), ("중간 6", "#FFC53D"), ("낮음 1", "#5AA2FF")]
    cxp = bx
    for label, col in chips:
        wlab = d.textlength(label, font=f_s)
        cw = int(wlab + 38)
        d.rounded_rectangle([cxp, 216, cxp + cw, 240], radius=12, fill=SURF2, outline=LINE, width=1)
        d.ellipse([cxp + 12, 224, cxp + 20, 232], fill=col)
        d.text((cxp + 26, 228), label, font=f_s, fill=TEXT, anchor="lm")
        cxp += cw + 8

    # 발견 카드
    def card(y, accent, badge, title, loc, snippet, tag=None):
        d.rounded_rectangle([28, y, W - 28, y + 96], radius=12, fill=SURF, outline=LINE, width=1)
        d.rounded_rectangle([28, y, 33, y + 96], radius=2, fill=accent)
        d.rounded_rectangle([48, y + 14, 48 + int(d.textlength(badge, font=f_s)) + 18, y + 38], radius=6, fill=accent)
        d.text((48 + 9, y + 26), badge, font=f_s, fill=INK, anchor="lm")
        tx = 48 + int(d.textlength(badge, font=f_s)) + 30
        d.text((tx, y + 26), title, font=f_h, fill=TEXT, anchor="lm")
        d.text((48, y + 52), loc, font=f_m, fill=MUTED)
        d.rounded_rectangle([48, y + 66, W - 44, y + 88], radius=6, fill="#0E0F13", outline=LINE, width=1)
        d.text((58, y + 77), snippet, font=f_m, fill="#D6DAE2", anchor="lm")
        if tag:
            d.rounded_rectangle([W - 44 - 118, y + 14, W - 44, y + 36], radius=6, fill=SLOP)
            d.text((W - 44 - 59, y + 25), tag, font=f_s, fill="#2a1a4a", anchor="mm")

    card(268, CRIT, "치명적", "eval()로 외부 입력 실행 — 원격 코드 실행",
         "examples/vibe_coded_app/server.js:38", "const result = eval(req.query.expr);")
    card(376, "#FF8A3D", "높음", "TLS 인증서 검증 비활성화",
         "examples/vibe_coded_app/server.js:43", "new https.Agent({ rejectUnauthorized: false });")
    card(484, "#FFC53D", "중간", "유명 패키지와 유사한 이름: 'reqeusts'",
         "examples/vibe_coded_app/requirements.txt:1", "reqeusts", tag="공급망/슬롭")

    d.text((28, H - 28), "VibeGuard · 런타임 외부 의존성 0 · 127.0.0.1 로컬 실행", font=f_s, fill=MUTED)

    os.makedirs(ASSETS, exist_ok=True)
    img.save(os.path.join(ASSETS, "screenshot.png"))
    print("wrote", os.path.join(ASSETS, "screenshot.png"))


if __name__ == "__main__":
    main()
