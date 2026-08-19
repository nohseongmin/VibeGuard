"""VibeGuard 데스크톱 앱 (네이티브 창).

파이썬 표준 라이브러리 tkinter 로만 만든 창이라 외부 의존성이 없다.
실행하면 홈 화면에 세 가지 버튼이 있다: 검사 실행 · 이전 검사 결과 · 설정.
검사 화면에 폴더를 끌어다 놓으면(윈도우는 네이티브 드래그앤드롭) 바로 검사하고
결과를 창 안에서 보여준다. 브라우저도, 로컬 서버도, 터미널도 필요 없다.
"""

from __future__ import annotations

import os
import subprocess
import sys
import threading
import time
import tkinter as tk
from tkinter import filedialog, messagebox
from typing import Any, Callable, Dict, List, Optional

from . import appdata

# 브랜드 색(아이콘·리포트·데모와 동일)
BG, SURF, SURF2, LINE = "#0B0B0F", "#15161A", "#1B1D22", "#25272E"
TEXT, MUTED, GREEN = "#FFFFFF", "#9BA0A8", "#29D17F"
SEV_COLOR = {"CRITICAL": "#FF4D4D", "HIGH": "#FF8A3D", "MEDIUM": "#FFC53D",
             "LOW": "#5AA2FF", "INFO": "#8A8F99"}
SEV_LABEL = {"CRITICAL": "치명적", "HIGH": "높음", "MEDIUM": "중간",
             "LOW": "낮음", "INFO": "정보"}
SEV_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]

MAX_CARDS = 300          # 한 화면에 그릴 최대 카드 수(너무 많으면 창이 느려진다)
_FAMILY = "Malgun Gothic" if sys.platform == "win32" else "Helvetica"
_MONO = "Consolas" if sys.platform == "win32" else "Courier"


def F(size: int, bold: bool = False):
    return (_FAMILY, size, "bold") if bold else (_FAMILY, size)


def MF(size: int):
    return (_MONO, size)


class WindowsDrop:
    """윈도우 네이티브 드래그앤드롭(WM_DROPFILES) 수신기.

    tkinter 자체는 파일 드롭을 지원하지 않으므로 ctypes 로 창 프로시저를 감싸
    드롭된 실제 경로를 받는다. 실패하면 조용히 꺼지고 '폴더 선택' 버튼만 쓴다.
    """

    def __init__(self, root: tk.Tk, on_drop: Callable[[List[str]], None]):
        self.ok = False
        self._keep: List[Any] = []      # 콜백 객체가 GC 되면 크래시하므로 참조를 붙든다
        if sys.platform != "win32":
            return
        try:
            import ctypes
            from ctypes import wintypes

            hwnd = int(root.wm_frame(), 16)
            shell32, user32 = ctypes.windll.shell32, ctypes.windll.user32
            shell32.DragAcceptFiles(wintypes.HWND(hwnd), True)

            WM_DROPFILES, GWLP_WNDPROC = 0x0233, -4
            WNDPROC = ctypes.WINFUNCTYPE(ctypes.c_longlong, wintypes.HWND,
                                         ctypes.c_uint, ctypes.c_ulonglong,
                                         ctypes.c_longlong)
            call = user32.CallWindowProcW
            call.restype = ctypes.c_longlong
            call.argtypes = [ctypes.c_void_p, wintypes.HWND, ctypes.c_uint,
                             ctypes.c_ulonglong, ctypes.c_longlong]
            setfn = getattr(user32, "SetWindowLongPtrW", None) or user32.SetWindowLongW
            setfn.restype = ctypes.c_void_p
            setfn.argtypes = [wintypes.HWND, ctypes.c_int, ctypes.c_void_p]

            prev = []

            def proc(handle, msg, wparam, lparam):
                if msg == WM_DROPFILES:
                    paths = []
                    drop = wintypes.HANDLE(wparam)
                    count = shell32.DragQueryFileW(drop, 0xFFFFFFFF, None, 0)
                    for idx in range(count):
                        size = shell32.DragQueryFileW(drop, idx, None, 0)
                        buf = ctypes.create_unicode_buffer(size + 1)
                        shell32.DragQueryFileW(drop, idx, buf, size + 1)
                        paths.append(buf.value)
                    shell32.DragFinish(drop)
                    if paths:
                        root.after(0, on_drop, paths)
                    return 0
                return call(prev[0], handle, msg, wparam, lparam)

            callback = WNDPROC(proc)
            prev.append(setfn(wintypes.HWND(hwnd), GWLP_WNDPROC,
                              ctypes.cast(callback, ctypes.c_void_p)))
            self._keep += [callback, prev]
            self.ok = bool(prev[0])
        except Exception:
            self.ok = False


def flat_button(parent, text, command, primary=False, small=False):
    """브랜드 색을 그대로 쓰는 납작한 버튼(기본 버튼은 회색이라 직접 칠한다)."""
    bg = GREEN if primary else SURF2
    fg = "#062012" if primary else TEXT
    return tk.Button(parent, text=text, command=command, relief="flat", bd=0,
                     bg=bg, fg=fg, activebackground=bg, activeforeground=fg,
                     font=F(11 if small else 12, bold=primary), cursor="hand2",
                     padx=14 if small else 20, pady=6 if small else 10,
                     highlightthickness=0)


class VibeGuardApp:
    def __init__(self):
        self.settings = appdata.load_settings()
        self.scanning = False
        self._anim_on = False
        self._sev_buttons: Dict[str, tk.Label] = {}

        self.root = tk.Tk()
        self.root.title("VibeGuard — 바이브코딩 보안 스캐너")
        self.root.configure(bg=BG)
        self.root.geometry("980x680")
        self.root.minsize(820, 560)
        self._set_icon()
        self.root.update_idletasks()

        self._build_header()
        self.body = tk.Frame(self.root, bg=BG)
        self.body.pack(fill="both", expand=True)

        self.drop = WindowsDrop(self.root, self._on_drop)
        self.show_home()

    # ---- 뼈대 ------------------------------------------------------------
    def _set_icon(self):
        path = _asset("icon.ico")
        if path and sys.platform == "win32":
            try:
                self.root.iconbitmap(path)
            except tk.TclError:
                pass

    def _build_header(self):
        head = tk.Frame(self.root, bg=BG)
        head.pack(fill="x", padx=26, pady=(20, 6))

        logo = tk.Canvas(head, width=40, height=40, bg=BG, highlightthickness=0)
        logo.pack(side="left")
        logo.create_rectangle(2, 2, 38, 38, fill="#000000", outline=LINE)
        logo.create_polygon(11, 10, 29, 10, 29, 22, 20, 31, 11, 22,
                            fill="#FFFFFF", outline="")
        logo.create_line(15, 19, 19, 23, 26, 15, fill=GREEN, width=3,
                         capstyle="round", joinstyle="round")

        box = tk.Frame(head, bg=BG)
        box.pack(side="left", padx=12)
        tk.Label(box, text="VibeGuard", bg=BG, fg=TEXT, font=F(17, True)).pack(anchor="w")
        self.subtitle = tk.Label(box, text="AI가 만든 코드를 안전하게",
                                 bg=BG, fg=MUTED, font=F(9))
        self.subtitle.pack(anchor="w")

        self.back_btn = flat_button(head, "← 홈", self.show_home, small=True)

    def _nav(self, home: bool, subtitle: str):
        self.subtitle.config(text=subtitle)
        if home:
            self.back_btn.pack_forget()
        else:
            self.back_btn.pack(side="right")
        for widget in self.body.winfo_children():
            widget.destroy()

    # ---- 홈 --------------------------------------------------------------
    def show_home(self):
        self._nav(True, "AI가 만든 코드를 안전하게")
        wrap = tk.Frame(self.body, bg=BG)
        wrap.pack(expand=True)

        tk.Label(wrap, text="무엇을 할까요?", bg=BG, fg=TEXT,
                 font=F(24, True)).pack(pady=(0, 6))
        tk.Label(wrap, text="코딩을 몰라도 됩니다. 검사할 폴더만 있으면 됩니다.",
                 bg=BG, fg=MUTED, font=F(11)).pack(pady=(0, 26))

        menu = [
            ("검사 실행", "폴더를 끌어다 놓으면 바로 검사합니다", self.show_scan, True),
            ("이전 검사 결과", "지난 검사들을 최신순으로 다시 봅니다", self.show_history, False),
            ("설정", "검사 방식과 기록 보관을 바꿉니다", self.show_settings, False),
        ]
        for title, desc, command, primary in menu:
            self._menu_card(wrap, title, desc, command, primary)

    def _menu_card(self, parent, title, desc, command, primary):
        card = tk.Frame(parent, bg=SURF, cursor="hand2",
                        highlightbackground=GREEN if primary else LINE,
                        highlightthickness=1)
        card.pack(fill="x", pady=7)

        inner = tk.Frame(card, bg=SURF, cursor="hand2", width=520)
        inner.pack(fill="x", padx=22, pady=14)
        tk.Label(inner, text=title, bg=SURF, fg=GREEN if primary else TEXT,
                 font=F(15, True), cursor="hand2").pack(anchor="w")
        tk.Label(inner, text=desc, bg=SURF, fg=MUTED, font=F(10),
                 cursor="hand2").pack(anchor="w", pady=(3, 0))

        for widget in (card, inner, *inner.winfo_children()):
            widget.bind("<Button-1>", lambda _e, c=command: c())

    # ---- 검사 화면 -------------------------------------------------------
    def show_scan(self):
        self._nav(False, "검사 실행")
        wrap = tk.Frame(self.body, bg=BG)
        wrap.pack(expand=True, fill="both", padx=40, pady=10)

        zone = tk.Frame(wrap, bg=SURF, highlightbackground=LINE, highlightthickness=2)
        zone.pack(expand=True, fill="both", pady=(0, 14))

        inner = tk.Frame(zone, bg=SURF)
        inner.place(relx=.5, rely=.5, anchor="center")
        tk.Label(inner, text="📁", bg=SURF, fg=TEXT, font=F(46)).pack()
        tk.Label(inner, text="검사할 폴더를 여기에 끌어다 놓으세요",
                 bg=SURF, fg=TEXT, font=F(16, True)).pack(pady=(10, 4))
        hint = ("드래그앤드롭이 준비되었습니다. 폴더를 창 위로 끌어다 놓으세요."
                if self.drop.ok else
                "이 환경에서는 드래그앤드롭 대신 아래 버튼을 사용하세요.")
        tk.Label(inner, text=hint, bg=SURF, fg=MUTED, font=F(10)).pack(pady=(0, 16))
        flat_button(inner, "폴더 선택", self._pick_folder, primary=True).pack()

        mode = ("실시간 조회 켜짐 (가짜 패키지 · CVE)" if self.settings["online_lookup"]
                else "오프라인 모드 (네트워크 조회 안 함)")
        tk.Label(wrap, text="현재 설정: " + mode, bg=BG, fg=MUTED, font=F(9)).pack()

    def _pick_folder(self):
        path = filedialog.askdirectory(title="검사할 폴더 선택")
        if path:
            self.start_scan(path)

    def _on_drop(self, paths: List[str]):
        target = next((p for p in paths if os.path.isdir(p)), None) or paths[0]
        if os.path.exists(target):
            self.start_scan(target)

    # ---- 검사 실행 -------------------------------------------------------
    def start_scan(self, path: str):
        if self.scanning:
            return
        if not os.path.exists(path):
            messagebox.showerror("경로 없음", "이 경로를 찾을 수 없습니다.\n\n%s" % path)
            self.show_scan()
            return
        self.scanning = True
        self._nav(False, "검사 중")
        wrap = tk.Frame(self.body, bg=BG)
        wrap.pack(expand=True)

        tk.Label(wrap, text="검사 중…", bg=BG, fg=TEXT, font=F(22, True)).pack(pady=(0, 8))
        tk.Label(wrap, text=path, bg=BG, fg=MUTED, font=MF(9),
                 wraplength=620).pack(pady=(0, 18))
        dots = tk.Label(wrap, text="●○○", bg=BG, fg=GREEN, font=F(18))
        dots.pack()
        tk.Label(wrap, text="파일을 읽고, 의존성의 알려진 취약점을 조회하고 있습니다.",
                 bg=BG, fg=MUTED, font=F(10)).pack(pady=(16, 0))

        self._anim_on = True

        def spin(idx=0):
            if not self._anim_on or not dots.winfo_exists():
                return
            dots.config(text=["●○○", "○●○", "○○●"][idx % 3])
            self.root.after(320, spin, idx + 1)
        spin()

        def work():
            from .server import build_scan_payload
            payload, error = None, None
            try:
                payload = build_scan_payload(
                    path,
                    offline=not self.settings["online_lookup"],
                    exclude=self.settings["exclude"],
                    timeout=8.0,
                )
            except Exception as exc:      # 창이 죽지 않도록 오류를 화면에 알린다
                error = str(exc)
            self.root.after(0, self._scan_done, payload, error)

        threading.Thread(target=work, daemon=True).start()

    def _scan_done(self, payload, error):
        self._anim_on = False
        self.scanning = False
        if payload is None:
            messagebox.showerror("검사 실패", "검사 중 오류가 발생했습니다.\n\n%s" % error)
            self.show_scan()
            return
        try:
            appdata.save_scan(payload, limit=self.settings["history_limit"])
        except OSError:
            pass                          # 기록 저장 실패가 결과 표시를 막지는 않는다
        self.show_result(payload)

    # ---- 결과 화면 -------------------------------------------------------
    def show_result(self, payload: Dict[str, Any]):
        self._nav(False, "검사 결과")
        wrap = tk.Frame(self.body, bg=BG)
        wrap.pack(fill="both", expand=True, padx=26, pady=(0, 10))

        top = tk.Frame(wrap, bg=SURF, highlightbackground=LINE, highlightthickness=1)
        top.pack(fill="x", pady=(0, 12))
        row = tk.Frame(top, bg=SURF)
        row.pack(fill="x", padx=20, pady=16)

        score = int(payload.get("score", 0))
        color = self._grade_color(score)
        ring = tk.Canvas(row, width=112, height=112, bg=SURF, highlightthickness=0)
        ring.pack(side="left")
        ring.create_oval(8, 8, 104, 104, outline=SURF2, width=10)
        if score > 0:
            ring.create_arc(8, 8, 104, 104, start=90, extent=-359.9 * score / 100,
                            style="arc", outline=color, width=10)
        ring.create_text(56, 50, text=str(score), fill=TEXT, font=F(26, True))
        ring.create_text(56, 72, text="/ 100", fill=MUTED, font=F(8))

        info = tk.Frame(row, bg=SURF)
        info.pack(side="left", padx=18, fill="x", expand=True)
        tk.Label(info, text="등급 %s" % payload.get("grade", "-"), bg=color,
                 fg="#0B0B0F", font=F(12, True), padx=12, pady=1).pack(anchor="w")
        tk.Label(info, text=payload.get("verdict", ""), bg=SURF, fg=TEXT, font=F(12),
                 wraplength=560, justify="left").pack(anchor="w", pady=(8, 2))
        tk.Label(info, text="%s · 파일 %d개 · 발견 %d건" % (
            _short(payload.get("path", "")), payload.get("files_scanned", 0),
            payload.get("total", 0)), bg=SURF, fg=MUTED, font=F(9),
            wraplength=560, justify="left").pack(anchor="w")

        counts = payload.get("counts", {})
        chips = tk.Frame(info, bg=SURF)
        chips.pack(anchor="w", pady=(10, 0))
        for name in SEV_ORDER:
            count = counts.get(name, 0)
            if not count:
                continue
            chip = tk.Frame(chips, bg=SURF2, highlightbackground=LINE, highlightthickness=1)
            chip.pack(side="left", padx=(0, 7))
            tk.Label(chip, text="●", bg=SURF2, fg=SEV_COLOR[name],
                     font=F(9)).pack(side="left", padx=(8, 3), pady=3)
            tk.Label(chip, text="%s %d" % (SEV_LABEL[name], count), bg=SURF2,
                     fg=TEXT, font=F(9)).pack(side="left", padx=(0, 9))

        acts = tk.Frame(wrap, bg=BG)
        acts.pack(fill="x", pady=(0, 8))
        flat_button(acts, "다시 검사", self.show_scan, primary=True, small=True).pack(side="left")
        flat_button(acts, "이전 결과 보기", self.show_history, small=True).pack(side="left", padx=8)

        findings = payload.get("findings", [])
        floor = (SEV_ORDER.index(self.settings["min_severity"])
                 if self.settings["min_severity"] in SEV_ORDER else len(SEV_ORDER) - 1)
        shown = [f for f in findings
                 if SEV_ORDER.index(f.get("severity", "INFO")) <= floor]
        hidden = len(findings) - len(shown)

        list_frame = tk.Frame(wrap, bg=BG)
        list_frame.pack(fill="both", expand=True)
        inner = self._scrollable(list_frame)

        if not payload.get("files_scanned"):
            tk.Label(inner, text="검사할 코드 파일을 찾지 못했습니다.\n"
                                 "이 폴더에 소스코드가 있는지 확인해 주세요.",
                     bg=SURF, fg=SEV_COLOR["MEDIUM"], font=F(13, True), pady=28,
                     justify="center").pack(fill="x")
            return
        if not findings:
            tk.Label(inner, text="문제를 발견하지 못했습니다. 안전합니다!",
                     bg=SURF, fg=GREEN, font=F(13, True), pady=28).pack(fill="x")
            return
        if hidden:
            tk.Label(inner, text="설정한 최소 심각도(%s)보다 낮은 %d건은 숨겼습니다."
                     % (SEV_LABEL[self.settings["min_severity"]], hidden),
                     bg=BG, fg=MUTED, font=F(9)).pack(anchor="w", pady=(0, 6))
        for finding in shown[:MAX_CARDS]:
            self._finding_card(inner, finding)
        if len(shown) > MAX_CARDS:
            tk.Label(inner, text="… 외 %d건" % (len(shown) - MAX_CARDS),
                     bg=BG, fg=MUTED, font=F(9)).pack(anchor="w", pady=6)

    def _finding_card(self, parent, finding: Dict[str, Any]):
        sev = finding.get("severity", "INFO")
        color = SEV_COLOR.get(sev, MUTED)
        card = tk.Frame(parent, bg=SURF, highlightbackground=LINE, highlightthickness=1)
        card.pack(fill="x", pady=4)
        tk.Frame(card, bg=color, width=4).pack(side="left", fill="y")

        box = tk.Frame(card, bg=SURF)
        box.pack(side="left", fill="x", expand=True, padx=14, pady=11)

        head = tk.Frame(box, bg=SURF)
        head.pack(fill="x")
        tk.Label(head, text=SEV_LABEL.get(sev, sev), bg=color, fg="#0B0B0F",
                 font=F(8, True), padx=7).pack(side="left")
        tk.Label(head, text=finding.get("title", ""), bg=SURF, fg=TEXT, font=F(11, True),
                 wraplength=560, justify="left").pack(side="left", padx=8)
        rule = finding.get("rule_id", "")
        tk.Label(head, text=rule, bg=SURF2, fg=MUTED, font=MF(8), padx=6).pack(side="left")
        if "SLOP" in rule:
            tk.Label(head, text="공급망/슬롭스쿼팅", bg="#C8A2FF", fg="#2a1a4a",
                     font=F(8, True), padx=6).pack(side="left", padx=5)
        elif "CVE" in rule:
            tk.Label(head, text="알려진 취약점(CVE)", bg=GREEN, fg="#0B0B0F",
                     font=F(8, True), padx=6).pack(side="left", padx=5)

        tk.Label(box, text="%s:%s" % (finding.get("file", ""), finding.get("line", "")),
                 bg=SURF, fg=MUTED, font=MF(8), wraplength=700,
                 justify="left").pack(anchor="w", pady=(6, 2))
        snippet = (finding.get("snippet") or "").strip()
        if snippet:
            tk.Label(box, text=snippet[:200], bg="#0E0F13", fg="#D6DAE2", font=MF(9),
                     wraplength=700, justify="left", anchor="w", padx=8,
                     pady=5).pack(anchor="w", fill="x")
        for key, label in (("explanation", "설명"), ("fix", "해결")):
            value = (finding.get(key) or "").strip()
            if not value:
                continue
            line = tk.Frame(box, bg=SURF)
            line.pack(fill="x", pady=(5, 0))
            tk.Label(line, text=label, bg=SURF, fg=GREEN, font=F(9, True),
                     width=4, anchor="w").pack(side="left")
            tk.Label(line, text=value, bg=SURF, fg=TEXT if key == "fix" else MUTED,
                     font=F(9), wraplength=640, justify="left").pack(side="left")

    # ---- 이전 검사 결과 ---------------------------------------------------
    def show_history(self):
        self._nav(False, "이전 검사 결과")
        wrap = tk.Frame(self.body, bg=BG)
        wrap.pack(fill="both", expand=True, padx=26, pady=(0, 14))

        scans = appdata.list_scans()
        head = tk.Frame(wrap, bg=BG)
        head.pack(fill="x", pady=(0, 10))
        tk.Label(head, text="최신순 %d건" % len(scans), bg=BG, fg=MUTED,
                 font=F(10)).pack(side="left")
        if scans:
            flat_button(head, "기록 전체 삭제", self._clear_history,
                        small=True).pack(side="right")

        inner = self._scrollable(wrap)
        if not scans:
            tk.Label(inner, text="아직 검사 기록이 없습니다.\n'검사 실행'으로 첫 검사를 해보세요.",
                     bg=SURF, fg=MUTED, font=F(12), pady=34,
                     justify="center").pack(fill="x")
            return
        for item in scans:
            self._history_row(inner, item)

    def _history_row(self, parent, item: Dict[str, Any]):
        color = self._grade_color(int(item.get("score", 0)))
        row = tk.Frame(parent, bg=SURF, highlightbackground=LINE,
                       highlightthickness=1, cursor="hand2")
        row.pack(fill="x", pady=4)
        box = tk.Frame(row, bg=SURF, cursor="hand2")
        box.pack(fill="x", padx=16, pady=12)

        left = tk.Frame(box, bg=SURF, cursor="hand2")
        left.pack(side="left", fill="x", expand=True)
        when = time.strftime("%Y-%m-%d %H:%M", time.localtime(item.get("scanned_at", 0)))
        tk.Label(left, text=when, bg=SURF, fg=TEXT, font=F(11, True),
                 cursor="hand2").pack(anchor="w")
        tk.Label(left, text=_short(item.get("path", "")), bg=SURF, fg=MUTED,
                 font=MF(8), cursor="hand2").pack(anchor="w", pady=(2, 0))

        right = tk.Frame(box, bg=SURF, cursor="hand2")
        right.pack(side="right")
        tk.Label(right, text="%d점 · %s" % (item.get("score", 0), item.get("grade", "-")),
                 bg=color, fg="#0B0B0F", font=F(10, True), padx=10,
                 cursor="hand2").pack(side="right")
        tk.Label(right, text="발견 %d건" % item.get("total", 0), bg=SURF, fg=MUTED,
                 font=F(9), cursor="hand2").pack(side="right", padx=10)

        def open_it(_event=None, path=item["file"]):
            try:
                self.show_result(appdata.load_scan(path))
            except (OSError, ValueError):
                messagebox.showerror("열 수 없음", "기록 파일을 읽을 수 없습니다.")

        for widget in (row, box, left, right,
                       *left.winfo_children(), *right.winfo_children()):
            widget.bind("<Button-1>", open_it)

    def _clear_history(self):
        if messagebox.askyesno("기록 삭제", "지난 검사 기록을 모두 지울까요?"):
            appdata.clear_history()
            self.show_history()

    # ---- 설정 ------------------------------------------------------------
    def show_settings(self):
        self._nav(False, "설정")
        wrap = tk.Frame(self.body, bg=BG)
        wrap.pack(fill="both", expand=True, padx=26, pady=(0, 14))
        inner = self._scrollable(wrap)

        online = tk.BooleanVar(value=self.settings["online_lookup"])
        sev = tk.StringVar(value=self.settings["min_severity"])
        exclude = tk.StringVar(value=", ".join(self.settings["exclude"]))
        limit = tk.StringVar(value=str(self.settings["history_limit"]))

        box = self._section(inner, "검사 방식")
        tk.Checkbutton(box, text="  실시간 조회 사용 (가짜 패키지 · 알려진 취약점 CVE)",
                       variable=online, bg=SURF, fg=TEXT, font=F(11), selectcolor=SURF2,
                       activebackground=SURF, activeforeground=TEXT, bd=0,
                       highlightthickness=0, anchor="w",
                       cursor="hand2").pack(fill="x", pady=(2, 2))
        tk.Label(box, text="끄면 인터넷 없이 코드 규칙만 검사합니다. 켜면 항상 최신 CVE가 반영됩니다.",
                 bg=SURF, fg=MUTED, font=F(9), wraplength=640,
                 justify="left").pack(anchor="w", padx=26)

        box2 = self._section(inner, "결과에 표시할 최소 심각도")
        chips = tk.Frame(box2, bg=SURF)
        chips.pack(anchor="w", pady=4)
        self._sev_buttons = {}
        for name in SEV_ORDER:
            chip = tk.Label(chips, text=SEV_LABEL[name], bg=SURF2, fg=TEXT, font=F(10),
                            padx=14, pady=6, cursor="hand2")
            chip.pack(side="left", padx=(0, 7))
            chip.bind("<Button-1>", lambda _e, n=name: self._pick_sev(sev, n))
            self._sev_buttons[name] = chip
        self._pick_sev(sev, sev.get())
        tk.Label(box2, text="선택한 등급보다 낮은 항목은 목록에서 숨깁니다(점수는 전체 기준).",
                 bg=SURF, fg=MUTED, font=F(9), wraplength=640,
                 justify="left").pack(anchor="w", pady=(4, 0))

        box3 = self._section(inner, "검사에서 제외할 폴더")
        tk.Entry(box3, textvariable=exclude, bg="#0E0F13", fg=TEXT, font=MF(10),
                 insertbackground=TEXT, relief="flat", highlightthickness=1,
                 highlightbackground=LINE,
                 highlightcolor=GREEN).pack(fill="x", ipady=6, pady=3)
        tk.Label(box3, text="쉼표로 구분해 입력하세요. (.git, node_modules 등은 기본으로 제외됩니다)",
                 bg=SURF, fg=MUTED, font=F(9)).pack(anchor="w")

        box4 = self._section(inner, "검사 기록")
        row = tk.Frame(box4, bg=SURF)
        row.pack(fill="x", pady=3)
        tk.Label(row, text="보관 개수", bg=SURF, fg=TEXT, font=F(10)).pack(side="left")
        tk.Entry(row, textvariable=limit, width=6, bg="#0E0F13", fg=TEXT, font=MF(10),
                 insertbackground=TEXT, relief="flat", highlightthickness=1,
                 highlightbackground=LINE,
                 justify="center").pack(side="left", padx=10, ipady=4)
        flat_button(row, "저장 폴더 열기", self._open_data_dir, small=True).pack(side="left")
        tk.Label(box4, text=appdata.app_dir(), bg=SURF, fg=MUTED, font=MF(8),
                 wraplength=640, justify="left").pack(anchor="w", pady=(6, 0))

        bar = tk.Frame(inner, bg=BG)
        bar.pack(fill="x", pady=14)
        flat_button(bar, "저장",
                    lambda: self._save_settings(online, sev, exclude, limit),
                    primary=True).pack(side="left")
        flat_button(bar, "기본값으로", self._reset_settings, small=True).pack(side="left", padx=8)

    def _save_settings(self, online, sev, exclude, limit):
        self.settings["online_lookup"] = bool(online.get())
        self.settings["min_severity"] = sev.get()
        self.settings["exclude"] = [x.strip() for x in exclude.get().split(",") if x.strip()]
        try:
            self.settings["history_limit"] = max(1, min(500, int(limit.get())))
        except ValueError:
            self.settings["history_limit"] = appdata.DEFAULT_SETTINGS["history_limit"]
        try:
            appdata.save_settings(self.settings)
        except OSError as exc:
            messagebox.showerror("저장 실패", "설정을 저장하지 못했습니다.\n%s" % exc)
            return
        messagebox.showinfo("저장됨", "설정을 저장했습니다.")
        self.show_home()

    def _pick_sev(self, var: tk.StringVar, name: str):
        var.set(name)
        for key, widget in self._sev_buttons.items():
            on = key == name
            widget.config(bg=GREEN if on else SURF2, fg="#062012" if on else TEXT)

    def _reset_settings(self):
        self.settings = dict(appdata.DEFAULT_SETTINGS)
        try:
            appdata.save_settings(self.settings)
        except OSError:
            pass
        self.show_settings()

    def _open_data_dir(self):
        path = appdata.app_dir()
        try:
            if sys.platform == "win32":
                os.startfile(path)                    # 사용자 자신의 데이터 폴더
            elif sys.platform == "darwin":
                subprocess.run(["open", path], check=False)
            else:
                subprocess.run(["xdg-open", path], check=False)
        except OSError as exc:
            messagebox.showerror("열 수 없음", str(exc))

    # ---- 공통 부품 -------------------------------------------------------
    def _section(self, parent, title: str) -> tk.Frame:
        tk.Label(parent, text=title, bg=BG, fg=GREEN, font=F(11, True)).pack(
            anchor="w", pady=(12, 5))
        box = tk.Frame(parent, bg=SURF, highlightbackground=LINE, highlightthickness=1)
        box.pack(fill="x")
        pad = tk.Frame(box, bg=SURF)
        pad.pack(fill="x", padx=16, pady=12)
        return pad

    def _scrollable(self, parent) -> tk.Frame:
        canvas = tk.Canvas(parent, bg=BG, highlightthickness=0)
        bar = tk.Scrollbar(parent, orient="vertical", command=canvas.yview,
                           bg=SURF2, troughcolor=BG, bd=0, relief="flat",
                           activebackground=GREEN, highlightthickness=0)
        inner = tk.Frame(canvas, bg=BG)
        window = canvas.create_window((0, 0), window=inner, anchor="nw")
        inner.bind("<Configure>",
                   lambda _e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.bind("<Configure>", lambda e: canvas.itemconfig(window, width=e.width))
        canvas.configure(yscrollcommand=bar.set)
        canvas.pack(side="left", fill="both", expand=True)
        bar.pack(side="right", fill="y")

        def wheel(event):
            if canvas.winfo_exists():
                canvas.yview_scroll(int(-event.delta / 120), "units")
        canvas.bind_all("<MouseWheel>", wheel)
        return inner

    @staticmethod
    def _grade_color(score: int) -> str:
        if score >= 90:
            return GREEN
        if score >= 75:
            return "#7ED957"
        if score >= 60:
            return SEV_COLOR["MEDIUM"]
        if score >= 40:
            return SEV_COLOR["HIGH"]
        return SEV_COLOR["CRITICAL"]

    def run(self) -> int:
        self.root.mainloop()
        return 0


def _asset(name: str) -> Optional[str]:
    """PyInstaller 로 묶였을 때와 소스 실행 모두에서 assets 파일을 찾는다."""
    roots = [getattr(sys, "_MEIPASS", None),
             os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                          "assets")]
    for root in roots:
        if not root:
            continue
        for candidate in (os.path.join(root, name), os.path.join(root, "assets", name)):
            if os.path.isfile(candidate):
                return candidate
    return None


def _short(path: str, limit: int = 70) -> str:
    return path if len(path) <= limit else "…" + path[-(limit - 1):]


def target_from_args(argv: List[str]) -> Optional[str]:
    """실행 인자에서 검사할 경로를 고른다.

    공백이 든 경로("C:/My Code")가 따옴표 없이 들어와 여러 인자로 쪼개지는 경우가
    있어, 먼저 전부 이어붙인 형태를 확인한 뒤 개별 인자를 본다.
    """
    argv = [a for a in argv if a]
    if not argv:
        return None
    joined = " ".join(argv)
    if os.path.exists(joined):
        return joined
    return next((a for a in argv if os.path.exists(a)), None)


def main(argv: Optional[List[str]] = None) -> int:
    """앱 실행. 인자로 경로가 오면(아이콘에 드롭) 그 폴더를 바로 검사한다."""
    argv = list(sys.argv[1:] if argv is None else argv)
    app = VibeGuardApp()
    target = target_from_args(argv)
    if target:
        app.root.after(120, app.start_scan, target)
    return app.run()


if __name__ == "__main__":
    raise SystemExit(main())
