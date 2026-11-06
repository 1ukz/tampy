"""TAMPY terminal UI: themed, animated, and TTY-aware.

A single place for the tool's look and feel -- a gradient banner, a boot
sequence, themed status lines, section headers, spinners and progress bars.

Design rules:
* **Truecolor with graceful fallback.** 24-bit gradients when the terminal
  supports them, plain text when it does not.
* **Never break non-interactive use.** All animation and colour is disabled
  automatically when stdout is not a TTY, when ``NO_COLOR`` is set, or when
  ``TERM=dumb`` -- so piped output, logs, CI and the app pane stay clean.
* **Animation is opt-outable** with ``TAMPY_NO_ANIM`` (or ``--no-anim`` wired by
  the caller) while colour stays on.
"""

from __future__ import annotations

import os
import sys
import threading
import time
from typing import Iterable, Optional, Tuple

RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"
ITALIC = "\033[3m"
HIDE_CURSOR = "\033[?25l"
SHOW_CURSOR = "\033[?25h"

RGB = Tuple[int, int, int]

# Theme palette (toxic green -> cyan, a classic offensive-tooling look).
C_START: RGB = (57, 255, 136)  # green
C_END: RGB = (0, 183, 255)  # cyan
C_ACCENT: RGB = (0, 183, 255)
C_WARN: RGB = (255, 190, 60)
C_ERR: RGB = (255, 85, 95)
C_OK: RGB = (57, 255, 136)
C_MUTE: RGB = (130, 140, 150)


# --------------------------------------------------------------------------- #
# Capability detection
# --------------------------------------------------------------------------- #
def color_enabled() -> bool:
    if os.environ.get("NO_COLOR") is not None:
        return False
    if os.environ.get("TERM") == "dumb":
        return False
    try:
        return sys.stdout.isatty()
    except Exception:
        return False


def anim_enabled() -> bool:
    return color_enabled() and os.environ.get("TAMPY_NO_ANIM") is None


def _truecolor() -> bool:
    return os.environ.get("COLORTERM", "").lower() in ("truecolor", "24bit")


# --------------------------------------------------------------------------- #
# Colour primitives
# --------------------------------------------------------------------------- #
def fg(rgb: RGB) -> str:
    if not color_enabled():
        return ""
    r, g, b = rgb
    return f"\033[38;2;{r};{g};{b}m"


def paint(text: str, rgb: RGB, bold: bool = False) -> str:
    if not color_enabled():
        return text
    return f"{BOLD if bold else ''}{fg(rgb)}{text}{RESET}"


def _lerp(a: int, b: int, t: float) -> int:
    return int(round(a + (b - a) * t))


def _mix(c1: RGB, c2: RGB, t: float) -> RGB:
    return (_lerp(c1[0], c2[0], t), _lerp(c1[1], c2[1], t), _lerp(c1[2], c2[2], t))


def gradient(text: str, c1: RGB = C_START, c2: RGB = C_END, bold: bool = True) -> str:
    """Colour each character along a c1->c2 gradient."""
    if not color_enabled():
        return text
    n = max(len(text) - 1, 1)
    out = [BOLD] if bold else []
    for i, ch in enumerate(text):
        out.append(fg(_mix(c1, c2, i / n)) + ch)
    out.append(RESET)
    return "".join(out)


# --------------------------------------------------------------------------- #
# Banner
# --------------------------------------------------------------------------- #
_BANNER = r"""
 ████████╗ █████╗ ███╗   ███╗██████╗ ██╗   ██╗
 ╚══██╔══╝██╔══██╗████╗ ████║██╔══██╗╚██╗ ██╔╝
    ██║   ███████║██╔████╔██║██████╔╝ ╚████╔╝
    ██║   ██╔══██║██║╚██╔╝██║██╔═══╝   ╚██╔╝
    ██║   ██║  ██║██║ ╚═╝ ██║██║        ██║
    ╚═╝   ╚═╝  ╚═╝╚═╝     ╚═╝╚═╝        ╚═╝
"""

_TAGLINE = "E-Commerce Business-Logic Security Assessment"


def banner(version: str = "2.0", author: str = "@1ukz") -> None:
    """Render the TAMPY banner with a vertical gradient (animated if possible)."""
    lines = [ln for ln in _BANNER.splitlines() if ln.strip("")]
    # drop the leading empty line but keep internal spacing
    lines = _BANNER.splitlines()[1:]
    n = max(len(lines) - 1, 1)

    animate = anim_enabled()
    if animate:
        sys.stdout.write(HIDE_CURSOR)
    try:
        for i, ln in enumerate(lines):
            colored = (
                "".join(fg(_mix(C_START, C_END, i / n)) + ch for ch in ln) + RESET
                if color_enabled()
                else ln
            )
            print(BOLD + colored if color_enabled() else ln)
            if animate:
                time.sleep(0.045)
    finally:
        if animate:
            sys.stdout.write(SHOW_CURSOR)
            sys.stdout.flush()

    sub = f"  {paint('v' + version, C_ACCENT, bold=True)}  {paint('·', C_MUTE)}  {paint(_TAGLINE, C_MUTE)}"
    credit = f"  {paint('·', C_MUTE)}  {paint('by ' + author, C_MUTE)}"
    if animate:
        _typewriter(
            "  " + _TAGLINE,
            C_MUTE,
            delay=0.008,
            prefix=f"  {paint('v' + version, C_ACCENT, bold=True)}  {paint('·', C_MUTE)}",
        )
        print(credit)
    else:
        print(sub + credit)
    print(rule())
    print()


# --------------------------------------------------------------------------- #
# Text effects
# --------------------------------------------------------------------------- #
def _typewriter(text: str, rgb: RGB = C_MUTE, delay: float = 0.01, prefix: str = "") -> None:
    if prefix:
        sys.stdout.write(prefix + " ")
    if not anim_enabled():
        print(paint(text.strip(), rgb))
        return
    for ch in text:
        sys.stdout.write(paint(ch, rgb))
        sys.stdout.flush()
        time.sleep(delay)
    sys.stdout.write("\n")
    sys.stdout.flush()


def typewriter(text: str, rgb: RGB = C_MUTE, delay: float = 0.01) -> None:
    _typewriter(text, rgb, delay)


def rule(width: Optional[int] = None) -> str:
    try:
        w = width or min(os.get_terminal_size().columns, 64)
    except Exception:
        w = width or 64
    line = "─" * w
    return gradient(line, C_START, C_END, bold=False) if color_enabled() else line


# --------------------------------------------------------------------------- #
# Status lines
# --------------------------------------------------------------------------- #
_ICONS = {
    "ok": ("✔", C_OK),
    "info": ("•", C_ACCENT),
    "run": ("»", C_ACCENT),
    "warn": ("!", C_WARN),
    "err": ("✖", C_ERR),
    "hit": ("◆", C_ERR),  # a live/confirmed finding
}


def status(kind: str, msg: str) -> None:
    icon, color = _ICONS.get(kind, ("•", C_ACCENT))
    tag = paint(f"[{icon}]", color, bold=True)
    print(f"{tag} {msg}")


def ok(msg: str) -> None:
    status("ok", msg)


def info(msg: str) -> None:
    status("info", msg)


def warn(msg: str) -> None:
    status("warn", msg)


def err(msg: str) -> None:
    status("err", msg)


def hit(msg: str) -> None:
    status("hit", msg)


# --------------------------------------------------------------------------- #
# Section header
# --------------------------------------------------------------------------- #
def section(label: str, subtitle: str = "") -> None:
    bar = paint("▌", C_ACCENT, bold=True)
    title = gradient(label.upper(), C_START, C_END)
    print()
    print(f"{bar} {title}")
    if subtitle:
        print(f"  {paint(subtitle, C_MUTE)}")
    print(paint("  " + "─" * max(len(label), len(subtitle)), C_MUTE) if color_enabled() else "")


# --------------------------------------------------------------------------- #
# Boot sequence
# --------------------------------------------------------------------------- #
def boot(steps: Iterable[str], delay: float = 0.12) -> None:
    """Show an animated [ OK ] boot checklist."""
    for step in steps:
        if anim_enabled():
            frames = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"
            end = time.time() + delay
            i = 0
            while time.time() < end:
                sys.stdout.write(
                    f"\r  {paint('[' + frames[i % len(frames)] + ']', C_ACCENT)} {step} "
                )
                sys.stdout.flush()
                time.sleep(0.05)
                i += 1
            sys.stdout.write(f"\r  {paint('[✔]', C_OK, bold=True)} {step}    \n")
            sys.stdout.flush()
        else:
            print(f"  [OK] {step}")


# --------------------------------------------------------------------------- #
# Spinner (context manager)
# --------------------------------------------------------------------------- #
class Spinner:
    """A lightweight braille spinner usable as a context manager.

    Falls back to a single printed line when animation is disabled.
    """

    FRAMES = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"

    def __init__(self, text: str = "Working...", rgb: RGB = C_ACCENT):
        self.text = text
        self.rgb = rgb
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None

    def _spin(self) -> None:
        i = 0
        while not self._stop.is_set():
            frame = paint(self.FRAMES[i % len(self.FRAMES)], self.rgb, bold=True)
            sys.stdout.write(f"\r{frame} {self.text} ")
            sys.stdout.flush()
            time.sleep(0.08)
            i += 1

    def start(self) -> Spinner:
        if anim_enabled():
            sys.stdout.write(HIDE_CURSOR)
            self._thread = threading.Thread(target=self._spin, daemon=True)
            self._thread.start()
        else:
            print(f"  {self.text}")
        return self

    def stop(self, done_msg: Optional[str] = None, kind: str = "ok") -> None:
        # Idempotent: safe to call more than once (the stream path may stop the
        # spinner early to show reasoning, then the caller stops it again).
        if self._thread is not None and not self._stop.is_set():
            self._stop.set()
            self._thread.join()
            sys.stdout.write("\r" + " " * (len(self.text) + 6) + "\r")
            sys.stdout.write(SHOW_CURSOR)
            sys.stdout.flush()
        if done_msg:
            status(kind, done_msg)

    def __enter__(self) -> Spinner:
        return self.start()

    def __exit__(self, exc_type, exc, tb) -> None:
        self.stop()


# --------------------------------------------------------------------------- #
# Progress bar
# --------------------------------------------------------------------------- #
def progress(current: int, total: int, label: str = "", width: int = 28) -> None:
    """Render/update a single-line progress bar (overwrites in place)."""
    total = max(total, 1)
    frac = max(0.0, min(1.0, current / total))
    filled = int(frac * width)
    if color_enabled():
        bar = gradient("█" * filled, C_START, C_END, bold=False) + paint(
            "░" * (width - filled), C_MUTE
        )
    else:
        bar = "#" * filled + "-" * (width - filled)
    pct = f"{int(frac * 100):3d}%"
    line = f"\r  {bar} {paint(pct, C_ACCENT, bold=True)} {paint(label, C_MUTE)}"
    sys.stdout.write(line)
    sys.stdout.flush()
    if current >= total:
        sys.stdout.write("\n")
        sys.stdout.flush()
