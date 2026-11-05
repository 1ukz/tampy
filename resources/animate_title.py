"""Animated startup: gradient banner + boot checklist."""

import os

from resources import ui


def animate_title(version: str = "2.0", author: str = "@1ukz"):
    # Clear the screen for a clean canvas (only when interactive).
    if ui.anim_enabled():
        os.system("cls" if os.name == "nt" else "clear")

    ui.banner(version=version, author=author)
    ui.boot(
        [
            "Loading environment",
            "Arming business-logic controls",
            "Initializing verification oracle",
            "Preparing secret redaction",
        ]
    )
    print()
