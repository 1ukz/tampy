import os
import time

from resources.bcolors import bcolors


def animate_title():
    ascii_art = [
        f"{bcolors.BOLD} /$$$$$$$$ /$$$$$$  /$$      /$$ /$$$$$$$  /$$     /$$",
        "|__  $$__//$$__  $$| $$$    /$$$| $$__  $$|  $$   /$$/",
        "   | $$  | $$  \\ $$| $$$$  /$$$$| $$  \\ $$ \\  $$ /$$/ ",
        "   | $$  | $$$$$$$$| $$ $$/$$ $$| $$$$$$$/  \\  $$$$/  ",
        "   | $$  | $$__  $$| $$  $$$| $$| $$____/    \\  $$/   ",
        "   | $$  | $$  | $$| $$\\  $ | $$| $$          | $$    ",
        "   | $$  | $$  | $$| $$ \\/  | $$| $$          | $$    ",
        "   |__/  |__/  |__/|__/     |__/|__/          |__/     ",
        f"                                                       {bcolors.ENDC}",
    ]
    max_shift = 8
    for shift in range(max_shift):
        os.system("cls" if os.name == "nt" else "clear")
        for line in ascii_art:
            print(" " * shift + line)
        time.sleep(0.035)
    for shift in range(max_shift, -1, -1):
        os.system("cls" if os.name == "nt" else "clear")
        for line in ascii_art:
            print(" " * shift + line)
        time.sleep(0.035)
    os.system("cls" if os.name == "nt" else "clear")
    for line in ascii_art:
        print(line)
    print(f"{bcolors.BOLD}created by @1ukz{bcolors.ENDC}")
    print("------------------------------------------------------------\n\n")
    time.sleep(0.5)
