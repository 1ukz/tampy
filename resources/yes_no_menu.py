from resources.bcolors import bcolors


def yes_no_menu(question):
    while True:
        choice = input(question).strip().lower()
        if choice not in ["y", "yes", "n", "no"]:
            print(f"{bcolors.BOLD}{bcolors.FAIL}Please enter 'y' or 'n'{bcolors.ENDC}")
        else:
            return choice in ["y", "yes"]
