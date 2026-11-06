from resources import ui


def yes_no_menu(question):
    while True:
        choice = input(question).strip().lower()
        if choice not in ["y", "yes", "n", "no"]:
            ui.warn("Please enter 'y' or 'n'.")
        else:
            return choice in ["y", "yes"]
