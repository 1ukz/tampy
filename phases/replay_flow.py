import importlib
from pathlib import Path
import re
from resources.bcolors import bcolors

PAUSE_SNIPPET = [
    "    # ---------------------\n",
    "    print()\n",
    "    input()\n",
]

MAIN_SNIPPET = [
    "\n",
    "def main() -> None:\n",
    '    """Public entry point wrapping the generated _run()"""\n',
    "    from playwright.sync_api import sync_playwright\n",
    "    with sync_playwright() as playwright:\n",
    "        _run(playwright)\n",
]


def post_process(path: Path):
    lines = path.read_text(encoding="utf-8").splitlines(keepends=True)
    out_lines = []
    in_sync_block = False

    for line in lines:
        # 1a) remove any HAR-routing line
        if "context.route_from_har" in line:
            continue
        # 1b) remove stray calls to run(playwright) inside _run
        if line.strip() == "run(playwright)":
            continue

        # 2) detect and rename the run() definition
        if re.match(r"\s*def\s+run\s*\(\s*playwright", line):
            # replace "def run(...)" with "def _run(...)"
            line = line.replace("def run", "def _run", 1)

        # 3) drop the bottom `with sync_playwright() as playwright:` block entirely
        #    (we'll re-add a nicer main() at the bottom)
        if line.lstrip().startswith("with sync_playwright") or in_sync_block:
            # enter skip mode when we see the with,
            # and leave only when we hit an unindented line (no leading space)
            if not in_sync_block:
                in_sync_block = True
            # if the next line is unindented, close skip mode
            if in_sync_block and not line.startswith("    "):
                in_sync_block = False
            continue

        # 4) inject our pause snippet just before the context/browser close
        if line.lstrip().startswith("context.close()"):
            out_lines.extend(PAUSE_SNIPPET)

        out_lines.append(line)

    # 5) append the new public main() entrypoint
    out_lines.extend(MAIN_SNIPPET)

    # write back
    path.write_text("".join(out_lines), encoding="utf-8")


def load_actions_module(actions_file):
    """
    Dynamically load a Python module from a file path.
    Returns the loaded module object.
    """
    path = Path(actions_file)

    if not path.exists():
        print(
            f"{bcolors.BOLD}{bcolors.FAIL}[ERROR]: File not found: {actions_file}{bcolors.ENDC}"
        )
        return None
    module_name = path.stem  # grab the file name without extension
    spec = importlib.util.spec_from_file_location(module_name, str(path))
    if spec is None or spec.loader is None:
        print(
            f"{bcolors.BOLD}{bcolors.FAIL}[ERROR]: Cannot load recorder actions module from path: {actions_file}{bcolors.ENDC}"
        )

    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def replay_flow(actions_file):
    actions_file_path = Path(actions_file)

    post_process(actions_file_path)

    # load the actions module
    module = load_actions_module(actions_file_path)

    if not hasattr(module, "main"):
        print(
            f"{bcolors.BOLD}{bcolors.FAIL} Module '{actions_file}' has no main() function to run.{bcolors.ENDC}"
        )

    actions_main_func = getattr(module, "main")
    actions_main_func()
    print(
        f"{bcolors.BOLD}{bcolors.OKGREEN} Playback finished! Evaluate the resutls.{bcolors.ENDC}"
    )
    print(
        f"{bcolors.BOLD}{bcolors.OKGREEN} Press <ENTER> to close browser.{bcolors.ENDC}"
    )
