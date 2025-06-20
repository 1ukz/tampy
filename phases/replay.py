import argparse
import importlib.util
from pathlib import Path
import sys


def load_module_from_path(path: Path, module_name: str = "recorded_flow"):
    """
    Dynamically load a Python module from a file path.
    Returns the loaded module object.
    """
    spec = importlib.util.spec_from_file_location(module_name, str(path))
    if spec is None or spec.loader is None:
        raise ImportError(f"Cannot load module from path: {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def replay(flow_path: Path, times: int = 1):
    """
    Replay the recorded flow script by invoking its main() function.

    :param flow_path: Path to the Playwright-generated Python script.
    :param times: Number of times to replay the flow.
    """
    if not flow_path.exists():
        raise FileNotFoundError(f"Flow script not found: {flow_path}")

    # Load the module
    module = load_module_from_path(flow_path)

    if not hasattr(module, "main"):
        raise AttributeError(f"Module '{flow_path}' has no main() function to run.")
    main_func = getattr(module, "main")

    # Replay in a loop
    for i in range(1, times + 1):
        print(f"► Replaying '{flow_path.name}' (run {i}/{times})")
        main_func()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Replay a recorded Playwright flow script."
    )
    parser.add_argument(
        "flow", type=str, help="Path to the recorded Playwright flow (Python script)."
    )
    parser.add_argument(
        "-n", "--times", type=int, default=1, help="Number of times to replay the flow."
    )
    args = parser.parse_args()

    try:
        flow_file = Path(args.flow)
        replay(flow_file, args.times)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
