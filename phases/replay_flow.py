import subprocess
import sys
from resources.bcolors import bcolors


def replay_flow(actions_path, url):
    """Execute modified Playwright script with request interception"""
    try:
        print(
            f"{bcolors.OKBLUE}[INFO]: Starting replay with {actions_path}{bcolors.ENDC}"
        )

        # Execute Playwright script
        result = subprocess.run(
            [sys.executable, actions_path], capture_output=True, text=True
        )

        # Output results
        if result.returncode == 0:
            print(f"{bcolors.OKGREEN}[SUCCESS]: Replay completed{bcolors.ENDC}")
        else:
            print(
                f"{bcolors.FAIL}[ERROR]: Replay failed (code {result.returncode}){bcolors.ENDC}"
            )
            print("=" * 50)
            print("STDOUT:")
            print(result.stdout)
            print("=" * 50)
            print("STDERR:")
            print(result.stderr)
            print("=" * 50)

    except Exception as e:
        print(f"{bcolors.FAIL}[ERROR]: Replay exception: {str(e)}{bcolors.ENDC}")
