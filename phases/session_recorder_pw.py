import subprocess
import signal
import os
import time
from resources.bcolors import bcolors


def record_user_session(url, har_path, actions_path):
    os.makedirs(os.path.dirname(har_path), exist_ok=True)
    os.makedirs(os.path.dirname(actions_path), exist_ok=True)

    cmd = [
        "playwright",
        "codegen",
        "--target",
        "python",
        "-o",
        actions_path,
        "--save-har",
        har_path,
        url,
    ]
    print(f"{bcolors.OKBLUE}[INFO]: Starting Playwright codegen...{bcolors.ENDC}")
    print(f"{bcolors.OKBLUE}[INFO]: Command: {' '.join(cmd)}{bcolors.ENDC}")
    time.sleep(1)

    if os.name == "nt":
        proc = subprocess.Popen(cmd, creationflags=subprocess.CREATE_NEW_PROCESS_GROUP)
    else:
        proc = subprocess.Popen(cmd, preexec_fn=os.setsid)

    err = proc.stderr.read().decode("utf-8") if proc.stderr else None
    if err:
        print(f"{bcolors.FAIL}[ERROR]: Playwright error: {err}{bcolors.ENDC}")
        return None, None

    try:
        input(
            f"{bcolors.BOLD}{bcolors.WARNING}Press <Enter> to stop recording...{bcolors.ENDC}"
        )
        if os.name == "nt":
            proc.send_signal(signal.CTRL_BREAK_EVENT)
        else:
            os.killpg(os.getpgid(proc.pid), signal.SIGINT)
        proc.wait()
    except KeyboardInterrupt:
        if proc.poll() is None:
            proc.terminate()
        proc.wait()
    except Exception as e:
        print(f"{bcolors.FAIL}[ERROR]: {e}{bcolors.ENDC}")
        return None, None

    print(f"{bcolors.OKGREEN}[SUCCESS]: HAR saved to:     {har_path}{bcolors.ENDC}")
    print(f"{bcolors.OKGREEN}[SUCCESS]: Actions saved to: {actions_path}{bcolors.ENDC}")

    return har_path, actions_path
