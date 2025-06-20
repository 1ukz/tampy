import subprocess
import signal
import os
from resources.bcolors import bcolors


def _strip_main_block(flow_path: str):
    """
    Remove everything from the first "if __name__" line to EOF.
    """
    lines = []
    with open(flow_path, "r", encoding="utf-8") as in_f:
        for line in in_f:
            if line.strip().startswith("if __name__"):
                break
            lines.append(line)
    with open(flow_path, "w", encoding="utf-8") as out_f:
        out_f.writelines(lines)


def record_user_session(url: str, har_path: str, actions_path: str):
    os.makedirs(os.path.dirname(har_path), exist_ok=True)
    os.makedirs(os.path.dirname(actions_path), exist_ok=True)

    cmd = [
        "playwright",
        "codegen",
        "--target",
        "python-async",
        "-o",
        actions_path,
        "--save-har",
        har_path,
        url,
    ]
    print(f"{bcolors.OKBLUE}[INFO]: Starting Playwright codegen...{bcolors.ENDC}")
    print(f"{bcolors.OKBLUE}[INFO]: Command: {' '.join(cmd)}{bcolors.ENDC}")

    if os.name == "nt":
        proc = subprocess.Popen(cmd, creationflags=subprocess.CREATE_NEW_PROCESS_GROUP)
    else:
        proc = subprocess.Popen(cmd, preexec_fn=os.setsid)

    try:
        input(
            f"{bcolors.BOLD}{bcolors.WARNING}Press <Enter> to stop recording…{bcolors.ENDC}"
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

    # **Strip out** the trailing "__main__" invocation so imports no longer run it
    _strip_main_block(actions_path)

    return har_path, actions_path
