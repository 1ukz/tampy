import subprocess
import signal
import os
import time
from resources.bcolors import bcolors

# Global flag to control the recording loop
stop_recording = False


def record_user_session(url, har_path, actions_path):
    global stop_recording
    stop_recording = False  # Reset flag for each recording session

    # Save the original signal handler for SIGINT
    original_handler = signal.getsignal(signal.SIGINT)

    # Create parent directories for both paths
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
    print(f"{bcolors.OKBLUE}[INFO]: Command: {' '.join(cmd)}\n{bcolors.ENDC}")
    print(
        f"{bcolors.BOLD}{bcolors.WARNING} Please simulate an ordinary user completing the purchase flow for one product. {bcolors.ENDC}"
    )
    print(
        f"{bcolors.WARNING}[WARNING]: Only interact with the website interface, DO NOT use browser functions (e.g. back button){bcolors.ENDC}"
    )
    time.sleep(1)

    # Run subprocess attached to the console
    proc = subprocess.Popen(cmd, stdout=None, stderr=None)

    # Signal handler for Ctrl+C
    def handler(signum, frame):
        global stop_recording
        stop_recording = True

    # Set the custom signal handler for SIGINT (Ctrl+C)
    signal.signal(signal.SIGINT, handler)

    print(
        f"{bcolors.BOLD}{bcolors.WARNING}Press Ctrl+C to stop recording...{bcolors.ENDC}"
    )
    # Keep the script running until Ctrl+C is pressed
    while not stop_recording:
        time.sleep(1)

    # Restore the original signal handler
    signal.signal(signal.SIGINT, original_handler)

    # Wait for the subprocess to finish
    proc.wait()

    # Check if the files were created
    if not os.path.exists(har_path) or not os.path.exists(actions_path):
        print(
            f"{bcolors.FAIL}[ERROR]: Files not created: {har_path} or {actions_path}{bcolors.ENDC}"
        )
        return None, None

    print(f"{bcolors.OKGREEN}[SUCCESS]: HAR saved to: {har_path}{bcolors.ENDC}")
    print(f"{bcolors.OKGREEN}[SUCCESS]: Actions saved to: {actions_path}{bcolors.ENDC}")

    return har_path, actions_path
