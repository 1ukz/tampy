import os
import signal
import subprocess
import time

from resources import ui

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
        "--browser",
        "chromium",
        "--ignore-https-errors",  # Ignore SSL errors
        "--target",
        "python",
        "-o",
        actions_path,
        "--save-har",
        har_path,
        url,
    ]
    ui.info("Launching Playwright codegen — a browser window will open.")
    print(f"      {ui.paint(' '.join(cmd), ui.C_MUTE)}\n")
    ui.status("run", "Complete ONE full purchase flow for a single product, as a normal user.")
    ui.warn("Use only the website's own interface — avoid browser controls (e.g. the back button).")
    time.sleep(1)

    # Run subprocess attached to the console
    proc = subprocess.Popen(cmd, stdout=None, stderr=None)

    # Signal handler for Ctrl+C
    def handler(signum, frame):
        global stop_recording
        stop_recording = True

    # Set the custom signal handler for SIGINT (Ctrl+C)
    signal.signal(signal.SIGINT, handler)

    ui.status("run", "Recording… press Ctrl+C when the purchase flow is complete.")
    # Keep the script running until Ctrl+C is pressed
    while not stop_recording:
        time.sleep(1)

    # Restore the original signal handler
    signal.signal(signal.SIGINT, original_handler)

    # Wait for the subprocess to finish
    proc.wait()

    # Check if the files were created
    if not os.path.exists(har_path) or not os.path.exists(actions_path):
        ui.err(f"Recording files not created: {har_path} or {actions_path}")
        return None, None

    ui.ok(f"HAR saved to: {har_path}")
    ui.ok(f"Actions saved to: {actions_path}")

    return har_path, actions_path
