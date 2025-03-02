import os
from selenium import webdriver
from selenium.webdriver.firefox.options import Options
from selenium.webdriver.firefox.service import Service as FirefoxService
from webdriver_manager.firefox import GeckoDriverManager
from bcolors import bcolors

def record_user_session(url):
    """
    Opens Firefox (via geckodriver), installs the Katalon Automation Record extension
    dynamically, and then navigates to the given URL so the user can interact.
    
    This avoids requiring a custom local profile, making it portable for anyone
    who clones the repository.
    """
    # Path to the Katalon Automation Record extension XPI file
    extension_path = os.path.join(".", "extensions", "katalon_automation_record-5.5.3.xpi")
    
    # Check if the extension file exists
    if not os.path.exists(extension_path):
        print(f"{bcolors.FAIL}Katalon extension not found at {extension_path}.{bcolors.ENDC}")
        print(f"{bcolors.FAIL}Please place the XPI file in the 'extensions' folder or update the path.{bcolors.ENDC}")
        return

    options = Options()
    options.headless = False  # We want to see the browser UI
    
    print(f"{bcolors.OKBLUE}Launching Firefox...{bcolors.ENDC}")
    driver = webdriver.Firefox(
        service=FirefoxService(GeckoDriverManager().install()),
        options=options
    )

    try:
        # Install the Katalon extension at runtime
        driver.install_addon(extension_path, temporary=True)
        print(f"{bcolors.OKBLUE}Katalon extension installed {bcolors.ENDC}")
    except Exception as e:
        print(f"{bcolors.FAIL}Failed to install Katalon extension dynamically: {e}{bcolors.ENDC}")
        driver.quit()
        return

    # Now navigate to the URL
    driver.get(url)
    print(f"{bcolors.OKBLUE}Katalon Automation Record should be available.\n"
          f"Interact with the website normally. When finished, close the browser window or press Enter here to end session recording.{bcolors.ENDC}")

    input("Press Enter after you have finished interacting with the website...")

    driver.quit()
    print(f"{bcolors.OKBLUE}User session recording finished. You can now export the recorded actions from the Katalon extension.{bcolors.ENDC}")
