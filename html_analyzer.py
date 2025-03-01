import requests
from bs4 import BeautifulSoup
from bcolors import bcolors  # Assuming you have this module for colored output

def search_html_for_keywords(url, keywords):
    
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
    except Exception as e:
        print(f"{bcolors.FAIL}Error downloading the webpage from URL! {e}{bcolors.ENDC}")
        return False

    # Parse and prettify the HTML, then convert to lowercase for easier searching
    soup = BeautifulSoup(response.text, 'html.parser')
    html_text = soup.prettify().lower()
    
    # Split the HTML into individual lines
    lines = html_text.splitlines()
    
    # Search for lines that contain any keyword
    found_lines = []
    for line in lines:
        for keyword in keywords:
            if keyword.lower() in line:
                found_lines.append(line.strip())
                break  # Avoid duplicate entries if multiple keywords are in the same line
    
    # Determine the output file name using the first keyword in the list
    if keywords:
        file_name = f"{keywords[0]}_analysis.txt"
    else:
        file_name = "analysis.txt"
    
    # Write the found lines to the file, each preceded by its line number
    with open(file_name, "w", encoding="utf-8") as f:
        if found_lines:
            f.write(f"{len(found_lines)} line(s) have been found:\n\n")
            for i, line in enumerate(found_lines, start=1):
                f.write(f"[{i}] {line}\n")
        else:
            f.write("No lines matching the expected keywords were found.\n")
    
    # Create a string from the keywords for display purposes
    keywords_str = ", ".join(keywords)
    
    # Inform the user and ask if they want to display the file content
    if found_lines:
        print(f"{bcolors.OKGREEN}{len(found_lines)} line(s) have been found using keywords: {keywords_str} in the HTML from URL: {url}{bcolors.ENDC}")
    else:
        print(f"{bcolors.WARNING}No matching lines were found using keywords: {keywords_str} in the HTML from URL: {url}{bcolors.ENDC}")
    
    choice = input(f"{bcolors.BOLD}Do you want to display the analysis content on screen? (y/n): {bcolors.ENDC}").strip().lower()
    if choice in ['y', 'yes']:
        try:
            with open(file_name, "r", encoding="utf-8") as f:
                print("\n" + f.read())
        except Exception as e:
            print(f"{bcolors.FAIL}Error reading the file: {e}{bcolors.ENDC}")
    
    return bool(found_lines)
