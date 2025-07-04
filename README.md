# TAMPY v1.0
<br>
<img src="https://github.com/user-attachments/assets/71003213-54e5-46ac-8301-029e359bb376" alt="TAMPY screenshot" width="450"/>
<br><br>

**TAMPY** is a command-line tool designed to perform security assessments of e-commerce websites. It automates technology enumeration, HTTP packet recording, AI-driven analysis, and replay testing of tampered requests in order to test the business logic, architecture and purchase-flow security.

---

## 📝 Structure

  Each phase is encapsulated in `phases/` for easy extension or customization.
  
- **Phase 1: Technology enumeration**  
  Scans a target URL for web technologies and flags common e-commerce platforms.

- **Phase 2: User session recording**  
  Records HTTP(S) traffic during manual browsing with Playwright codegen (actions + HAR).

- **Phase 3: AI-powered packet analysis**  
  Sends filtered HTTP packets to an LLM (local or remote) for vulnerability control suggestions.

- **Phase 4: Control testing & replay**  
  Lets you modify a specific packet and replay the full flow in a headed browser to validate tampering.

---

## 🚀 Quick start

### Prerequisites

- Python **3.9+**
- `playwright` CLI and browsers:  
  ```bash
  pip install playwright
  playwright install
  playwright install deps
  ```
- LLM API manageable with OpenAI python client (e.g DeepSeek, ChatGPT or xAI API) or Local LLM model running in a server (e.g. LM Studio with deepseek-r1-0528-qwen3-8b)
- You will need to install [Firefox](https://www.mozilla.org/en-US/firefox/windows/) and [geckodriver](https://github.com/mozilla/geckodriver/releases). Below are detailed steps for setting up geckodriver but you may use google/youtube for help.
<details>
<summary>Setting up geckodriver</summary>

  #### Step 1: Download GeckoDriver
1. Visit the official GeckoDriver releases page on GitHub:  
   [https://github.com/mozilla/geckodriver/releases](https://github.com/mozilla/geckodriver/releases)
2. Download the version compatible with your system:
   - For Windows: `geckodriver-vX.XX.X-win64.zip`
   - For macOS: `geckodriver-vX.XX.X-macos.tar.gz`
   - For Linux: `geckodriver-vX.XX.X-linux64.tar.gz`
3. Extract the downloaded file to a folder of your choice.

#### Step 2: Add GeckoDriver to the System Path
To ensure Selenium can locate the GeckoDriver executable:
- **Windows**:
  1. Move the `geckodriver.exe` to a directory (e.g., `C:\WebDrivers\`).
  2. Add this directory to the system's PATH:
     - Open **Environment Variables**.
     - Under **System Variables**, find and select the `Path` variable, then click **Edit**.
     - Click **New** and enter the directory path where `geckodriver.exe` is stored.
     - Click **OK** to save.
- **macOS/Linux**:
  1. Move the `geckodriver` file to `/usr/local/bin/` or another directory in your PATH.
  2. Use the following command in the terminal:
     ```bash
     sudo mv geckodriver /usr/local/bin/
     ```
     Ensure `/usr/local/bin/` is in your PATH.
</details>

## 💻 Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/1ukz/tampy.git
   cd tampy
   ```

2. **Create & activate a virtual environment**
   ```bash
   python -m venv venv
   source venv/bin/activate    # Linux/macOS
   venv\Scripts\activate       # Windows
   ```

3. **Install Python dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Set up environment variables**
   - Copy `.env.example` to `.env` and fill in your LLM API keys or local server URL.

---

## ⚙️ Usage

Run the main script with either local or remote LLM mode:

- **Local LLM**
  ```bash
  python tampy.py -L
  ```
- **Remote LLM**
  ```bash
  python tampy.py -R
  ```

#### Optional flags

- `-S` / `--stream` — Enable streaming LLM responses.
- `-T` / `--think` — Display chain-of-thought reasoning in the console.
- `-U` / `--url` — Skip the initial URL prompt.
- `-D` / `--debug` — Debug mode for extra prints and information.

#### Command example
  
  ```bash
  python tampy.py -R -S -U https://www.example.com
  ```

---

## 📂 Project Structure

```
├── phases/
│   ├── phase1_webtech_rec.py       # Phase 1: Technology enumeration
│   ├── phase2_session_recorder.py  # Phase 2: Record user session
│   ├── phase2_har_parser.py        # Phase 2: HAR filtering
│   ├── phase3_ai_analyzer.py       # Phase 3: AI-driven analysis
│   ├── phase4_control_testing.py   # Phase 4: Replay & tamper testing
│   └── phase4_replay_flow.py       # Phase 4: Playwright replay module
├── resources/
│   ├── bcolors.py           # ANSI color codes
│   ├── animate_title.py     # Initial title animation
│   ├── control_refs.py      # Table with controls evaluated and references
│   └── yes_no_menu.py       # Simple Y/N prompt
├── .logs/                   # Output logs, HAR, and flow scripts
├── .env.example             # Example environment variables
├── requirements.txt         # Python dependencies
├── tampy.py                 # Main CLI entrypoint
└── README.md                # This file
```

---

## 🤝 Contributing

Contributions, issues, and feature requests are welcome! Please:

1. Fork the project.
2. Create a feature branch (`git checkout -b feature-name`).
3. Commit your changes (`git commit -m 'Add some feature'`).
4. Push to the branch (`git push origin feature-name`).
5. Open a Pull Request.
