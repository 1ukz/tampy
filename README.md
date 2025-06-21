# TAMPY v1.0
<br>
<img src="https://github.com/user-attachments/assets/71003213-54e5-46ac-8301-029e359bb376" alt="TAMPY screenshot" width="450"/>
<br><br>

**TAMPY** is a command-line tool designed to perform security assessments of e-commerce websites. It automates technology enumeration, HTTP packet recording, AI-driven analysis, and replay testing of tampered requests in order to test the business logic, architecture and purchase-flow security.

---

## 📝 Features

- **Phase 1: Technology Enumeration**  
  Scans a target URL for web technologies and flags common e-commerce platforms.

- **Phase 2: User Session Recording**  
  Records HTTP(S) traffic during manual browsing with Playwright codegen (actions + HAR) or Selenium-Wire.

- **Phase 3: AI-Powered Packet Analysis**  
  Sends filtered HTTP packets to an LLM (local or remote) for vulnerability control suggestions.

- **Phase 4: Control Testing & Replay**  
  Lets you modify a specific packet and replay the full flow in a headed browser to validate tampering.

- **Modular Phases**  
  Each phase is encapsulated in `phases/` for easy extension or customization.

- **Colorful CLI**  
  Animated title, spinners, and colored output via `halo` and custom `bcolors` for a smooth UX.

---

## 🚀 Quick Start

### Prerequisites

- Python **3.9+**
- Firefox Browser (if using Selenium-Wire replay)
- `playwright` CLI and browsers:  
  ```bash
  pip install playwright playwright-stealth
  playwright install
  ```

### Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/<YOUR_USERNAME>/tampy.git
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
  python tampy.py --local
  ```
- **Remote LLM**
  ```bash
  python tampy.py --remote
  ```

#### Optional Flags

- `-S` / `--stream` — Enable streaming LLM responses.
- `-T` / `--think` — Display chain-of-thought reasoning in the console.

---

## 📂 Project Structure

```
├── phases/
│   ├── webtech_rec.py       # Phase 1: Technology enumeration
│   ├── session_recorder.py  # Phase 2: Record user session
│   ├── har_parser.py        # Phase 2: HAR filtering
│   ├── ai_analyzer.py       # Phase 3: AI-driven analysis
│   ├── control_testing.py   # Phase 4: Replay & tamper testing
│   └── replay_flow.py       # Phase 4: Playwright replay module
├── resources/
│   ├── bcolors.py           # ANSI color codes
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
