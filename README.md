# Rakiber RAR Cracker — Installation & Run Quick Guide (README)

This README provides all commands needed to install and run the project in one go. It's written for Debian/Ubuntu/Kali-based systems (sudo privileges required).

---

## All-in-one command (paste into terminal)

Copy and paste the following commands into your terminal. It will update the system, install required packages, clone the GitHub repo, create a virtual environment, and install Python dependencies:

```bash
sudo apt update && sudo apt install -y git python3-venv python3-pip python3-tk unrar p7zip-full build-essential python3-dev && \
cd ~/Downloads && \
rm -rf rakiber-rar-cracker && \
git clone https://github.com/bigbang412247-hub/rakiber-rar-cracker.git && \
cd rakiber-rar-cracker && \
python3 -m venv .venv && \
source .venv/bin/activate && \
pip install --upgrade pip && \
if [ -f requirements.txt ]; then pip install -r requirements.txt; else echo "requirements.txt not found — install required packages manually (e.g. pip install rarfile)"; fi && \
if [ -f cracker.py ]; then chmod +x cracker.py; fi && \
echo "Setup complete. To run: source .venv/bin/activate && python3 cracker.py (or the project's main script)"
```

> Note: If the main script is not `cracker.py`, replace it with the correct filename (for example `main.py` or `run.sh`).

---

## Alternative: create and run an installation script

If you prefer, save the following content into a file named `setup_rar_cracker.sh`, make it executable, and run it.

```bash
#!/usr/bin/env bash
set -euo pipefail

# 1. System update and required packages
sudo apt update
sudo apt install -y git python3-venv python3-pip python3-tk unrar p7zip-full build-essential python3-dev

# 2. Working directory
cd ~/Downloads

# 3. Remove old folder (optional)
rm -rf rakiber-rar-cracker

# 4. Clone repository
git clone https://github.com/bigbang412247-hub/rakiber-rar-cracker.git

# 5. Create and activate virtual environment
cd rakiber-rar-cracker
python3 -m venv .venv
source .venv/bin/activate

# 6. Upgrade pip and install requirements
pip install --upgrade pip
if [ -f requirements.txt ]; then
  pip install -r requirements.txt
else
  echo "requirements.txt not found — install required Python packages manually (for example: pip install rarfile)"
fi

# 7. Make main script executable if present
if [ -f cracker.py ]; then
  chmod +x cracker.py
fi

echo "========================================"
echo "Setup finished. How to run:" 
echo "1) source .venv/bin/activate"
echo "2) python3 cracker.py    # or the project's main script"
echo "========================================"
```

Create and run:

```bash
nano setup_rar_cracker.sh   # or use your preferred editor
# paste the script content, save
chmod +x setup_rar_cracker.sh
./setup_rar_cracker.sh
```

---

## Quick troubleshooting

* **Git clone error**: Check internet connection or repo URL. For private repos, provide credentials.
* **python3: No module named venv**: Install with `sudo apt install -y python3-venv`.
* **Tkinter GUI not shown**: Install `sudo apt install -y python3-tk`.
* **pip install fails**: Ensure virtualenv is activated: `source .venv/bin/activate`.
* **unrar missing**: Install `sudo apt install -y unrar`.

---

## How can I tell which file to run?

After cloning, paste the output of `ls -la` or `tree -L 2` here and I will identify the main script and show the exact command to run it.

---

If you want, I can also create a small `run.sh` file that launches the project (GUI or CLI) — let me know which you prefer.

Thank you — tell me if you want any additional changes.
