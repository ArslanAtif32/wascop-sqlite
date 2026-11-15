"""Start WAScope interception and a dedicated Chrome browser in one command.

Place this file in the WAScope project root, beside Interception.py.
Run: python start_wascope_browser.py

MITMproxy uses its regular-proxy default (localhost:8080); no listen flags
are needed. Chrome is launched with that proxy configured automatically.
"""

from __future__ import annotations

import importlib.util
import os
import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent
INTERCEPTION_SCRIPT = PROJECT_ROOT / "Interception.py"
PROXY_HOST = "127.0.0.1"
PROXY_PORT = 8080  # MITMproxy's default regular-proxy port
CHROME_PROFILE = PROJECT_ROOT / "wascope_chrome_profile"


def find_mitmdump_command() -> list[str] | None:
    """Find mitmdump, or invoke its Python entry point in this interpreter."""
    found = shutil.which("mitmdump")
    if found:
        return [found]

    candidates = [
        Path(sys.prefix) / "Scripts" / "mitmdump.exe",
        PROJECT_ROOT / ".venv" / "Scripts" / "mitmdump.exe",
        PROJECT_ROOT / "venv" / "Scripts" / "mitmdump.exe",
        PROJECT_ROOT / "venv311" / "Scripts" / "mitmdump.exe",
        PROJECT_ROOT / "wascope-venv" / "Scripts" / "mitmdump.exe",
    ]
    for candidate in candidates:
        if candidate.is_file():
            return [str(candidate)]

    # Some installations have the mitmproxy package but not the mitmdump.exe
    # console launcher. In that case, call the same entry point with Python.
    if importlib.util.find_spec("mitmproxy") is not None:
        return [
            sys.executable,
            "-c",
            "from mitmproxy.tools.main import mitmdump; mitmdump()",
        ]
    return None


def find_chrome() -> str | None:
    """Find a standard Google Chrome installation on Windows."""
    env_paths = []
    for variable in ("PROGRAMFILES", "PROGRAMFILES(X86)", "LOCALAPPDATA"):
        base = os.environ.get(variable)
        if base:
            env_paths.append(Path(base) / "Google" / "Chrome" / "Application" / "chrome.exe")

    for candidate in env_paths:
        if candidate.is_file():
            return str(candidate)

    found = shutil.which("chrome")
    return found


def port_is_open(host: str, port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(0.4)
        return sock.connect_ex((host, port)) == 0


def stop_process(process: subprocess.Popen | None, name: str) -> None:
    if process is None or process.poll() is not None:
        return
    print(f"Stopping {name}...")
    process.terminate()
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)


def main() -> int:
    if not INTERCEPTION_SCRIPT.is_file():
        print("ERROR: Interception.py was not found.")
        print("Place start_wascope_browser.py in the WAScope project root, beside Interception.py.")
        return 1

    mitmdump_command = find_mitmdump_command()
    if not mitmdump_command:
        print("ERROR: mitmdump was not found in PATH or the common WAScope virtual environments.")
        print("Activate the WAScope virtual environment, install the requirements, then run this file again.")
        print("For example: python -m pip install mitmproxy==10.2.4")
        return 1

    chrome = find_chrome()
    if not chrome:
        print("ERROR: Google Chrome was not found in the usual Windows installation folders.")
        print("Install Chrome or edit find_chrome() with your chrome.exe path.")
        return 1

    if port_is_open(PROXY_HOST, PROXY_PORT):
        print(f"ERROR: {PROXY_HOST}:{PROXY_PORT} is already in use.")
        print("Close the other MITMproxy instance, then run this launcher again.")
        return 1

    # No --listen-host/--listen-port flags: MITMproxy's default proxy is used.
    proxy_command = [*mitmdump_command, "-s", str(INTERCEPTION_SCRIPT)]
    print("Starting WAScope interception...")
    print("MITMproxy will use its default local proxy address (127.0.0.1:8080).")

    proxy_process = None
    browser_process = None
    try:
        proxy_process = subprocess.Popen(proxy_command, cwd=str(PROJECT_ROOT))

        deadline = time.time() + 20
        while time.time() < deadline:
            if proxy_process.poll() is not None:
                print("ERROR: MITMproxy exited before its proxy became available.")
                return 1
            if port_is_open(PROXY_HOST, PROXY_PORT):
                break
            time.sleep(0.25)
        else:
            print("ERROR: MITMproxy did not start listening on its default port 8080.")
            return 1

        CHROME_PROFILE.mkdir(parents=True, exist_ok=True)
        chrome_args = [
            "--proxy-server=http://127.0.0.1:8080",
            # Ensure localhost/127.0.0.1 traffic is also sent through the proxy.
            "--proxy-bypass-list=<-loopback>",
            f"--user-data-dir={CHROME_PROFILE}",
            "--no-first-run",
            "--no-default-browser-check",
            "http://mitm.it",
        ]

        print("Starting a separate Chrome profile through WAScope...")
        print("First-time setup: install and trust the MITMproxy CA from http://mitm.it.")
        print("Then browse only websites you own or are explicitly authorized to test.")
        print("Close this Chrome window or press Ctrl+C here to stop interception.\n")

        browser_process = subprocess.Popen([chrome, *chrome_args], cwd=str(PROJECT_ROOT))
        browser_process.wait()
        return 0

    except KeyboardInterrupt:
        print("\nInterruption requested.")
        return 0
    except OSError as exc:
        print(f"ERROR: Could not start WAScope or Chrome: {exc}")
        return 1
    finally:
        stop_process(browser_process, "Chrome")
        stop_process(proxy_process, "MITMproxy")


if __name__ == "__main__":
    raise SystemExit(main())
