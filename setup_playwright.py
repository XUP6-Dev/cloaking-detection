"""Install and verify Chromium for this project's Playwright package only."""
import os
import subprocess
import sys


def main():
    # "0" is Playwright's documented package-local browser storage mode.
    # Respect a caller's custom location so installation and runtime agree.
    os.environ.setdefault("PLAYWRIGHT_BROWSERS_PATH", "0")
    subprocess.run([sys.executable, "-m", "playwright", "install", "chromium"], check=True)

    from playwright.sync_api import sync_playwright
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(
            headless=True, chromium_sandbox=True, args=["--no-proxy-server"], timeout=30000)
        try:
            print(f"Playwright Chromium ready: {browser.version}")
        finally:
            browser.close()


if __name__ == "__main__":
    main()
