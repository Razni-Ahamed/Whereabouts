"""Scripted, polite browsing for lab sessions (Playwright).

Visits a seeded sample of public sites for a number of minutes: at most
five page loads per site per session, 5-20 seconds apart, never crawling.
Only runs inside the lab's disposable runners.
"""

from __future__ import annotations

import argparse
import json
import random
import time
from pathlib import Path
from urllib.parse import urlparse

MAX_LOADS_PER_SITE = 5


def plan_visits(sites: list[str], minutes: float, seed: int) -> list[tuple[str, float]]:
    """A seeded list of (url, pause seconds) that fits in `minutes`."""
    rng = random.Random(seed)
    budget = minutes * 60.0
    loads: dict[str, int] = {}
    visits: list[tuple[str, float]] = []
    spent = 0.0
    while spent < budget:
        open_sites = [s for s in sites if loads.get(s, 0) < MAX_LOADS_PER_SITE]
        if not open_sites:
            break
        site = rng.choice(open_sites)
        pause = rng.uniform(5.0, 20.0)
        loads[site] = loads.get(site, 0) + 1
        visits.append((site, pause))
        spent += pause + 5.0  # a page load takes a few seconds too
    return visits


def browse(browser_name: str, sites: list[str], minutes: float, seed: int) -> int:
    """Runs the visits; returns how many pages loaded."""
    from playwright.sync_api import sync_playwright

    deadline = time.monotonic() + minutes * 60.0
    loaded = 0
    with sync_playwright() as p:

        def launch(headless: bool):
            if browser_name == "firefox":
                return p.firefox.launch(headless=headless)
            return p.chromium.launch(channel=browser_name, headless=headless)  # installed Edge or Chrome

        try:
            browser = launch(headless=False)
        except Exception as error:  # a runner without a desktop: the same traffic, headless
            print(f"headed launch failed ({type(error).__name__}); browsing headless")
            browser = launch(headless=True)
        page = browser.new_page()
        for url, pause in plan_visits(sites, minutes, seed):
            if time.monotonic() > deadline:
                break
            try:
                page.goto(url, wait_until="load", timeout=30_000)
                loaded += 1
                # Sometimes follow one link on the same site, as a person would.
                links = page.eval_on_selector_all("a[href]", "els => els.map(e => e.href)")
                host = urlparse(url).hostname
                same = [link for link in links if urlparse(link).hostname == host]
                if same and random.Random(f"{seed}-{loaded}").random() < 0.5:
                    page.goto(random.Random(f"{seed}-{url}").choice(same), wait_until="load", timeout=30_000)
                    loaded += 1
            except Exception as error:  # a slow or blocking site must not end the session
                print(f"skipped {url}: {type(error).__name__}")
            time.sleep(min(pause, max(0.0, deadline - time.monotonic())))
        browser.close()
    return loaded


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--browser", choices=["msedge", "chrome", "firefox"], required=True)
    parser.add_argument("--sites", type=Path, required=True)
    parser.add_argument("--list", default="general")
    parser.add_argument("--minutes", type=float, required=True)
    parser.add_argument("--seed", type=int, required=True)
    args = parser.parse_args()
    sites = json.loads(args.sites.read_text(encoding="utf-8"))[args.list]
    print(f"loaded {browse(args.browser, sites, args.minutes, args.seed)} pages")


if __name__ == "__main__":
    main()
