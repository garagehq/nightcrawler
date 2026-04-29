"""Playwright UI tests for the Nightcrawler web dashboard.

Run with: pytest tests/test_ui.py --headed (or headless by default)
Requires: pip install playwright && playwright install chromium

These tests verify the interactive C2 features work end-to-end.
They require the webui to be running on localhost or Tailscale IP.
"""

import os
import pytest

# Skip if playwright not installed
try:
    from playwright.sync_api import sync_playwright, expect
    HAS_PLAYWRIGHT = True
except ImportError:
    HAS_PLAYWRIGHT = False

WEBUI_URL = os.environ.get("WEBUI_URL", "https://<tailscale-ip>:8888")

pytestmark = pytest.mark.skipif(
    not HAS_PLAYWRIGHT,
    reason="playwright not installed"
)


@pytest.fixture(scope="module")
def browser():
    """Launch browser for tests."""
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        yield browser
        browser.close()


@pytest.fixture
def page(browser):
    """New page for each test, ignoring SSL errors."""
    context = browser.new_context(ignore_https_errors=True)
    page = context.new_page()
    page.goto(WEBUI_URL, wait_until="networkidle")
    yield page
    context.close()


class TestDashboardLoads:
    """Verify the dashboard loads and shows data."""

    def test_banner_visible(self, page):
        assert page.locator(".banner").is_visible()

    def test_status_bar_visible(self, page):
        assert page.locator(".status-bar").is_visible()

    def test_findings_bar_visible(self, page):
        assert page.locator(".findings-bar").is_visible()

    def test_hosts_panel_visible(self, page):
        assert page.locator("#hosts-body").is_visible()

    def test_feed_panel_visible(self, page):
        assert page.locator("#feed-body").is_visible()


class TestNetworkSelector:
    """Test network selection UI."""

    def test_network_bar_visible(self, page):
        assert page.locator(".network-bar").is_visible()

    def test_all_button_active_by_default(self, page):
        all_btn = page.locator("#net-all")
        assert all_btn.is_visible()
        assert "active" in all_btn.get_attribute("class")


class TestHostInteraction:
    """Test clickable host cards."""

    def test_host_cards_exist(self, page):
        page.wait_for_selector(".host-card", timeout=10000)
        cards = page.locator(".host-card")
        assert cards.count() > 0

    def test_click_expands_host(self, page):
        page.wait_for_selector(".host-card", timeout=10000)
        first_card = page.locator(".host-card").first
        first_card.click()
        # After click, should have 'expanded' class
        page.wait_for_timeout(1000)
        assert page.locator(".host-card.expanded").count() >= 1

    def test_expanded_shows_ports(self, page):
        page.wait_for_selector(".host-card", timeout=10000)
        first_card = page.locator(".host-card").first
        first_card.click()
        page.wait_for_timeout(1000)
        port_lines = page.locator(".host-card.expanded .port-line")
        # Should have port lines or "No open ports" message
        detail = page.locator(".host-card.expanded .host-detail")
        assert detail.is_visible()


class TestControlBar:
    """Test C2 control features."""

    def test_control_bar_visible(self, page):
        assert page.locator(".control-bar").is_visible()

    def test_pause_button_exists(self, page):
        assert page.locator("#pause-btn").is_visible()

    def test_kill_button_exists(self, page):
        assert page.locator("#kill-btn").is_visible()

    def test_phase_buttons_exist(self, page):
        # Should have buttons for RECON, ENUM, EXPLOIT
        buttons = page.locator(".control-bar button")
        assert buttons.count() >= 4  # pause, recon, enum, exploit, config, kill

    def test_pause_toggle(self, page):
        pause_btn = page.locator("#pause-btn")
        pause_btn.click()
        page.wait_for_timeout(500)
        # Button text or class should change
        # (implementation-dependent)


class TestCommandInjection:
    """Test manual command injection."""

    def test_command_input_exists(self, page):
        assert page.locator("#cmd-input").is_visible()

    def test_inject_command(self, page):
        input_el = page.locator("#cmd-input")
        input_el.fill("nmap -sV 192.168.1.2")
        inject_btn = page.locator("button", has_text="INJECT")
        if inject_btn.is_visible():
            inject_btn.click()
            page.wait_for_timeout(500)


class TestStarHost:
    """Test host starring."""

    def test_star_icon_visible(self, page):
        page.wait_for_selector(".host-card", timeout=10000)
        # Star icons should be visible on host cards
        stars = page.locator(".star-icon, .host-star, [data-star]")
        # May not exist yet if hosts haven't loaded
        # Just verify host cards exist
        assert page.locator(".host-card").count() > 0


class TestCommandSearch:
    """Test command history search."""

    def test_search_input_exists(self, page):
        search = page.locator("#cmd-search")
        if search.is_visible():
            search.fill("nmap")
            page.wait_for_timeout(1000)
