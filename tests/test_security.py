"""Security tests to ensure no API key leaks, telemetry, or data exfiltration.

These tests codify the security guarantees of the proxy so regressions
are caught automatically.
"""

import ast
import re
from pathlib import Path


# Project root (all source directories)
ROOT = Path(__file__).resolve().parent.parent
SRC_DIRS = [
    ROOT / d for d in ("api", "cli", "config", "messaging", "providers", "utils")
]

# Collect all Python source files (excluding tests and .venv)
_SRC_FILES: list[Path] = []
for d in SRC_DIRS:
    if d.is_dir():
        _SRC_FILES.extend(d.rglob("*.py"))


def _read_sources() -> list[tuple[Path, str]]:
    """Read all source files and return (path, content) pairs."""
    results = []
    for p in _SRC_FILES:
        try:
            results.append((p, p.read_text(encoding="utf-8")))
        except Exception:
            pass
    return results


class TestNoHardcodedSecrets:
    """Ensure no real API keys or secrets are committed in source code."""

    # Patterns that look like real API keys (not test/placeholder values)
    _SECRET_PATTERNS = [
        # NVIDIA NIM keys (nvapi-...)
        re.compile(r"nvapi-[A-Za-z0-9_-]{20,}"),
        # OpenRouter keys (sk-or-...)
        re.compile(r"sk-or-[A-Za-z0-9_-]{20,}"),
        # Generic OpenAI-style keys (sk-... but not sk-placeholder)
        re.compile(r"sk-(?!placeholder)[A-Za-z0-9_-]{20,}"),
        # Discord bot tokens (long base64-ish strings)
        re.compile(r"[MN][A-Za-z0-9_-]{23,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{27,}"),
        # Telegram bot tokens (digits:alphanum)
        re.compile(r"\d{8,}:[A-Za-z0-9_-]{30,}"),
    ]

    def test_no_hardcoded_api_keys_in_source(self):
        for path, content in _read_sources():
            for pattern in self._SECRET_PATTERNS:
                matches = pattern.findall(content)
                assert not matches, (
                    f"Potential hardcoded secret in {path.relative_to(ROOT)}: "
                    f"{[m[:10] + '...' for m in matches]}"
                )


class TestNoTelemetry:
    """Ensure no telemetry, analytics, or phone-home code exists."""

    # Known legitimate external hosts the proxy connects to
    _ALLOWED_HOSTS = {
        "integrate.api.nvidia.com",
        "openrouter.ai",
        "localhost",
    }

    def test_no_unknown_external_urls(self):
        """Only known provider URLs should appear in source code."""
        url_pattern = re.compile(r"https?://([a-zA-Z0-9._-]+)")
        for path, content in _read_sources():
            for match in url_pattern.finditer(content):
                host = match.group(1)
                # Strip port if present
                host = host.split(":")[0]
                assert host in self._ALLOWED_HOSTS, (
                    f"Unknown external URL in {path.relative_to(ROOT)}: "
                    f"{match.group(0)} (host: {host}). "
                    f"If this is a legitimate provider, add it to _ALLOWED_HOSTS."
                )

    def test_no_telemetry_imports(self):
        """No analytics/telemetry libraries should be imported."""
        telemetry_modules = {
            "sentry_sdk",
            "bugsnag",
            "rollbar",
            "newrelic",
            "datadog",
            "segment",
            "mixpanel",
            "amplitude",
            "posthog",
            "google.analytics",
            "firebase",
        }
        for path, content in _read_sources():
            try:
                tree = ast.parse(content)
            except SyntaxError:
                continue
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        assert alias.name not in telemetry_modules, (
                            f"Telemetry import '{alias.name}' found in "
                            f"{path.relative_to(ROOT)}:{node.lineno}"
                        )
                elif isinstance(node, ast.ImportFrom):
                    if node.module:
                        root_module = node.module.split(".")[0]
                        assert root_module not in telemetry_modules, (
                            f"Telemetry import from '{node.module}' found in "
                            f"{path.relative_to(ROOT)}:{node.lineno}"
                        )


class TestNoCredentialLeaks:
    """Ensure API keys are not logged or exposed in responses."""

    def test_no_api_key_in_log_statements(self):
        """Log statements should not reference api_key or token values directly."""
        # Pattern: logger calls that interpolate api_key or token variables
        # (not just mentioning the word "token" in a message string)
        dangerous_patterns = [
            re.compile(r"logger\.\w+\(.*\bapi_key\b.*%[sd]", re.IGNORECASE),
            re.compile(r'logger\.\w+\(.*f".*\{.*api_key.*\}"', re.IGNORECASE),
            re.compile(r'logger\.\w+\(.*f".*\{.*bot_token.*\}"', re.IGNORECASE),
            re.compile(r'logger\.\w+\(.*f".*\{.*secret.*\}"', re.IGNORECASE),
            re.compile(r"print\(.*api_key", re.IGNORECASE),
            re.compile(r"print\(.*bot_token", re.IGNORECASE),
        ]
        for path, content in _read_sources():
            for line_num, line in enumerate(content.splitlines(), 1):
                for pattern in dangerous_patterns:
                    assert not pattern.search(line), (
                        f"Potential credential leak in log at "
                        f"{path.relative_to(ROOT)}:{line_num}: {line.strip()}"
                    )

    def test_env_file_in_gitignore(self):
        """The .env file must be in .gitignore to prevent credential commits."""
        gitignore = (ROOT / ".gitignore").read_text()
        assert ".env" in gitignore, ".env must be listed in .gitignore"

    def test_env_example_has_no_real_keys(self):
        """The .env.example file should only have empty/placeholder values."""
        env_example = (ROOT / ".env.example").read_text()
        for line in env_example.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" in line:
                key, _, value = line.partition("=")
                value = value.strip().strip('"').strip("'")
                # Value should be empty or a safe placeholder/default
                assert not any(
                    p.search(value) for p in TestNoHardcodedSecrets._SECRET_PATTERNS
                ), f"Potential real secret in .env.example: {key}"


class TestAccessControl:
    """Ensure authorization checks exist for messaging platforms."""

    def test_telegram_has_user_id_check(self):
        """Telegram adapter must check allowed_user_id."""
        telegram_path = ROOT / "messaging" / "platforms" / "telegram.py"
        content = telegram_path.read_text()
        assert "allowed_user_id" in content, (
            "Telegram adapter must check allowed_user_id"
        )
        assert "Unauthorized" in content or "unauthorized" in content.lower(), (
            "Telegram adapter must log/reject unauthorized access"
        )

    def test_discord_has_channel_check(self):
        """Discord adapter must check allowed_channel_ids."""
        discord_path = ROOT / "messaging" / "platforms" / "discord.py"
        content = discord_path.read_text()
        assert "allowed_channel_ids" in content, (
            "Discord adapter must check allowed_channel_ids"
        )
