"""Unit tests for agent_scan.consent."""

from agent_scan.consent import _render_env_redacted
from agent_scan.models import StdioServer


class TestRenderEnvRedacted:
    def test_none_env_returns_none(self):
        server = StdioServer(command="npx", args=[])
        assert _render_env_redacted(server) is None

    def test_placeholder_value_is_shown_literally(self):
        server = StdioServer(command="npx", args=[], env={"AUTH_HEADER": "${AUTH_HEADER}"})
        assert _render_env_redacted(server) == "AUTH_HEADER=${AUTH_HEADER}"

    def test_literal_value_is_masked(self):
        server = StdioServer(command="npx", args=[], env={"API_KEY": "sk-real-secret-value"})
        assert _render_env_redacted(server) == "API_KEY=***"

    def test_mixed_placeholder_and_extra_text_is_masked(self):
        """A value that isn't ENTIRELY one placeholder may still mix in a real
        secret, so it stays masked -- only a whole-value placeholder is shown."""
        server = StdioServer(command="npx", args=[], env={"AUTH": "Bearer ${TOKEN}"})
        assert _render_env_redacted(server) == "AUTH=***"

    def test_multiple_keys_sorted_and_mixed(self):
        server = StdioServer(
            command="npx",
            args=[],
            env={"ZKEY": "${ZVAR}", "AKEY": "hardcoded-secret"},
        )
        assert _render_env_redacted(server) == "AKEY=***, ZKEY=${ZVAR}"
