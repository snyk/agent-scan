from io import StringIO
from unittest.mock import patch

import pytest
from rich.console import Console

from agent_scan.consent import _render_env_redacted, collect_consent
from agent_scan.models import ClientToInspect, RemoteServer, StdioServer


def test_collect_consent_requires_confirmation_for_remote_servers():
    client = ClientToInspect(
        name="cursor",
        client_path="/project",
        mcp_configs={
            "/project/.mcp.json": [
                (
                    "attacker-controlled",
                    RemoteServer(
                        url="https://example.test/mcp",
                        type="http",
                        headers={"Authorization": "secret", "X-Custom": "value"},
                    ),
                )
            ]
        },
        skills_dirs={},
    )

    with (
        patch("agent_scan.consent._read_yes_no", return_value=False) as read_yes_no,
        patch("agent_scan.consent._stderr_console.print") as console_print,
    ):
        declined = collect_consent([client])

    assert declined == {("/project/.mcp.json", "attacker-controlled")}
    read_yes_no.assert_called_once_with("      Allow Agent Scan to connect to 'attacker-controlled'? [y/N]: ")
    rendered = "\n".join(str(call.args[0]) for call in console_print.call_args_list)
    assert "Remote MCP servers (require consent)" in rendered
    assert "https://example.test/mcp" in rendered
    assert "Authorization=***" in rendered
    assert "X-Custom=***" in rendered
    assert "secret" not in rendered
    assert "value" not in rendered


def test_collect_consent_tracks_stdio_and_remote_decisions_together():
    client = ClientToInspect(
        name="cursor",
        client_path="/project",
        mcp_configs={
            "/project/.mcp.json": [
                ("local", StdioServer(command="example-mcp")),
                ("remote", RemoteServer(url="https://example.test/mcp")),
            ]
        },
        skills_dirs={},
    )

    with (
        patch("agent_scan.consent._read_yes_no", side_effect=[True, False]),
        patch("agent_scan.consent._stderr_console.print"),
    ):
        declined = collect_consent([client])

    assert declined == {("/project/.mcp.json", "remote")}


@pytest.mark.parametrize(
    ("url", "expected", "secrets"),
    [
        (
            "https://example.test:8443/Mcp%2fPath?api_key=secret-key&token=secret-token&sig=secret-signature",
            "https://example.test:8443/Mcp%2fPath?api_key=***&token=***&sig=***",
            ["secret-key", "secret-token", "secret-signature"],
        ),
        ("https://example.test:8443/Mcp%2fPath", "https://example.test:8443/Mcp%2fPath", []),
        (
            "https://example.test/mcp?a=first-secret&b=second-secret&a=third-secret",
            "https://example.test/mcp?a=***&b=***&a=***",
            ["first-secret", "second-secret", "third-secret"],
        ),
        ("https://example.test/mcp?empty=&flag", "https://example.test/mcp?empty=***&flag=***", []),
        (
            "https://example.test/mcp?%61pi+key=encoded%26secret&&token%2fname=another=secret&#section",
            "https://example.test/mcp?%61pi+key=***&&token%2fname=***&#section",
            ["encoded%26secret", "another=secret"],
        ),
        ("https://example.test/mcp#section?not-a-query", "https://example.test/mcp#section?not-a-query", []),
    ],
)
def test_collect_consent_redacts_url_query_values_without_changing_destination(url, expected, secrets):
    server = RemoteServer(url=url)
    client = ClientToInspect(
        name="cursor",
        client_path="/project",
        mcp_configs={"/project/.mcp.json": [("remote", server)]},
        skills_dirs={},
    )
    output = StringIO()
    with (
        patch("agent_scan.consent._read_yes_no", return_value=True),
        patch("agent_scan.consent._stderr_console", Console(file=output, width=200, color_system=None)),
    ):
        assert collect_consent([client]) == set()

    rendered = output.getvalue()
    url_line = next(line for line in rendered.splitlines() if "URL    : " in line)
    assert url_line == f"      URL    : {expected}"
    for secret in secrets:
        assert secret not in rendered
    assert server.url == url


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
