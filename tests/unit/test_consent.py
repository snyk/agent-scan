from unittest.mock import patch

from agent_scan.consent import collect_consent
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
