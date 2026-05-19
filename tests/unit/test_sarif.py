from agent_scan.models import Issue, RemoteServer, ScanError, ScanPathResult, ServerScanResult
from agent_scan.sarif import scan_results_to_sarif


def test_sarif_includes_issues_and_runtime_failures(tmp_path):
    config_path = tmp_path / "mcp.json"
    config_path.write_text("{}", encoding="utf-8")
    scan_result = ScanPathResult(
        path=str(config_path),
        issues=[Issue(code="E001", message="Prompt injection risk", reference=None)],
        error=ScanError(message="parse failed", is_failure=True, category="parse_error"),
    )

    sarif = scan_results_to_sarif([scan_result], base_dir=tmp_path)

    assert sarif["version"] == "2.1.0"
    run = sarif["runs"][0]
    rule_ids = {rule["id"] for rule in run["tool"]["driver"]["rules"]}
    assert rule_ids == {"E001", "X005"}

    results = run["results"]
    assert [result["ruleId"] for result in results] == ["E001", "X005"]
    assert results[0]["level"] == "error"
    assert results[0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "mcp.json"
    assert results[1]["message"]["text"] == f"[X005] Failed to scan {config_path}: parse failed"


def test_sarif_includes_server_failure_reference(tmp_path):
    config_path = tmp_path / "mcp.json"
    config_path.write_text("{}", encoding="utf-8")
    scan_result = ScanPathResult(
        path=str(config_path),
        servers=[
            ServerScanResult(
                name="github",
                server=RemoteServer(url="https://example.com/mcp"),
                error=ScanError(message="startup failed", is_failure=True, category="server_startup"),
            )
        ],
    )

    sarif = scan_results_to_sarif([scan_result], base_dir=tmp_path)

    result = sarif["runs"][0]["results"][0]
    assert result["ruleId"] == "X001"
    assert result["level"] == "error"
    assert result["properties"]["reference"] == [0, None]
    assert "github" in result["message"]["text"]
