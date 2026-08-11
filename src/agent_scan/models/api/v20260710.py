"""Request and response models for the v2026-07-10 analysis contract.

The request carries the normalized inventory produced by inspection. The
response reports MCP and skill risks separately, then groups both component
types under the path that was analyzed.
"""

from typing import Any, Literal

from pydantic import BaseModel, Field

from agent_scan.models.api.common import ScanUserInfo
from agent_scan.models.errors import ScanError
from agent_scan.models.inspect import InspectedPath, InspectedServer, InspectedSkill
from agent_scan.models.mcp import RemoteServer, ServerSignature, StdioServer
from agent_scan.models.skill import SkillFile


def _error_for_request(error: ScanError | None) -> ScanError | None:
    """Copy an error while keeping machine-local diagnostics off the wire."""
    if error is None:
        return None

    # Imported lazily because ``redact`` depends on the public model facade,
    # which imports this version module while that facade is initialized.
    from agent_scan.redact import redact_absolute_paths, redact_text

    def sanitize(value: Exception | str | None) -> str | None:
        if value is None:
            return None
        return redact_absolute_paths(redact_text(str(value)))

    sanitized = error.clone()
    sanitized.message = sanitize(sanitized.message)
    sanitized.exception = sanitize(sanitized.exception)
    sanitized.traceback = None
    sanitized.server_output = sanitize(sanitized.server_output)
    return sanitized


def _server_for_request(server: StdioServer | RemoteServer) -> StdioServer | RemoteServer:
    """Copy and sanitize a server config without changing local inspect output."""
    # See the lazy-import note in ``_error_for_request`` above.
    from agent_scan.redact import redact_server_config

    return redact_server_config(server.model_copy(deep=True))


# Request inventory and envelope
# ------------------------------
# These are deliberately distinct from the local inspection models. Conversion
# at the API boundary controls exactly which inspected data leaves the process.
class McpServerRequest(BaseModel):
    name: str
    config_path: str | None = None
    server: StdioServer | RemoteServer
    signature: ServerSignature | None = None
    error: ScanError | None = None

    @classmethod
    def from_inspected(cls, inspected: InspectedServer) -> "McpServerRequest":
        return cls(
            name=inspected.name,
            config_path=inspected.config_path,
            server=_server_for_request(inspected.server),
            signature=inspected.signature.model_copy(deep=True) if inspected.signature else None,
            error=_error_for_request(inspected.error),
        )


class SkillRequest(BaseModel):
    name: str
    installation_path: str
    files: list[SkillFile] = Field(default_factory=list)
    error: ScanError | None = None

    @classmethod
    def from_inspected(cls, inspected: InspectedSkill) -> "SkillRequest":
        return cls(
            name=inspected.name,
            installation_path=inspected.installation_path,
            files=[file.model_copy(deep=True) for file in inspected.files],
            error=_error_for_request(inspected.error),
        )


class ScanPathRequest(BaseModel):
    client: str | None = None
    path: str
    servers: list[McpServerRequest] = Field(default_factory=list)
    skills: list[SkillRequest] = Field(default_factory=list)
    error: ScanError | None = None

    @classmethod
    def from_inspected(cls, inspected: InspectedPath) -> "ScanPathRequest":
        return cls(
            client=inspected.client,
            path=inspected.path,
            servers=[McpServerRequest.from_inspected(server) for server in inspected.servers],
            skills=[SkillRequest.from_inspected(skill) for skill in inspected.skills],
            error=_error_for_request(inspected.error),
        )


class ScanRequest(BaseModel):
    scan_path_requests: list[ScanPathRequest]
    scan_user_info: ScanUserInfo | None = None
    scan_metadata: dict[str, Any] | None = None

    @classmethod
    def from_inspected_paths(
        cls,
        inspected_paths: list[InspectedPath],
        *,
        scan_user_info: ScanUserInfo | None = None,
        scan_metadata: dict[str, Any] | None = None,
    ) -> "ScanRequest":
        return cls(
            scan_path_requests=[ScanPathRequest.from_inspected(path) for path in inspected_paths],
            scan_user_info=scan_user_info,
            scan_metadata=scan_metadata,
        )


# MCP risk models
class RiskScore(BaseModel):
    score: int = Field(ge=0, le=1000)
    evidence: str
    affected_tools: list[int] | None = None


class McpServerRiskIndexes(BaseModel):
    dangerous_words: RiskScore | None = None
    prompt_injection_tool_desc: RiskScore | None = None
    untrusted_content: RiskScore | None = None
    private_data: RiskScore | None = None
    destructive_capabilities: RiskScore | None = None


MCP_SERVER_RISK_DISPLAY_NAMES: dict[str, str] = {
    "dangerous_words": "Dangerous words",
    "prompt_injection_tool_desc": "Prompt injection in tool",
    "untrusted_content": "Untrusted content",
    "private_data": "Private data",
    "destructive_capabilities": "Destructive capabilities",
}


class McpEntitySummary(BaseModel):
    name: str
    type: Literal["tool", "resource", "resource_template", "prompt"]


class McpServerRiskResponse(BaseModel):
    name: str
    entities: list[McpEntitySummary] = Field(default_factory=list)
    risk_indexes: McpServerRiskIndexes = Field(default_factory=McpServerRiskIndexes)
    error: ScanError | None = None


# Skill risk models
class Occurrence(BaseModel):
    path: str
    line: int | None = None
    offset: int | None = None


class Region(BaseModel):
    start: Occurrence
    end: Occurrence | None = None


class SkillRiskScore(BaseModel):
    score: int = Field(ge=0, le=1000)
    evidence: str
    locations: list[Region] | None = None


class MaliciousURLSkillRiskScore(SkillRiskScore):
    malicious_urls: list[str] = Field(default_factory=list)


class UnverifiableURLSkillRiskScore(SkillRiskScore):
    unverifiable_urls: list[str] = Field(default_factory=list)


class SkillRiskIndexes(BaseModel):
    prompt_injection_skill_instructions: SkillRiskScore | None = None
    suspicious_download_url: MaliciousURLSkillRiskScore | None = None
    malicious_code: SkillRiskScore | None = None
    insecure_credential_handling: SkillRiskScore | None = None
    secret_detection: SkillRiskScore | None = None
    direct_money_access: SkillRiskScore | None = None
    third_party_content_exposure: SkillRiskScore | None = None
    unverifiable_dependencies: UnverifiableURLSkillRiskScore | None = None
    modifying_system_services: SkillRiskScore | None = None
    missing_skill_md: SkillRiskScore | None = None


SKILL_RISK_DISPLAY_NAMES: dict[str, str] = {
    "prompt_injection_skill_instructions": "Potential prompt injection",
    "suspicious_download_url": "Suspicious download URL",
    "malicious_code": "Malicious code",
    "insecure_credential_handling": "Insecure credential handling",
    "secret_detection": "Secret detection",
    "direct_money_access": "Direct money access",
    "third_party_content_exposure": "Third party content exposure",
    "unverifiable_dependencies": "Unverifiable dependencies",
    "modifying_system_services": "Attempt to modify system services",
    "missing_skill_md": "Missing SKILL.md",
}


class SkillFileSummary(BaseModel):
    name: str
    type: Literal["instruction", "script", "asset"]


class SkillRiskResponse(BaseModel):
    name: str
    files: list[SkillFileSummary] = Field(default_factory=list)
    risk_indexes: SkillRiskIndexes = Field(default_factory=SkillRiskIndexes)
    error: ScanError | None = None


# Mapping of risk index keys to human-readable display names for UI rendering.
RISK_DISPLAY_NAMES: dict[str, str] = {
    **MCP_SERVER_RISK_DISPLAY_NAMES,
    **SKILL_RISK_DISPLAY_NAMES,
}


class ScanPathResponse(BaseModel):
    client: str | None = None
    path: str
    server_risks: list[McpServerRiskResponse] = Field(default_factory=list)
    skill_risks: list[SkillRiskResponse] = Field(default_factory=list)
    error: ScanError | None = None


class ScanResponse(BaseModel):
    scan_path_responses: list[ScanPathResponse]
