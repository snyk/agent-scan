"""Credential-format regressions for ADS-1331; all values are synthetic."""

import pytest

from agent_scan.redact import redact_text
from agent_scan.skill_client import collect_skill_files


@pytest.mark.parametrize(
    "text,values",
    [
        ("password hunter2plain\n", ["hunter2plain"]),
        (
            "machine example.test login demo-user password hunter2plain\n",
            ["example.test", "demo-user", "hunter2plain"],
        ),
        (
            "machine example.test\n  login demo-user\n  password hunter2plain\n",
            ["example.test", "demo-user", "hunter2plain"],
        ),
        ('default login "demo user" password "plain test password"', ["demo user", "plain test password"]),
        ("\tPASSWORD\thunter2plain", ["hunter2plain"]),
    ],
)
def test_redact_netrc_credentials(text, values):
    redacted = redact_text(text)

    assert redacted is not None
    assert all(value not in redacted for value in values)
    assert "**REDACTED_SECRET_NETRCCREDENTIAL**" in redacted
    assert redacted.count("\n") == text.count("\n")


@pytest.mark.parametrize(
    "kind", ["OPENSSH PRIVATE KEY", "RSA PRIVATE KEY", "EC PRIVATE KEY", "PRIVATE KEY", "ENCRYPTED PRIVATE KEY"]
)
@pytest.mark.parametrize("newline", ["\n", "\r\n"])
def test_redact_entire_private_key_block(kind, newline):
    block = newline.join([f"-----BEGIN {kind}-----", "lowentropy", "aaaaaaaabbbbbbbb", f"-----END {kind}-----"])

    assert redact_text(f"before\n{block}\nafter\n") == "before\n**REDACTED_SECRET_PRIVATEKEYDETECTOR**\nafter\n"


def test_redact_multiple_private_keys_without_removing_surrounding_text():
    block = "-----BEGIN OPENSSH PRIVATE KEY-----\nlowentropy\n-----END OPENSSH PRIVATE KEY-----"

    assert redact_text(f"{block}\nbetween\n{block}") == (
        "**REDACTED_SECRET_PRIVATEKEYDETECTOR**\nbetween\n**REDACTED_SECRET_PRIVATEKEYDETECTOR**"
    )


def test_redact_unterminated_private_key_to_end_of_text():
    assert redact_text("before\n-----BEGIN OPENSSH PRIVATE KEY-----\nlowentropy\n") == (
        "before\n**REDACTED_SECRET_PRIVATEKEYDETECTOR**"
    )


def test_redact_credentials_leaves_unrelated_prose_and_public_key_blocks():
    text = "Use the machine to build.\nCheck login documentation.\n-----BEGIN PUBLIC KEY-----\nlowentropy\n-----END PUBLIC KEY-----"
    assert redact_text(text) == text


def test_skill_collection_redacts_netrc_and_private_key_content(tmp_path):
    (tmp_path / ".netrc").write_text("machine example.test login demo-user password hunter2plain\n")
    (tmp_path / "key.txt").write_text(
        "-----BEGIN OPENSSH PRIVATE KEY-----\nlowentropy\n-----END OPENSSH PRIVATE KEY-----\n"
    )

    files = collect_skill_files(str(tmp_path))

    assert len(files) == 2
    assert all("**REDACTED_SECRET_" in file.content for file in files)
    assert all("hunter2plain" not in file.content and "lowentropy" not in file.content for file in files)
