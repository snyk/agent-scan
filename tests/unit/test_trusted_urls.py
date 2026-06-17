"""Tests for the --trusted-urls / --trusted-urls-file finding-suppression feature."""

import json
from argparse import Namespace

import pytest

from agent_scan.cli import (
    _apply_trusted_urls,
    _classify_trusted_patterns,
    _host_is_trusted,
    _load_trusted_urls,
    _message_urls_all_trusted,
)
from agent_scan.models import Issue, ScanPathResult


def _result(path: str, *issues: Issue) -> ScanPathResult:
    return ScanPathResult(path=path, issues=list(issues))


class TestClassifyTrustedPatterns:
    def test_splits_networks_and_domains(self):
        networks, domains = _classify_trusted_patterns(
            ["nexus.corp", "10.0.0.0/8", "192.168.1.5", "artifacts.internal"]
        )
        assert [str(n) for n in networks] == ["10.0.0.0/8", "192.168.1.5/32"]
        assert domains == ["nexus.corp", "artifacts.internal"]

    def test_strips_glob_prefix_and_lowercases(self):
        networks, domains = _classify_trusted_patterns(["*.Internal", "  Nexus.CORP  "])
        assert networks == []
        assert domains == ["internal", "nexus.corp"]

    def test_ignores_blank_patterns(self):
        networks, domains = _classify_trusted_patterns(["", "  ", "nexus.corp"])
        assert networks == []
        assert domains == ["nexus.corp"]

    def test_bare_glob_does_not_produce_empty_domain(self):
        # "*." strips to "" — must not become a trusted domain (would match
        # almost any host via endswith(".")).
        networks, domains = _classify_trusted_patterns(["*.", " *. ", "nexus.corp"])
        assert networks == []
        assert "" not in domains
        assert domains == ["nexus.corp"]


class TestHostIsTrusted:
    @pytest.fixture
    def buckets(self):
        return _classify_trusted_patterns(["nexus.corp", "*.internal", "10.0.0.0/8"])

    def test_exact_domain(self, buckets):
        assert _host_is_trusted("nexus.corp", *buckets)

    def test_subdomain_of_trusted_domain(self, buckets):
        assert _host_is_trusted("artifacts.internal", *buckets)

    def test_ip_inside_cidr(self, buckets):
        assert _host_is_trusted("10.5.5.5", *buckets)

    def test_ip_outside_cidr(self, buckets):
        assert not _host_is_trusted("172.16.0.1", *buckets)

    def test_empty_host(self, buckets):
        assert not _host_is_trusted("", *buckets)

    # --- substring traps the old `pattern in message` logic would have allowed ---

    def test_lookalike_domain_not_trusted(self, buckets):
        # "corp" is a substring of "evil-corp.com" but not a label-boundary match.
        assert not _host_is_trusted("evil-corp.com", *buckets)

    def test_label_boundary_trap_not_trusted(self, buckets):
        # "internal" is a prefix label of "internal.attacker.io" — must NOT match.
        assert not _host_is_trusted("internal.attacker.io", *buckets)

    def test_ipv6_brackets_stripped(self):
        networks, domains = _classify_trusted_patterns(["::1/128"])
        assert _host_is_trusted("[::1]", networks, domains)

    def test_trailing_dot_fqdn_matches(self, buckets):
        # A fully-qualified host with a trailing dot must match the trusted domain.
        assert _host_is_trusted("nexus.corp.", *buckets)
        assert _host_is_trusted("artifacts.internal.", *buckets)

    def test_bare_glob_pattern_does_not_match_arbitrary_host(self):
        # Regression: "*." must not be usable to trust everything.
        networks, domains = _classify_trusted_patterns(["*."])
        assert not _host_is_trusted("anything.evil.com", networks, domains)


class TestMessageUrlsAllTrusted:
    @pytest.fixture
    def buckets(self):
        return _classify_trusted_patterns(["nexus.corp", "*.internal", "10.0.0.0/8"])

    def test_single_trusted_url(self, buckets):
        assert _message_urls_all_trusted("Suspicious download http://nexus.corp/install.sh", *buckets)

    def test_single_untrusted_url(self, buckets):
        assert not _message_urls_all_trusted("Download http://evil.com/x.sh", *buckets)

    def test_all_urls_must_be_trusted(self, buckets):
        msg = "Two urls http://nexus.corp/a and http://evil.com/b"
        assert not _message_urls_all_trusted(msg, *buckets)

    def test_fails_closed_when_no_url(self, buckets):
        assert not _message_urls_all_trusted("No url here at all", *buckets)

    def test_trailing_punctuation_not_part_of_host(self, buckets):
        # The closing paren/quote must not be swallowed into the host.
        assert _message_urls_all_trusted('Fetch from "http://artifacts.internal/tool.sh".', *buckets)


class TestApplyTrustedUrls:
    def test_suppresses_matching_url_bearing_code(self):
        result = [
            _result(
                "/p",
                Issue(code="E005", message="Suspicious download http://nexus.corp/x.sh", reference=None),
            )
        ]
        _apply_trusted_urls(result, ["nexus.corp"])
        assert result[0].issues == []

    def test_keeps_untrusted_url(self):
        issue = Issue(code="E005", message="Download http://evil.com/x.sh", reference=None)
        result = [_result("/p", issue)]
        _apply_trusted_urls(result, ["nexus.corp"])
        assert result[0].issues == [issue]

    def test_does_not_touch_non_url_codes(self):
        # A prompt-injection finding that happens to mention a trusted host must survive.
        issue = Issue(code="E001", message="Prompt injection referencing http://nexus.corp", reference=None)
        result = [_result("/p", issue)]
        _apply_trusted_urls(result, ["nexus.corp"])
        assert result[0].issues == [issue]

    def test_noop_when_no_patterns(self):
        issue = Issue(code="E005", message="http://nexus.corp/x.sh", reference=None)
        result = [_result("/p", issue)]
        _apply_trusted_urls(result, [])
        assert result[0].issues == [issue]

    def test_w011_and_w012_are_in_scope(self):
        result = [
            _result(
                "/p",
                Issue(code="W011", message="Untrusted content http://nexus.corp/feed", reference=None),
                Issue(code="W012", message="Remote dep http://nexus.corp/cfg", reference=None),
            )
        ]
        _apply_trusted_urls(result, ["nexus.corp"])
        assert result[0].issues == []


class TestLoadTrustedUrls:
    def test_flag_only(self):
        args = Namespace(trusted_urls="nexus.corp, 10.0.0.0/8 ", trusted_urls_file=None)
        assert _load_trusted_urls(args) == ["nexus.corp", "10.0.0.0/8"]

    def test_file_only(self, tmp_path):
        f = tmp_path / "trusted.json"
        f.write_text(json.dumps({"trusted_urls": ["nexus.corp", "*.internal"]}))
        args = Namespace(trusted_urls=None, trusted_urls_file=str(f))
        assert _load_trusted_urls(args) == ["nexus.corp", "*.internal"]

    def test_flag_and_file_merged(self, tmp_path):
        f = tmp_path / "trusted.json"
        f.write_text(json.dumps({"trusted_urls": ["artifacts.internal"]}))
        args = Namespace(trusted_urls="nexus.corp", trusted_urls_file=str(f))
        assert _load_trusted_urls(args) == ["nexus.corp", "artifacts.internal"]

    def test_no_sources(self):
        args = Namespace(trusted_urls=None, trusted_urls_file=None)
        assert _load_trusted_urls(args) == []

    def test_missing_file_exits(self, tmp_path):
        args = Namespace(trusted_urls=None, trusted_urls_file=str(tmp_path / "nope.json"))
        with pytest.raises(SystemExit) as exc:
            _load_trusted_urls(args)
        assert exc.value.code == 2

    def test_invalid_json_exits(self, tmp_path):
        f = tmp_path / "bad.json"
        f.write_text("{not json")
        args = Namespace(trusted_urls=None, trusted_urls_file=str(f))
        with pytest.raises(SystemExit) as exc:
            _load_trusted_urls(args)
        assert exc.value.code == 2

    def test_wrong_shape_exits(self, tmp_path):
        f = tmp_path / "shape.json"
        f.write_text(json.dumps(["nexus.corp"]))  # list, not {"trusted_urls": [...]}
        args = Namespace(trusted_urls=None, trusted_urls_file=str(f))
        with pytest.raises(SystemExit) as exc:
            _load_trusted_urls(args)
        assert exc.value.code == 2

    def test_trusted_urls_not_a_list_exits(self, tmp_path):
        f = tmp_path / "shape2.json"
        f.write_text(json.dumps({"trusted_urls": "nexus.corp"}))
        args = Namespace(trusted_urls=None, trusted_urls_file=str(f))
        with pytest.raises(SystemExit) as exc:
            _load_trusted_urls(args)
        assert exc.value.code == 2
