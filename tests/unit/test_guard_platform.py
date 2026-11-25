from types import SimpleNamespace

import pytest

from agent_scan import guard_platform


@pytest.mark.parametrize(
    ("system", "build", "machine", "pointer_bytes", "expected"),
    [
        ("linux", "x86_64-linux-gnu", "aarch64", 8, {"os": "Linux", "arch": "x64"}),
        ("linux", "i686-linux-gnu", "x86_64", 4, {"os": "Linux"}),
        ("darwin", "", "x86_64", 8, {"os": "Darwin", "arch": "x64"}),
        ("freebsd", "", "aarch64", 8, {"arch": "arm64"}),
        ("linux", "riscv64-linux-gnu", "riscv64", 8, {"os": "Linux"}),
    ],
)
def test_installation_platform(system, build, machine, pointer_bytes, expected, monkeypatch):
    monkeypatch.setattr(
        guard_platform, "sys", SimpleNamespace(platform=system, implementation=SimpleNamespace(_multiarch=build))
    )
    monkeypatch.setattr(guard_platform, "os", SimpleNamespace(uname=lambda: SimpleNamespace(machine=machine)))
    monkeypatch.setattr(guard_platform, "struct", SimpleNamespace(calcsize=lambda _: pointer_bytes))
    assert guard_platform.collect_platform() == expected
