"""Installer architecture-specific dependency tests."""

from importlib import util
from pathlib import Path
from types import SimpleNamespace


ROOT = Path(__file__).resolve().parents[2]
SPEC = util.spec_from_file_location("core_install_tasks", ROOT / "tasks.py")
assert SPEC is not None and SPEC.loader is not None
INSTALL_TASKS = util.module_from_spec(SPEC)
SPEC.loader.exec_module(INSTALL_TASKS)


class FakeContext:
    def __init__(self) -> None:
        self.commands = []

    def run(self, command, **kwargs):
        self.commands.append((command, kwargs))
        return SimpleNamespace(ok=True)


def _os_info(os_like):
    return INSTALL_TASKS.OsInfo(
        INSTALL_TASKS.OsName.UNKNOWN,
        os_like,
        0,
    )


def test_debian_arm64_installs_and_verifies_amd64_emulation(monkeypatch):
    monkeypatch.setattr(INSTALL_TASKS.platform, "machine", lambda: "aarch64")
    context = FakeContext()

    INSTALL_TASKS.install_arm64_container_emulation(
        context,
        _os_info(INSTALL_TASKS.OsLike.DEBIAN),
        hide=True,
    )

    commands = [command for command, _kwargs in context.commands]
    assert commands[0] == "sudo apt install -y qemu-user-static binfmt-support"
    assert "sudo systemctl restart systemd-binfmt.service" in commands
    assert any("update-binfmts --enable qemu-x86_64" in command for command in commands)
    assert any(
        "qemu-x86_64*" in command and "^flags:.*F" in command
        for command in commands
    )


def test_fedora_arm64_installs_static_x86_emulator(monkeypatch):
    monkeypatch.setattr(INSTALL_TASKS.platform, "machine", lambda: "arm64")
    context = FakeContext()

    INSTALL_TASKS.install_arm64_container_emulation(
        context,
        _os_info(INSTALL_TASKS.OsLike.REDHAT),
        hide=False,
    )

    commands = [command for command, _kwargs in context.commands]
    assert commands[0] == "sudo yum install -y qemu-user-static-x86"
    assert any(
        "qemu-x86_64*" in command and "^flags:.*F" in command
        for command in commands
    )
    assert not any("update-binfmts" in command for command in commands)


def test_amd64_does_not_install_emulation(monkeypatch):
    monkeypatch.setattr(INSTALL_TASKS.platform, "machine", lambda: "x86_64")
    context = FakeContext()

    INSTALL_TASKS.install_arm64_container_emulation(
        context,
        _os_info(INSTALL_TASKS.OsLike.DEBIAN),
        hide=True,
    )

    assert context.commands == []


def test_arm64_emulation_is_part_of_system_dependency_install(monkeypatch):
    monkeypatch.setattr(INSTALL_TASKS.platform, "machine", lambda: "aarch64")
    context = FakeContext()

    INSTALL_TASKS.install_system(
        context,
        _os_info(INSTALL_TASKS.OsLike.DEBIAN),
        hide=True,
        no_python=True,
    )

    commands = [command for command, _kwargs in context.commands]
    assert "sudo apt install -y qemu-user-static binfmt-support" in commands
    assert any("^flags:.*F" in command for command in commands)
