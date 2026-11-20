"""Tests for atropa.backend.snapshots - snapper on Btrfs."""

from __future__ import annotations

import json

import pytest

from atropa import helper
from atropa.backend import snapshots

ROOT = ["findmnt", "-n", "-o", "FSTYPE,SOURCE,OPTIONS", "/"]


@pytest.fixture
def system(tmp_path, monkeypatch, fake_run):
    """A root filesystem described by findmnt, an fstab and a cmdline - all fake."""
    fstab, cmdline, snaps = tmp_path / "fstab", tmp_path / "cmdline", tmp_path / ".snapshots"
    fstab.write_text("")
    cmdline.write_text("root=UUID=x rw\n")
    monkeypatch.setattr(snapshots, "FSTAB", fstab)
    monkeypatch.setattr(snapshots, "CMDLINE", cmdline)
    monkeypatch.setattr(snapshots, "SNAPSHOTS_DIR", snaps)
    monkeypatch.setattr(snapshots, "SNAPPER_CONFIG", tmp_path / "configs" / "root")
    monkeypatch.setattr(snapshots, "SNAPPER_CONFD", tmp_path / "conf.d-snapper")

    class System:
        def root(self, line):
            fake_run.set_response(ROOT, stdout=line + "\n")

        def snapshots_mount(self, mounted: bool):
            snaps.mkdir(exist_ok=True)
            argv = ["findmnt", "-n", "-o", "FSTYPE,SOURCE,OPTIONS", str(snaps)]
            if mounted:
                fake_run.set_response(argv, stdout="btrfs /dev/vda3[/@.snapshots] rw,subvol=/@.snapshots\n")
            else:
                fake_run.set_response(argv, returncode=1)

    s = System()
    s.fstab, s.cmdline, s.snaps, s.tmp = fstab, cmdline, snaps, tmp_path
    return s


# ---------------------------------------------------------------- layout --

def test_top_level_root(system):
    system.root("btrfs /dev/vda3 rw,relatime,compress=zstd:1,subvolid=5,subvol=/")
    layout = snapshots.layout()
    assert (layout.btrfs, layout.kind, layout.subvol, layout.device) == (True, "top-level", "/", "/dev/vda3")
    assert "can't be swapped" in layout.rollback


def test_archinstall_subvolume_pinned_in_fstab(system):
    system.root("btrfs /dev/nvme0n1p2[/@] rw,noatime,subvolid=256,subvol=/@")
    system.fstab.write_text("UUID=x / btrfs rw,noatime,compress=zstd,subvol=/@ 0 0\n")
    system.snapshots_mount(True)
    layout = snapshots.layout()
    assert (layout.kind, layout.subvol, layout.snapshots_mounted) == ("subvolume", "/@", True)


def test_subvolume_pinned_only_on_the_kernel_command_line(system):
    system.root("btrfs /dev/sda2[/@] rw,subvol=/@")
    system.cmdline.write_text("root=UUID=x rw rootflags=subvol=@\n")
    assert snapshots.layout().kind == "subvolume"


def test_default_subvolume_root_supports_snapper_rollback(system):
    system.root("btrfs /dev/sda2[/@/.snapshots/1/snapshot] rw,subvol=/@/.snapshots/1/snapshot")
    layout = snapshots.layout()
    assert layout.kind == "default-subvolume"
    assert "snapper rollback" in layout.rollback


def test_not_btrfs(system):
    system.root("ext4 /dev/nvme0n1p3 rw,relatime")
    layout = snapshots.layout()
    assert (layout.btrfs, layout.kind) == (False, "not-btrfs")


# ----------------------------------------------------------------- setup --

def _capture_streaming(monkeypatch):
    calls = []

    def fake(argv, on_line, **kwargs):
        calls.append(argv)
        return snapshots.CommandResult(0, "", "")

    monkeypatch.setattr(snapshots, "run_privileged_streaming", fake)
    return calls


def test_setup_on_a_fresh_top_level_root_creates_the_config(system, fake_run, fake_which, monkeypatch):
    system.root("btrfs /dev/vda3 rw,subvolid=5,subvol=/")
    streamed = _capture_streaming(monkeypatch)
    assert snapshots.setup(lambda _l: None).ok
    assert streamed == [["pacman", "-S", "--needed", "--noconfirm", "snapper", "snap-pac"]]
    sent = [call[1:] for call in fake_run.calls if call[:1] == ["pkexec"]]
    assert sent == [
        ["snapper", "-c", "root", "create-config", "/"],
        ["systemctl", "enable", "--now", "snapper-cleanup.timer"],
    ]
    assert [helper.validate_command(argv)[0] for argv in sent] == [helper.ASK, helper.KEEP]


def test_setup_with_a_mounted_snapshots_subvolume_writes_the_config(system, fake_run, fake_which, monkeypatch):
    system.root("btrfs /dev/nvme0n1p2[/@] rw,subvol=/@")
    system.fstab.write_text("UUID=x / btrfs rw,subvol=/@ 0 0\n")
    system.snapshots_mount(True)
    template = system.tmp / "template"
    template.write_text('SUBVOLUME="/"\nFSTYPE="btrfs"\nALLOW_USERS=""\nNUMBER_LIMIT="50"\n')
    monkeypatch.setattr(snapshots, "TEMPLATE", template)
    system.tmp.joinpath("conf.d-snapper").write_text('# configs\nSNAPPER_CONFIGS=""\n')
    _capture_streaming(monkeypatch)

    assert snapshots.setup(lambda _l: None).ok

    sent = [(call[1:], text) for call, text in zip(fake_run.calls, fake_run.inputs) if call[:1] == ["pkexec"]]
    assert sent[0][0] == ["install", "-m", "0640", "/dev/stdin", str(snapshots.SNAPPER_CONFIG)]
    assert 'SUBVOLUME="/"' in sent[0][1] and 'ALLOW_USERS=""' in sent[0][1]
    assert sent[1][0] == ["tee", str(snapshots.SNAPPER_CONFD)]
    assert 'SNAPPER_CONFIGS="root"' in sent[1][1] and "# configs" in sent[1][1]
    assert not any("create-config" in call for call in fake_run.calls)


def test_setup_keeps_an_existing_config(system, fake_run, fake_which, monkeypatch):
    system.root("btrfs /dev/vda3 rw,subvol=/")
    snapshots.SNAPPER_CONFIG.parent.mkdir()
    snapshots.SNAPPER_CONFIG.write_text("SUBVOLUME=/\n")
    _capture_streaming(monkeypatch)
    snapshots.setup(lambda _l: None)
    assert not any("create-config" in call or "install" in call for call in fake_run.calls)


def test_setup_refuses_a_plain_snapshots_directory(system, fake_run, fake_which, monkeypatch):
    system.root("btrfs /dev/vda3 rw,subvol=/")
    system.snapshots_mount(False)
    _capture_streaming(monkeypatch)
    with pytest.raises(RuntimeError, match="isn't a mounted subvolume"):
        snapshots.setup(lambda _l: None)


def test_setup_refuses_a_non_btrfs_root(system, monkeypatch):
    system.root("ext4 /dev/nvme0n1p3 rw")
    monkeypatch.setattr(snapshots, "run_privileged_streaming", lambda *a, **k: pytest.fail("must not install"))
    with pytest.raises(RuntimeError, match="isn't on Btrfs"):
        snapshots.setup(lambda _l: None)


@pytest.mark.parametrize(
    ("before", "after"),
    [
        ('SNAPPER_CONFIGS=""\n', 'SNAPPER_CONFIGS="root"\n'),
        ('SNAPPER_CONFIGS="home"\n', 'SNAPPER_CONFIGS="home root"\n'),
        ('SNAPPER_CONFIGS="root"\n', 'SNAPPER_CONFIGS="root"\n'),
        ("", 'SNAPPER_CONFIGS="root"\n'),
    ],
)
def test_snapper_configs_line(before, after):
    assert snapshots._with_snapper_configs(before) == after


# -------------------------------------------------------------- snapshots --

LIST = {
    "root": [
        {"number": 0, "type": "single", "pre-number": None, "date": "", "description": "current", "cleanup": ""},
        {"number": 3, "type": "pre", "pre-number": None, "date": "2026-11-20 20:24:01",
         "description": "pacman -S --noconfirm xclip", "cleanup": "number"},
        {"number": 4, "type": "post", "pre-number": 3, "date": "2026-11-20 20:24:03",
         "description": "xclip", "cleanup": "number"},
    ]
}


def test_snapshots_newest_first_without_the_live_system(fake_run, fake_which):
    fake_run.set_response(["pkexec", "snapper", "--jsonout"], stdout=json.dumps(LIST))
    found = snapshots.snapshots()
    assert [(s.number, s.type, s.pre_number) for s in found] == [(4, "post", 3), (3, "pre", None)]
    assert helper.validate_command(fake_run.calls[-1][1:])[0] == helper.KEEP


def test_changes_parse_snapper_status(fake_run, fake_which):
    fake_run.set_response(
        ["pkexec", "snapper", "-c", "root", "status"],
        stdout="c..... /etc/pacman.conf\n+..... /usr/bin/xclip\n-..... /etc/old.conf\n.p.... /etc/shadow\n",
    )
    found = snapshots.changes(3)
    assert [(c.path, c.kind) for c in found] == [
        ("/etc/pacman.conf", "content changed"),
        ("/usr/bin/xclip", "created"),
        ("/etc/old.conf", "deleted"),
        ("/etc/shadow", "permissions changed"),
    ]
    assert fake_run.calls[-1][1:] == ["snapper", "-c", "root", "status", "3..0"]


@pytest.mark.parametrize(
    ("call", "argv", "tier"),
    [
        (lambda: snapshots.create("before the new kernel"),
         ["snapper", "-c", "root", "create", "-d", "before the new kernel", "--cleanup-algorithm", "number"], helper.KEEP),
        (lambda: snapshots.create("--help\nrm -rf"),
         ["snapper", "-c", "root", "create", "-d", "help rm -rf", "--cleanup-algorithm", "number"], helper.KEEP),
        (lambda: snapshots.create(""),
         ["snapper", "-c", "root", "create", "-d", "Atropa", "--cleanup-algorithm", "number"], helper.KEEP),
        (lambda: snapshots.delete(4), ["snapper", "-c", "root", "delete", "4"], helper.ASK),
        (lambda: snapshots.restore(3, ["/etc/pacman.conf"]),
         ["snapper", "-c", "root", "undochange", "3..0", "/etc/pacman.conf"], helper.ASK),
    ],
)
def test_snapshot_operations_pass_the_helper_in_their_tier(fake_run, fake_which, call, argv, tier):
    call()
    assert fake_run.calls[-1][1:] == argv
    assert helper.validate_command(argv)[0] == tier


@pytest.mark.parametrize(
    "argv",
    [
        ["snapper", "-c", "home", "list"],
        ["snapper", "-c", "root", "delete", "0"],
        ["snapper", "-c", "root", "delete", "3-9"],
        ["snapper", "-c", "root", "undochange", "3..0", "etc/passwd"],
        ["snapper", "-c", "root", "undochange", "3..5", "/etc/passwd"],
        ["snapper", "-c", "root", "rollback", "3"],
        ["snapper", "-c", "root", "set-config", "ALLOW_USERS=me"],
        ["snapper", "-c", "root", "create-config", "/home"],
        ["snapper", "-c", "root", "create", "-d", "x" * 201, "--cleanup-algorithm", "number"],
        ["snapper", "-c", "root", "create", "-d", "x", "--command", "sh"],
        ["snapper", "--root", "/home/me", "-c", "root", "list"],
    ],
)
def test_snapper_shapes_atropa_never_sends_are_refused(argv):
    with pytest.raises(helper.Refused):
        helper.validate_command(argv)


def test_snapper_config_files_need_the_ask_helper():
    assert helper.needs_fresh_auth(["install", "-m", "0640", "/dev/stdin", "/etc/snapper/configs/root"])
    assert helper.needs_fresh_auth(["tee", "/etc/conf.d/snapper"])


def test_grub_btrfs_and_cleanup_units_stay_remembered():
    assert helper.validate_command(["systemctl", "enable", "--now", "grub-btrfsd.service"])[0] == helper.KEEP
    assert helper.validate_command(["systemctl", "enable", "--now", "snapper-cleanup.timer"])[0] == helper.KEEP
