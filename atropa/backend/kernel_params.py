"""
atropa.backend.kernel_params
-------------------------------
Kernel parameters (the kernel command line), with a way back.

What's configured comes from the bootloader: GRUB's
``GRUB_CMDLINE_LINUX_DEFAULT`` and ``GRUB_CMDLINE_LINUX`` in
/etc/default/grub, or the ``options`` line of the systemd-boot entry that
boots the running kernel. What's running is /proc/cmdline; the two differ
until a reboot.

A wrong parameter can stop the machine from booting, so before every
change the current boot entry is kept with its current parameters:

- GRUB: the helper copies the running kernel's menuentry from grub.cfg into
  /boot/grub/custom.cfg (``grub-keep-previous``), titled "... (kernel
  parameters before DATE)". GRUB's stock 41_custom sources that file at
  boot, so the entry survives every grub-mkconfig. Then
  /etc/default/grub is edited (backed up by the helper) and grub.cfg
  regenerated; a failed regeneration puts the old file back.
- systemd-boot: the entry is copied to ``atropa-previous-<kernel>.conf``
  first, then its options line is edited.

Every write here asks for the password each time: kernel parameters are
root-equivalent (``init=``).

Unified kernel images (/etc/kernel/cmdline baked into the image) aren't
handled; the page says so.
"""

from __future__ import annotations

import re
import shlex
from dataclasses import dataclass
from datetime import date
from pathlib import Path

from . import bootloader, kernels
from .privilege import CommandResult, run_privileged

PROC_CMDLINE = Path("/proc/cmdline")
GRUB_CUSTOM_CFG = Path("/boot/grub/custom.cfg")
ATROPA_MARKER = "# Written by Atropa"

# A parameter Atropa writes: one word, no quotes or shell syntax.
_PARAM_RE = re.compile(r"^[A-Za-z0-9_.,:=/+-]+$")

LSM_APPARMOR = "lsm=landlock,lockdown,yama,integrity,apparmor,bpf"
LSM_SELINUX = "lsm=landlock,lockdown,yama,integrity,selinux,bpf"


@dataclass(frozen=True)
class Preset:
    key: str
    title: str
    detail: str
    param: str


# Switches on the page. The lsm= ones exclude each other (one lsm= list).
PRESETS = (
    Preset("apparmor", "AppArmor", "Load AppArmor at boot (its LSM list)", LSM_APPARMOR),
    Preset("selinux", "SELinux", "Load SELinux at boot (its LSM list)", LSM_SELINUX),
    Preset("slab_nomerge", "Separate slab caches", "Makes heap overflows harder to exploit", "slab_nomerge"),
    Preset("init_on_alloc", "Zero memory on allocation", "Small speed cost; stops leaks of old data", "init_on_alloc=1"),
    Preset("init_on_free", "Zero memory when freed", "Bigger speed cost (a few %)", "init_on_free=1"),
    Preset("page_alloc.shuffle", "Shuffle the page allocator", "Harder to predict memory layout", "page_alloc.shuffle=1"),
    Preset("randomize_kstack_offset", "Randomise the kernel stack offset", "Per system call", "randomize_kstack_offset=on"),
    Preset("vsyscall", "No vsyscall page", "Breaks only very old static binaries", "vsyscall=none"),
    Preset("debugfs", "No debugfs", "Hides kernel debug interfaces", "debugfs=off"),
    Preset("quiet", "Quiet boot", "Fewer kernel messages on screen while booting", "quiet"),
)


def _name(param: str) -> str:
    return param.split("=", 1)[0]


@dataclass
class KernelParams:
    bootloader: str  # "grub", "systemd-boot", "unknown"
    running: list[str]
    configured: list[str]  # [] with supported=False
    supported: bool
    reason: str  # why it isn't supported, when it isn't
    previous_entry: str  # path of the kept previous-parameters entry, "" if none
    entry_path: str = ""  # systemd-boot: the entry being edited


def running() -> list[str]:
    try:
        return PROC_CMDLINE.read_text().split()
    except OSError:
        return []


def _grub_vars(text: str) -> dict[str, list[str]]:
    values = {"GRUB_CMDLINE_LINUX_DEFAULT": [], "GRUB_CMDLINE_LINUX": []}
    for line in text.splitlines():
        for key in values:
            if line.startswith(f"{key}="):
                try:
                    words = shlex.split(line.split("=", 1)[1], comments=True)
                except ValueError:
                    words = []
                values[key] = words[0].split() if words else []
    return values


def _sd_boot_entry() -> tuple[str, str] | None:
    """(path, text) of the systemd-boot entry booting the running kernel."""
    running_kernel = next((k for k in kernels.status().kernels if k.running), None)
    if running_kernel is None:
        return None
    for loader_dir in bootloader._loader_dirs():
        files = bootloader._read_loader_dir(loader_dir)
        for path, text in files.items():
            name = Path(path).name
            if "/entries/" not in path or name.startswith("atropa-previous-"):
                continue
            if re.search(rf"^linux\s+\S*/vmlinuz-{re.escape(running_kernel.pkgbase)}\s*$", text, re.MULTILINE):
                return path, text
    return None


def _sd_options(text: str) -> list[str]:
    params: list[str] = []
    for line in text.splitlines():
        if line.startswith("options"):
            params += line.split()[1:]
    return params


def read() -> KernelParams:
    kind = bootloader.detect()
    now = running()
    if kind == "grub":
        try:
            text = bootloader.GRUB_DEFAULT_PATH.read_text(encoding="utf-8")
        except OSError as exc:
            return KernelParams(kind, now, [], False, f"Couldn't read {bootloader.GRUB_DEFAULT_PATH}: {exc}", "")
        values = _grub_vars(text)
        previous = str(GRUB_CUSTOM_CFG) if _is_ours(GRUB_CUSTOM_CFG) else ""
        return KernelParams(kind, now, values["GRUB_CMDLINE_LINUX"] + values["GRUB_CMDLINE_LINUX_DEFAULT"], True, "",
                            previous)
    if kind == "systemd-boot":
        found = _sd_boot_entry()
        if found is None:
            return KernelParams(kind, now, [], False, "No systemd-boot entry boots the running kernel "
                                "(a unified kernel image keeps its parameters in /etc/kernel/cmdline).", "")
        path, text = found
        previous = Path(path).parent / f"atropa-previous-{Path(path).stem}.conf"
        return KernelParams(kind, now, _sd_options(text), True, "",
                            str(previous) if bootloader._exists(previous) else "", entry_path=path)
    return KernelParams(kind, now, [], False, "No supported bootloader detected", "")


def _is_ours(path: Path) -> bool:
    try:
        return path.read_text(encoding="utf-8").startswith(ATROPA_MARKER)
    except PermissionError:
        return True  # 0600 root: Atropa writes it that way; a user's own is usually readable
    except OSError:
        return False


def check_param(param: str) -> str:
    if not _PARAM_RE.match(param) or param.startswith("-"):
        raise ValueError(f"{param!r} isn't a kernel parameter Atropa writes (one word, no quotes)")
    return param


def with_changes(params: list[str], add: list[str], remove: list[str]) -> list[str]:
    """
    `params` with `remove` taken out (by exact text, or by name when the
    removal has no "=") and `add` put in, replacing a parameter of the same
    name - so a new lsm= list replaces the old one instead of adding a
    second.
    """
    for param in add + remove:
        check_param(param)
    add_names = {_name(p) for p in add}
    kept = [
        p for p in params
        if p not in remove
        and not any("=" not in r and _name(p) == r for r in remove)
        and _name(p) not in add_names
    ]
    return kept + [p for p in add if p not in kept]


def _grub_text_with(text: str, configured: list[str], new: list[str]) -> str:
    """/etc/default/grub with the parameters changed: removals from either
    variable, additions in GRUB_CMDLINE_LINUX_DEFAULT."""
    values = _grub_vars(text)
    removed = [p for p in configured if p not in new]
    added = [p for p in new if p not in configured]
    linux = [p for p in values["GRUB_CMDLINE_LINUX"] if p not in removed]
    default = [p for p in values["GRUB_CMDLINE_LINUX_DEFAULT"] if p not in removed] + added
    text = bootloader._with_setting(text, r"GRUB_CMDLINE_LINUX_DEFAULT=", f'GRUB_CMDLINE_LINUX_DEFAULT="{" ".join(default)}"')
    return bootloader._with_setting(text, r"GRUB_CMDLINE_LINUX=", f'GRUB_CMDLINE_LINUX="{" ".join(linux)}"')


def _sd_text_with(text: str, new: list[str]) -> str:
    lines = [line for line in text.splitlines() if not line.startswith("options")]
    lines.append("options " + " ".join(new))
    return "\n".join(lines) + "\n"


def apply(add: list[str], remove: list[str]) -> CommandResult:
    """Change the configured parameters, keeping a boot entry with the current ones first."""
    state = read()
    if not state.supported:
        raise RuntimeError(state.reason)
    new = with_changes(state.configured, add, remove)
    if new == state.configured:
        return CommandResult(0, "Nothing to change", "")
    today = date.today().isoformat()

    if state.bootloader == "grub":
        running_kernel = next((k for k in kernels.status().kernels if k.running), None)
        if running_kernel is None:
            raise RuntimeError("The running kernel isn't a kernel package, so its boot entry can't be kept.")
        kept = run_privileged(["grub-keep-previous", today, running_kernel.pkgbase])
        if not kept.ok:
            return kept
        original = bootloader.GRUB_DEFAULT_PATH.read_text(encoding="utf-8")
        result = run_privileged(["tee", str(bootloader.GRUB_DEFAULT_PATH)],
                                input_text=_grub_text_with(original, state.configured, new))
        if not result.ok:
            return result
        result = bootloader.regenerate_config()
        if not result.ok:
            restore = run_privileged(["tee", str(bootloader.GRUB_DEFAULT_PATH)], input_text=original)
            note = "restored the previous" if restore.ok else "and restoring the previous one ALSO failed -"
            return CommandResult(result.returncode, result.stdout,
                                 f"{result.stderr.strip()} ({note} {bootloader.GRUB_DEFAULT_PATH})")
        return result

    path = Path(state.entry_path)
    text = bootloader._read_loader_dir(path.parent.parent)[str(path)]
    previous = path.parent / f"atropa-previous-{path.stem}.conf"
    title = next((line.split(maxsplit=1)[1] for line in text.splitlines()
                  if line.startswith("title") and len(line.split()) > 1), path.stem)
    kept_text = re.sub(r"^title\s+.*$", f"title   {title} (kernel parameters before {today})", text,
                       count=1, flags=re.MULTILINE)
    if not kept_text.startswith("title"):
        kept_text = f"title   {title} (kernel parameters before {today})\n" + kept_text
    kept = run_privileged(["tee", str(previous)], input_text=kept_text)
    if not kept.ok:
        return kept
    return run_privileged(["tee", str(path)], input_text=_sd_text_with(text, new))


def forget_previous() -> CommandResult:
    """Remove the kept previous-parameters entry."""
    state = read()
    if state.bootloader == "grub":
        result = run_privileged(["grub-keep-previous", "--clear"])
        return result
    if state.previous_entry:
        return run_privileged(["loader-entry-remove", state.previous_entry])
    return CommandResult(0, "", "")
