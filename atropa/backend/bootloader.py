"""
atropa.backend.bootloader
------------------------------
Detects and manages GRUB or systemd-boot, the two common Arch bootloaders.

systemd-boot's loader.conf lives on the EFI system partition, which Arch
mounts at /efi, /boot or /boot/efi - so it's located through bootctl
rather than assumed to be under /boot. The ESP is often mounted root-only
(umask=0077, what systemd's own automount uses and bootctl's
"world accessible" warning asks for); then its files are read with one
privileged call instead of failing.
"""

from __future__ import annotations

import re
import shutil
from dataclasses import dataclass, field
from pathlib import Path

from .privilege import CommandResult, backup_file, run_privileged, run_unprivileged

GRUB_DEFAULT_PATH = Path("/etc/default/grub")
# Where bootctl looks for the ESP when it can't be asked, in its own order.
ESP_CANDIDATES = (Path("/efi"), Path("/boot"), Path("/boot/efi"))
# The Boot Loader Interface's EFI variables. LoaderInfo names the loader
# that started this boot: systemd-boot sets it, and so does GRUB since 2.12
# (its bli module), so only what it says tells them apart.
# LoaderConfigTimeout holds a timeout chosen in systemd-boot's menu (or
# with bootctl set-timeout), which overrides loader.conf's.
_SD_BOOT_VENDOR = "4a67b082-0a4c-41cf-b6c7-440b29bb8c4f"
EFIVARS_DIR = Path("/sys/firmware/efi/efivars")


@dataclass
class BootEntry:
    title: str
    identifier: str
    is_default: bool = False


@dataclass
class BootloaderInfo:
    kind: str  # "grub", "systemd-boot", "unknown"
    entries: list[BootEntry] = field(default_factory=list)
    default_timeout: str = ""


def _exists(path: Path) -> bool:
    """Path.exists() without the PermissionError Python 3.11-3.13 raise for an unreadable parent."""
    try:
        return path.exists()
    except OSError:
        return False


def _efivar_exists(name: str) -> bool:
    return _exists(EFIVARS_DIR / f"{name}-{_SD_BOOT_VENDOR}")


def _loader_info() -> str:
    """
    What the loader that started this boot calls itself - "systemd-boot
    257.5-2-arch", "GRUB 2.12" - from the LoaderInfo EFI variable. "" when
    it isn't set (a BIOS boot, a loader that doesn't say) or can't be read.
    """
    try:
        raw = (EFIVARS_DIR / f"LoaderInfo-{_SD_BOOT_VENDOR}").read_bytes()
    except OSError:
        return ""
    # efivarfs puts 4 bytes of attributes before the value, a UTF-16 string here.
    return raw[4:].decode("utf-16-le", errors="replace").strip("\x00 \t\r\n")


def _bootctl_path(flag: str) -> Path | None:
    if not shutil.which("bootctl"):
        return None
    result = run_unprivileged(["bootctl", flag])
    path = result.stdout.strip()
    return Path(path) if result.ok and path else None


def esp_path() -> Path | None:
    """The ESP's mount point: bootctl's answer, else the first candidate that has loader/."""
    esp = _bootctl_path("--print-esp-path")
    if esp is not None:
        return esp
    return next((c for c in ESP_CANDIDATES if _exists(c / "loader")), None)


def _loader_dirs() -> list[Path]:
    """loader/ on the ESP, plus on XBOOTLDR ($BOOT) if there's a separate one - entries can be on either."""
    dirs = []
    for root in (esp_path(), _bootctl_path("--print-boot-path")):
        if root is not None and root / "loader" not in dirs:
            dirs.append(root / "loader")
    return dirs


def _read_loader_dir(loader_dir: Path) -> dict[str, str]:
    """{path: text} for loader.conf and entries/*.conf under loader_dir."""
    try:
        files = {}
        conf = loader_dir / "loader.conf"
        if conf.is_file():
            files[str(conf)] = conf.read_text(encoding="utf-8", errors="replace")
        entries = loader_dir / "entries"
        if entries.is_dir():
            for entry in sorted(entries.glob("*.conf")):
                files[str(entry)] = entry.read_text(encoding="utf-8", errors="replace")
        return files
    except PermissionError:
        pass
    # Root-only ESP: one grep prints every line of every .conf, prefixed with its path.
    result = run_privileged(["grep", "-rH", "--include=*.conf", "", str(loader_dir)])
    if result.returncode not in (0, 1):  # 1: nothing matched, i.e. no non-empty .conf files
        raise RuntimeError(f"Couldn't read {loader_dir}: {result.stderr.strip() or f'exit code {result.returncode}'}")
    lines: dict[str, list[str]] = {}
    for line in result.stdout.splitlines():
        path, sep, text = line.partition(".conf:")
        if sep:
            lines.setdefault(path + ".conf", []).append(text)
    return {path: "\n".join(text) + "\n" for path, text in sorted(lines.items())}


def _grub_manageable() -> bool:
    return _exists(GRUB_DEFAULT_PATH) and shutil.which("grub-mkconfig") is not None


def _systemd_boot_on_disk() -> bool:
    """loader.conf or an entries directory under loader/, on the ESP or XBOOTLDR - what `bootctl install` leaves."""
    return any(_exists(d / "loader.conf") or _exists(d / "entries") for d in _loader_dirs())


def detect() -> str:
    """
    "systemd-boot", "grub" or "unknown".

    The loader that started this boot names itself in LoaderInfo, and that
    settles it - by name: GRUB sets the variable too, so its existing
    doesn't mean systemd-boot. When no loader says (a BIOS boot, a GRUB
    before 2.12), go by what's installed, GRUB first, since systemd-boot
    would have said. An ESP by itself decides nothing: every UEFI machine
    has one, the ones that boot GRUB included - this used to report all of
    those as systemd-boot.
    """
    loader = _loader_info().lower()
    has_bootctl = shutil.which("bootctl") is not None
    if loader.startswith("systemd-boot"):
        return "systemd-boot" if has_bootctl else "unknown"
    if loader.startswith("grub"):
        return "grub" if _grub_manageable() else "unknown"
    if _grub_manageable():
        return "grub"
    if has_bootctl and _systemd_boot_on_disk():
        return "systemd-boot"
    return "unknown"


def get_info() -> BootloaderInfo:
    kind = detect()
    if kind == "systemd-boot":
        return _systemd_boot_info()
    if kind == "grub":
        return _grub_info()
    return BootloaderInfo(kind="unknown")


def _timeout_from(loader_conf_text: str) -> str:
    timeout = ""
    for line in loader_conf_text.splitlines():
        parts = line.split()
        if len(parts) > 1 and parts[0] == "timeout":
            timeout = parts[1]  # systemd-boot applies every line in order: the last one wins
    return timeout


def _systemd_boot_info() -> BootloaderInfo:
    files: dict[str, str] = {}
    for loader_dir in _loader_dirs():
        files.update(_read_loader_dir(loader_dir))

    timeout = ""
    entries = []
    for path, text in files.items():
        if Path(path).name == "loader.conf" and Path(path).parent.name == "loader":
            timeout = timeout or _timeout_from(text)
            continue
        title = Path(path).stem
        for line in text.splitlines():
            if line.startswith("title"):
                title = line.split(maxsplit=1)[1] if len(line.split()) > 1 else title
        entries.append(BootEntry(title=title, identifier=Path(path).name))

    return BootloaderInfo(kind="systemd-boot", entries=entries, default_timeout=timeout)


def _grub_info() -> BootloaderInfo:
    timeout = ""
    if _exists(GRUB_DEFAULT_PATH):
        for line in GRUB_DEFAULT_PATH.read_text().splitlines():
            if line.startswith("GRUB_TIMEOUT="):
                timeout = line.split("=", 1)[1].strip()

    entries = []
    result = run_unprivileged(["grep", "-E", "^menuentry", "/boot/grub/grub.cfg"])
    for line in result.stdout.strip().splitlines():
        # menuentry 'Arch Linux' --class arch ...
        if "'" in line:
            title = line.split("'")[1]
            entries.append(BootEntry(title=title, identifier=title))

    return BootloaderInfo(kind="grub", entries=entries, default_timeout=timeout)


def set_timeout(seconds: int) -> CommandResult:
    kind = detect()
    if kind == "grub":
        return _set_grub_timeout(seconds)
    if kind == "systemd-boot":
        return _set_systemd_boot_timeout(seconds)
    raise RuntimeError("No supported bootloader detected")


def _with_setting(text: str, key_re: str, new_line: str) -> str:
    """
    Config text with every active line matching key_re replaced by
    new_line; else the first commented-out one restored; else new_line
    added. The old s/^key.*/ edits changed nothing when the line was
    commented out - which is how loader.conf's stock example ships it.
    """
    lines = text.splitlines()
    active = [i for i, line in enumerate(lines) if re.match(rf"^\s*{key_re}", line)]
    commented = [i for i, line in enumerate(lines) if re.match(rf"^\s*#\s*{key_re}", line)]
    for index in active or commented[:1]:
        lines[index] = new_line
    if not active and not commented:
        lines.append(new_line)
    return "\n".join(lines) + "\n"


def _with_timeout(loader_conf_text: str, seconds: int) -> str:
    # Every active line: systemd-boot applies them in order, so the last one counts.
    return _with_setting(loader_conf_text, r"timeout(\s|$)", f"timeout {seconds}")


def _set_grub_timeout(seconds: int) -> CommandResult:
    """
    Edit /etc/default/grub, then regenerate grub.cfg. If regeneration
    fails, the previous /etc/default/grub goes back - a bad edit here can
    otherwise leave the boot menu unable to regenerate at all.
    """
    original = GRUB_DEFAULT_PATH.read_text(encoding="utf-8")
    backup_file(str(GRUB_DEFAULT_PATH))
    result = run_privileged(
        ["tee", str(GRUB_DEFAULT_PATH)],
        input_text=_with_setting(original, r"GRUB_TIMEOUT=", f"GRUB_TIMEOUT={seconds}"),
    )
    if result.ok:
        result = regenerate_config()
        if not result.ok:
            restore = run_privileged(["tee", str(GRUB_DEFAULT_PATH)], input_text=original)
            note = "restored the previous" if restore.ok else "and restoring the previous one ALSO failed -"
            detail = f"{result.stderr.strip()} ({note} {GRUB_DEFAULT_PATH})"
            result = CommandResult(result.returncode, result.stdout, detail)
    return result


def _set_systemd_boot_timeout(seconds: int) -> CommandResult:
    esp = esp_path()
    if esp is None:
        raise RuntimeError("Couldn't find the EFI system partition (bootctl --print-esp-path found nothing)")
    loader_conf = esp / "loader" / "loader.conf"
    current = _read_loader_dir(esp / "loader").get(str(loader_conf), "")

    backup_file(str(loader_conf))
    result = run_privileged(["tee", str(loader_conf)], input_text=_with_timeout(current, seconds))
    if result.ok and _efivar_exists("LoaderConfigTimeout"):
        # A timeout picked in the boot menu is stored in an EFI variable that
        # takes precedence over loader.conf - drop it, or the edit above
        # changes nothing at the next boot.
        result = run_privileged(["bootctl", "set-timeout", ""])
    return result


def regenerate_config() -> CommandResult:
    kind = detect()
    if kind == "grub":
        return run_privileged(["grub-mkconfig", "-o", "/boot/grub/grub.cfg"])
    if kind == "systemd-boot":
        return run_privileged(["bootctl", "update"])
    raise RuntimeError("No supported bootloader detected")


def reinstall() -> CommandResult:
    """Reinstall the bootloader to the EFI/MBR (for recovery scenarios)."""
    kind = detect()
    if kind == "systemd-boot":
        return run_privileged(["bootctl", "install"])
    raise RuntimeError(
        "Automatic GRUB reinstall needs your boot disk / EFI target; "
        "use a terminal for 'grub-install' to avoid picking the wrong disk."
    )
