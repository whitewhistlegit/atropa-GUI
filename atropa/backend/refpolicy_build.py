"""
atropa.backend.refpolicy_build
--------------------------------
Builds and installs a custom SELinux Reference Policy source tree - e.g.
a user's own fork that fixes Arch-specific paths/contexts upstream
refpolicy doesn't ship out of the box (config already tuned in the
source tree's own build.conf: TYPE, NAME, MONOLITHIC, DISTRO, etc. -
this module reads them, never overrides them).

Every step here maps directly onto refpolicy's own documented Make
targets (doc/BUILD_INSTALL.md in the source tree itself) - nothing here
reimplements or second-guesses the build system, it only sequences and
streams its output. Only the *modular* target set is used
(conf/all/install), matching MONOLITHIC=n; a MONOLITHIC=y source tree
uses a different target set (policy/install/relabel) this module doesn't
attempt to detect or handle.

Three genuinely different risk tiers, kept as three separate functions
rather than one "build my policy" button:

1. build() - `make conf all`, entirely UNPRIVILEGED, compiles everything
   into the source tree's own build artifacts. Zero effect on the running
   system - nothing outside the source tree is touched at all. Can take
   several minutes for a full modular build, hence streamed.
2. install() - `make install load`, PRIVILEGED. In a modular build
   `install` only copies the module packages to /usr/share/selinux/NAME
   and the context files to /etc/selinux/NAME - no compiled policy, no
   policy store; `load` (semodule -s NAME) builds those, so without it
   there was nothing for Activate to boot into. Still does NOT make
   this the *active* policy - SELINUXTYPE in /etc/selinux/config is left
   alone, so the system keeps running on whatever policy it was using
   before this step. Low risk: worst case, files exist on disk that
   nothing is using yet.
3. activate() - the consequential one. Sets SELINUXTYPE in
   /etc/selinux/config (backed up first, same pattern selinux.set_mode()
   already uses for SELINUX=) to actually make this the policy the
   system boots into; ensures the __default__ login maps to unconfined_u
   (a targeted-type policy's whole design assumes interactive users land
   in unconfined_t - a working policy build with a wrong or missing
   login mapping would still put a real login into the wrong, likely far
   more restrictive, domain); and schedules a full filesystem relabel
   (reuses selinux.relabel_filesystem() rather than duplicating it - a
   different named policy almost always means different file contexts).
   Explicitly does NOT reboot, and explicitly does NOT touch any kernel
   boot parameter - switching the active policy only fully takes effect
   after a reboot, and Atropa never triggers one itself or edits
   bootloader/kernel-cmdline config for any feature; the human is the
   one who has to actually pull that trigger, on their own schedule,
   same reasoning that's kept kernel-param automation and PAM
   auto-wiring off the table everywhere else in this project.
"""

from __future__ import annotations

import os
import re
import shutil
from collections.abc import Callable
from pathlib import Path

from .privilege import CommandResult, backup_file, run_privileged, run_privileged_streaming, run_unprivileged_streaming
from .selinux import SELINUX_CONFIG, relabel_filesystem

SELINUX_ROOT = Path("/etc/selinux")
# build.conf's NAME becomes a directory name under /etc/selinux and the
# SELINUXTYPE value - nothing else belongs in it.
_POLICY_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")


def _make_available() -> bool:
    return shutil.which("make") is not None


def _require_source_dir(source_dir: str) -> None:
    if not Path(source_dir).is_dir():
        raise RuntimeError(f"{source_dir} isn't a directory")
    if not (Path(source_dir) / "Makefile").exists():
        raise RuntimeError(f"{source_dir} doesn't look like a refpolicy source tree (no Makefile)")


def build(source_dir: str, on_line: Callable[[str], None]) -> CommandResult:
    """
    `make conf all` - generates modules.conf/booleans.conf/policy.xml
    (safe to re-run; refpolicy's own docs say existing settings are
    preserved) and compiles the base module plus every module the source
    tree's build.conf/modules.conf enables. Entirely unprivileged.
    """
    if not _make_available():
        raise RuntimeError("'make' isn't installed. Install it with: pacman -S make")
    _require_source_dir(source_dir)
    return run_unprivileged_streaming(["make", "-C", source_dir, "conf", "all"], on_line, timeout=3600)


def install(source_dir: str, on_line: Callable[[str], None]) -> CommandResult:
    """
    `make install load` - compiles (if not already done), packages and
    installs the base module and configured loadable modules
    (/usr/share/selinux/NAME, /etc/selinux/NAME), then has semodule build
    them into NAME's own policy store, which is what writes the compiled
    policy (/etc/selinux/NAME/policy/policy.NN) a boot into NAME loads.
    Does NOT touch /etc/selinux/config, so the running system stays on
    its current policy - see activate() for the switch.
    """
    if not _make_available():
        raise RuntimeError("'make' isn't installed. Install it with: pacman -S make")
    _require_source_dir(source_dir)
    result = run_privileged_streaming(["make", "-C", source_dir, "install", "load"], on_line, timeout=3600)
    _return_root_owned_files(source_dir, on_line)
    return result


def _return_root_owned_files(source_dir: str, on_line: Callable[[str], None]) -> None:
    """
    make ran as root, so whatever it created inside the source tree is
    root-owned now - and the next unprivileged Build fails on those files.
    Hands back only files owned by root:root. -R doesn't follow symlinks
    (and -h changes a link itself, never its target), so nothing outside
    the tree is touched.
    """
    uid, gid = os.getuid(), os.getgid()
    if uid == 0:
        return  # Atropa itself runs as root: the files are already "yours"
    result = run_privileged(["chown", "-R", "-h", "--from=0:0", f"{uid}:{gid}", "--", source_dir])
    if not result.ok:
        on_line(
            f"Couldn't hand the files make created in {source_dir} back to you "
            f"({result.stderr.strip() or f'exit code {result.returncode}'}) - a later Build may fail on them."
        )


def _installed_binary_policy(policy_name: str) -> Path | None:
    """The compiled policy (/etc/selinux/NAME/policy/policy.NN) a boot into NAME loads, if present."""
    policy_dir = SELINUX_ROOT / policy_name / "policy"
    try:
        return next((p for p in sorted(policy_dir.glob("policy.*")) if p.suffix[1:].isdigit()), None)
    except OSError:
        return None


def _with_selinuxtype(config_text: str, policy_name: str) -> str:
    """config_text with SELINUXTYPE set: the first active line replaced, or one added."""
    lines = config_text.splitlines()
    for index, line in enumerate(lines):
        if re.match(r"^\s*SELINUXTYPE\s*=", line):
            lines[index] = f"SELINUXTYPE={policy_name}"
            break
    else:
        lines.append(f"SELINUXTYPE={policy_name}")
    return "\n".join(lines) + "\n"


def activate(policy_name: str, default_login_seuser: str = "unconfined_u") -> list[CommandResult]:
    """
    Makes an already-installed policy (via install() above) the one the
    system actually boots into. Returns one CommandResult per step so a
    caller can report exactly which step failed rather than one opaque
    pass/fail for the whole sequence - unlike build()/install(), this
    genuinely has multiple independently-meaningful steps.

    Refuses up front unless NAME is a plain name and a compiled policy for
    it exists: SELINUXTYPE pointing at a missing policy leaves an
    enforcing system unable to boot. The login mapping goes into the new
    policy's own store (-S) before /etc/selinux/config changes, so a
    failure there changes nothing; if scheduling the relabel fails after
    the switch, the previous config is put back, since booting into a
    different policy without relabelling can fail too.

    Deliberately does NOT reboot and does NOT touch any kernel boot
    parameter - see this module's docstring. The filesystem relabel this
    schedules only takes effect after a reboot too; both are the human's
    call to actually make, on their own schedule.
    """
    if not _POLICY_NAME_RE.match(policy_name):
        raise ValueError(f"{policy_name!r} isn't a policy name - letters, digits, '.', '_' and '-' only")
    if _installed_binary_policy(policy_name) is None:
        raise RuntimeError(
            f"No compiled policy under {SELINUX_ROOT / policy_name / 'policy'} - check the name matches "
            "build.conf's NAME and that Install finished."
        )
    original_config = SELINUX_CONFIG.read_text(encoding="utf-8")

    results: list[CommandResult] = []

    # Try adding the __default__ login mapping first; if one already
    # exists (common - most policies ship a default mapping of some kind),
    # `semanage login -a` fails with "already defined" and -m (modify) is
    # the correct follow-up rather than treating that as a hard failure.
    # -N: don't reload the running policy - this store isn't the active one.
    store = ["-S", policy_name, "-N"]
    add_result = run_privileged(["semanage", "login", *store, "-a", "-s", default_login_seuser, "__default__"])
    if add_result.ok:
        results.append(add_result)
    else:
        results.append(
            run_privileged(["semanage", "login", *store, "-m", "-s", default_login_seuser, "__default__"])
        )
    if not results[-1].ok:
        return results

    backup_file(str(SELINUX_CONFIG))
    new_config = _with_selinuxtype(original_config, policy_name)
    results.append(run_privileged(["tee", str(SELINUX_CONFIG)], input_text=new_config))
    if not results[-1].ok:
        return results

    relabel_result = relabel_filesystem()
    results.append(relabel_result)
    if not relabel_result.ok:
        restore = run_privileged(["tee", str(SELINUX_CONFIG)], input_text=original_config)
        outcome = (
            "put the previous /etc/selinux/config back, so the next boot still uses the old policy"
            if restore.ok
            else f"restoring the previous /etc/selinux/config ALSO failed ({restore.stderr.strip() or 'unknown error'}) "
            f"- set SELINUXTYPE back by hand before rebooting"
        )
        results[-1] = CommandResult(
            relabel_result.returncode,
            relabel_result.stdout,
            f"Couldn't schedule the relabel ({relabel_result.stderr.strip() or 'unknown error'}); {outcome}.",
        )
    return results
