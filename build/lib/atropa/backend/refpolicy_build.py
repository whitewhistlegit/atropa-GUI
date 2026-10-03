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
2. install() - `make install`, PRIVILEGED (writes under
   /etc/selinux/NAME and /usr/share/selinux/NAME). Still does NOT make
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

import shutil
from collections.abc import Callable
from pathlib import Path

from .privilege import CommandResult, backup_file, run_privileged, run_privileged_streaming, run_unprivileged_streaming
from .selinux import SELINUX_CONFIG, relabel_filesystem


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
    `make install` - compiles (if not already done), packages, and
    installs the base module and configured loadable modules under
    /etc/selinux/NAME and /usr/share/selinux/NAME. Does NOT touch
    /etc/selinux/config or load anything into the running kernel policy -
    see activate() for that.
    """
    if not _make_available():
        raise RuntimeError("'make' isn't installed. Install it with: pacman -S make")
    _require_source_dir(source_dir)
    return run_privileged_streaming(["make", "-C", source_dir, "install"], on_line, timeout=3600)


def activate(policy_name: str, default_login_seuser: str = "unconfined_u") -> list[CommandResult]:
    """
    Makes an already-installed policy (via install() above) the one the
    system actually boots into. Returns one CommandResult per step so a
    caller can report exactly which step failed rather than one opaque
    pass/fail for the whole sequence - unlike build()/install(), this
    genuinely has multiple independently-meaningful steps.

    Deliberately does NOT reboot and does NOT touch any kernel boot
    parameter - see this module's docstring. The filesystem relabel this
    schedules only takes effect after a reboot too; both are the human's
    call to actually make, on their own schedule.
    """
    results: list[CommandResult] = []

    backup_file(str(SELINUX_CONFIG))
    pattern = r"^SELINUXTYPE=.*$"
    results.append(
        run_privileged(["sed", "-i", "-E", f"s/{pattern}/SELINUXTYPE={policy_name}/", str(SELINUX_CONFIG)])
    )
    if not results[-1].ok:
        return results

    # Try adding the __default__ login mapping first; if one already
    # exists (common - most policies ship a default mapping of some kind),
    # `semanage login -a` fails with "already defined" and -m (modify) is
    # the correct follow-up rather than treating that as a hard failure.
    add_result = run_privileged(["semanage", "login", "-a", "-s", default_login_seuser, "__default__"])
    if add_result.ok:
        results.append(add_result)
    else:
        results.append(run_privileged(["semanage", "login", "-m", "-s", default_login_seuser, "__default__"]))
    if not results[-1].ok:
        return results

    results.append(relabel_filesystem())
    return results
