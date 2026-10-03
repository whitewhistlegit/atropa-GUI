"""
atropa.backend.selinux
---------------------------
Wraps the standard SELinux userspace tools (sestatus, getenforce,
setenforce, setsebool, getsebool, restorecon). Arch has no official
SELinux policy - people running it are typically on an AUR policy package
(e.g. refpolicy-arch), so this module only assumes the tools exist; it
doesn't assume any particular policy or package name.
"""

from __future__ import annotations

import json
import re
import shutil
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from .privilege import CommandResult, backup_file, run_privileged, run_privileged_streaming, run_unprivileged

SELINUX_CONFIG = Path("/etc/selinux/config")

# Persistent home for compiled review artifacts (.te/.mod/.pp) and Setup
# Mode state - kept around deliberately, as a paper trail of what was
# proposed and when, rather than scrubbed after use.
#   modules/  - compiled but not yet (or no longer) installed: still a draft
#   approved/ - has been installed at least once via this app; files move
#               here automatically the moment `semodule -i` succeeds, so a
#               glance at the folder tells you what's a draft vs what your
#               system has actually run with.
REVIEW_BASE_DIR = Path.home() / ".local" / "share" / "atropa" / "selinux-review"
REVIEW_MODULES_DIR = REVIEW_BASE_DIR / "modules"
APPROVED_MODULES_DIR = REVIEW_BASE_DIR / "approved"
SETUP_MODE_STATE_FILE = REVIEW_BASE_DIR / "setup_mode_state.json"
LAST_REVIEW_FILE = REVIEW_BASE_DIR / "last_review.json"


@dataclass
class SelinuxStatus:
    available: bool
    mode: str = "unknown"
    # Real sestatus output is lowercase ("enforcing" | "permissive" | "disabled")
    # when SELinux is available - "Disabled" (Title-case) above is a distinct
    # internal sentinel get_status() returns when SELinux isn't available at
    # all (no /sys/fs/selinux, no sestatus), never something parsed from real
    # sestatus text, so it doesn't need to match that casing. Any comparison
    # against a *parsed* mode value must be case-insensitive or match
    # lowercase - a Title-case comparison against real sestatus output was a
    # real, confirmed bug in two places (the SELinux page's mode toggle, and
    # hardening.py's Compliance Report SELinux check) before this note was
    # written; both compare `.lower()` now.
    policy: str = ""
    mls: str = ""
    deny_unknown: str = ""
    raw: str = ""


@dataclass
class SelinuxBoolean:
    name: str
    active: bool
    pending: bool  # differs from active if a non-persistent change is queued


def is_available() -> bool:
    return Path("/sys/fs/selinux").exists() or shutil.which("sestatus") is not None


def get_status() -> SelinuxStatus:
    if not is_available():
        return SelinuxStatus(available=False, mode="Disabled")

    result = run_unprivileged(["sestatus"])
    text = result.stdout

    def field_value(label: str) -> str:
        m = re.search(rf"{re.escape(label)}:\s*(.+)", text)
        return m.group(1).strip() if m else ""

    return SelinuxStatus(
        available=True,
        mode=field_value("Current mode") or "unknown",
        policy=field_value("Loaded policy name") or field_value("Policy from config file"),
        mls=field_value("Policy MLS status"),
        deny_unknown=field_value("Policy deny_unknown status"),
        raw=text.strip(),
    )


def set_mode(enforcing: bool, persistent: bool = True) -> CommandResult:
    """
    Runtime switch via setenforce (immediate, lost on reboot), optionally
    also updated in /etc/selinux/config so it survives a reboot too.
    """
    result = run_privileged(["setenforce", "1" if enforcing else "0"])
    if result.ok and persistent and SELINUX_CONFIG.exists():
        backup_file(str(SELINUX_CONFIG))
        value = "enforcing" if enforcing else "permissive"
        pattern = r"^SELINUX=.*$"
        result = run_privileged(["sed", "-i", "-E", f"s/{pattern}/SELINUX={value}/", str(SELINUX_CONFIG)])
    return result


def list_booleans(filter_text: str = "") -> list[SelinuxBoolean]:
    if not is_available() or not shutil.which("getsebool"):
        return []
    result = run_unprivileged(["getsebool", "-a"])
    booleans = []
    for line in result.stdout.strip().splitlines():
        # format: "name --> on" or "name --> on, pending: off"
        m = re.match(r"^(\S+)\s*-->\s*(\w+)", line)
        if not m:
            continue
        name, value = m.group(1), m.group(2)
        if filter_text and filter_text.lower() not in name.lower():
            continue
        booleans.append(SelinuxBoolean(name=name, active=(value == "on"), pending=(value == "on")))
    return booleans


def set_boolean(name: str, value: bool, persistent: bool = True) -> CommandResult:
    argv = ["setsebool"]
    if persistent:
        argv.append("-P")
    argv += [name, "on" if value else "off"]
    return run_privileged(argv)


def restorecon(path: str, recursive: bool = True) -> CommandResult:
    if not path:
        raise ValueError("Path is required")
    flag = "-Rv" if recursive else "-v"
    return run_privileged(["restorecon", flag, path])


def restorecon_streaming(path: str, recursive: bool, on_line) -> CommandResult:
    """
    Same as restorecon(), but streams restorecon's own per-file output to
    on_line as it runs. A recursive relabel over a large directory (or `/`)
    is exactly the kind of long, silent-looking operation a live progress
    log is meant for.
    """
    if not path:
        raise ValueError("Path is required")
    flag = "-Rv" if recursive else "-v"
    return run_privileged_streaming(["restorecon", flag, path], on_line)


def relabel_filesystem() -> CommandResult:
    """
    Schedules a full filesystem relabel on next boot (touches /.autorelabel).
    Useful after switching SELinux on for the first time.
    """
    return run_privileged(["touch", "/.autorelabel"])


# ---------------------------------------------------------------- Setup Mode --
#
# For someone bootstrapping a policy from scratch: set permissive, record a
# start time, do normal work for a while, then review everything that
# happened across that whole window in one pass instead of hunting through
# "recent N" denials. The timestamp is just local state (a small JSON file
# next to the review artifacts) - it doesn't change SELinux's own behavior
# beyond the initial setenforce 0, and exiting setup mode doesn't require
# ever having entered it (clear_setup_mode is harmless if it wasn't set).

def start_setup_mode() -> CommandResult:
    """Sets SELinux to permissive and records a start timestamp, so a later
    extensive review can scope to 'since I started setting this up'."""
    result = set_mode(enforcing=False, persistent=True)
    if result.ok:
        REVIEW_BASE_DIR.mkdir(parents=True, exist_ok=True)
        SETUP_MODE_STATE_FILE.write_text(json.dumps({"started_at": datetime.now(timezone.utc).isoformat()}))
    return result


def get_setup_mode_started_at() -> str | None:
    """ISO timestamp Setup Mode was started at, or None if not currently in it."""
    if not SETUP_MODE_STATE_FILE.exists():
        return None
    try:
        return json.loads(SETUP_MODE_STATE_FILE.read_text()).get("started_at")
    except (OSError, json.JSONDecodeError):
        return None


def is_in_setup_mode() -> bool:
    return get_setup_mode_started_at() is not None


def clear_setup_mode() -> None:
    """Exits Setup Mode (just clears the local timestamp - doesn't touch
    the current enforcing/permissive mode, since that's a deliberate
    separate decision made via set_mode())."""
    SETUP_MODE_STATE_FILE.unlink(missing_ok=True)




# ---------------------------------------------------------- AVC denials --

_MODULE_NAME_RE = re.compile(r"^[a-zA-Z0-9_-]{1,64}$")


def _validate_module_name(name: str) -> None:
    if not _MODULE_NAME_RE.match(name):
        raise ValueError("Module name must be 1-64 characters: letters, numbers, '_' or '-' only")


def _is_relevant_selinux_line(line: str) -> bool:
    """
    True for anything worth surfacing as a policy problem: a normal AVC
    denial, or a 'Permission/Class ... not defined in policy' message -
    the latter means the running kernel knows about a permission/class
    the compiled policy predates (e.g. newer capability bits like bpf/
    perfmon), which under a deny_unknown=deny policy gets silently
    blocked exactly like a real denial, but can't be fixed with a normal
    allow rule - the policy's class/permission definitions themselves
    need updating. See classify_denials()'s "undefined_in_policy" bucket.
    """
    lower = line.lower()
    return "denied" in lower or "not defined in policy" in lower


def list_avc_denials(limit: int = 50) -> list[str]:
    """
    Reads recent 'avc:  denied' lines (and 'not defined in policy'
    messages - see _is_relevant_selinux_line) from the kernel log via
    journalctl. Doesn't require root: these get printk'd to the kernel
    ring buffer even when auditd is also logging separately.
    """
    result = run_unprivileged(
        ["journalctl", "-k", "--no-pager", "-g", "avc:|not defined in policy", "-n", str(limit * 3), "--output=cat"]
    )
    lines = [ln.strip() for ln in result.stdout.strip().splitlines() if ln.strip() and _is_relevant_selinux_line(ln)]
    return lines[-limit:]


def list_avc_denials_from_audit_log(limit: int = 50) -> list[str]:
    """
    Fallback source via ausearch against /var/log/audit/audit.log, for
    systems where AVCs don't reach the kernel ring buffer (e.g. dmesg
    restricted or rate-limited). Requires root, so this is privileged and
    only called when the user explicitly asks for it - not on every page load.

    Only covers real AVC audit records: 'not defined in policy' messages
    are raw kernel printk lines, not audit records, so ausearch never
    returns them regardless - that gap is on the journal side only, and
    list_avc_denials()/list_all_denials() cover it there.
    """
    if not shutil.which("ausearch"):
        raise RuntimeError("ausearch isn't installed. Install it with: pacman -S audit")
    result = run_privileged(["ausearch", "-m", "avc", "-ts", "recent"])
    lines = [l.strip() for l in result.stdout.strip().splitlines() if "avc:" in l.lower() and "denied" in l.lower()]
    return lines[-limit:]


def explain_denial(raw_avc_line: str) -> str:
    """Runs audit2why on a single AVC line to explain *why* it was denied."""
    if not shutil.which("audit2why"):
        raise RuntimeError("audit2why isn't installed. Install it with: pacman -S audit")
    result = run_unprivileged(["audit2why"], input_text=raw_avc_line.strip() + "\n")
    output = (result.stdout or result.stderr).strip()
    if not output:
        raise RuntimeError("audit2why produced no output for this denial")
    return output


def generate_te(raw_avc_line: str, module_name: str) -> str:
    """Runs audit2allow on a single AVC line and returns the suggested .te module text."""
    if not shutil.which("audit2allow"):
        raise RuntimeError("audit2allow isn't installed. Install it with: pacman -S audit")
    _validate_module_name(module_name)
    result = run_unprivileged(["audit2allow", "-m", module_name], input_text=raw_avc_line.strip() + "\n")
    if not result.stdout.strip():
        raise RuntimeError(result.stderr.strip() or "audit2allow produced no output for this denial")
    return result.stdout


# --------------------------------------------------------- policy modules --

def list_semodules() -> list[str]:
    """
    Names of currently loaded (non-base) SELinux policy modules.

    Requires root - confirmed the hard way, from the user's own bare-metal
    report rather than assumed up front: run unprivileged, `semodule -l`
    can't read the real policy store and returns nothing, which the
    Load Policy page's "approved" section then read as "not loaded,
    needs reinstalling" for modules that were genuinely already active -
    only showing correctly when Atropa itself happened to be launched as
    root. Same failure shape as the ufw/firewall-cmd bug: no loud
    permission error, just quietly wrong output.
    """
    if not shutil.which("semodule"):
        return []
    result = run_privileged(["semodule", "-l"])
    names = []
    for line in result.stdout.strip().splitlines():
        line = line.strip()
        if line:
            names.append(line.split()[0])
    return names


def _compile_te(te_content: str, module_name: str, workdir: Path) -> str:
    """
    Writes, compiles, and packages a .te into <module_name>.pp under workdir.
    Deliberately does NOT use run_privileged: checkmodule/semodule_package
    only read/write local files, they don't touch the live policy, so
    running them as root would be an unnecessary privilege escalation.
    Returns the .pp path; raises RuntimeError on failure at any step.
    """
    _validate_module_name(module_name)
    for tool in ("checkmodule", "semodule_package"):
        if not shutil.which(tool):
            raise RuntimeError(f"'{tool}' isn't installed. Install it with: pacman -S policycoreutils")

    workdir.mkdir(parents=True, exist_ok=True)
    te_path = workdir / f"{module_name}.te"
    mod_path = workdir / f"{module_name}.mod"
    pp_path = workdir / f"{module_name}.pp"

    te_path.write_text(te_content, encoding="utf-8")

    result = run_unprivileged(["checkmodule", "-M", "-m", "-o", str(mod_path), str(te_path)])
    if not result.ok:
        raise RuntimeError(result.stderr.strip() or "checkmodule failed")

    result = run_unprivileged(["semodule_package", "-o", str(pp_path), "-m", str(mod_path)])
    if not result.ok:
        raise RuntimeError(result.stderr.strip() or "semodule_package failed")

    return str(pp_path)


def _move_to_approved(module_name: str, source_dir: Path) -> None:
    """Moves a module's .te/.mod/.pp trio from source_dir into APPROVED_MODULES_DIR, if present there."""
    APPROVED_MODULES_DIR.mkdir(parents=True, exist_ok=True)
    for ext in ("te", "mod", "pp"):
        src = source_dir / f"{module_name}.{ext}"
        if src.exists():
            src.replace(APPROVED_MODULES_DIR / f"{module_name}.{ext}")


def compile_and_load_te(te_content: str, module_name: str) -> CommandResult:
    """
    Compiles arbitrary .te policy text (from audit2allow, hand-written, or
    loaded from disk) and installs it. Only the final semodule -i step
    (which modifies the live policy) is privileged. On success, the
    compiled files move from modules/ to approved/.
    """
    if not shutil.which("semodule"):
        raise RuntimeError("'semodule' isn't installed. Install it with: pacman -S policycoreutils")
    pp_path = _compile_te(te_content, module_name, REVIEW_MODULES_DIR)
    result = run_privileged(["semodule", "-i", pp_path])
    if result.ok:
        _move_to_approved(module_name, REVIEW_MODULES_DIR)
    return result


# Matches audit2allow's own `module <name> <version>;` declaration line -
# the addon/imported .te files this is meant for are typically audit2allow
# output themselves (hand-kept from an earlier review, or from a personal
# policy collection), so the module's real name lives inside the file, not
# just in whatever the file happened to get saved as.
_MODULE_DECL_RE = re.compile(r"^\s*module\s+([A-Za-z0-9_-]+)\s+[\d.]+\s*;", re.MULTILINE)


def _module_name_from_te(te_content: str, fallback_stem: str) -> str:
    match = _MODULE_DECL_RE.search(te_content)
    return match.group(1) if match else fallback_stem


@dataclass
class ImportedTeFile:
    source_path: str
    module_name: str
    pp_path: str | None  # None if compilation failed
    error: str | None


def import_te_files(paths: list[str]) -> list[ImportedTeFile]:
    """
    Compiles a batch of already-written .te files - e.g. importing a
    personal or third-party policy "addon" collection - into
    REVIEW_MODULES_DIR, the same pending-review bucket build_policy_review()
    uses, rather than installing any of them directly.

    Deliberately more cautious than the single-file "paste .te and Compile
    & Load" flow on the Load Policy page: that one installs immediately
    after a single confirm, on the reasonable assumption that a single
    pasted/loaded file has actually been read in the editor right there
    first. A *batch* import of files that may never have been individually
    opened doesn't get that same assumption - each one lands in Pending
    for its own review+install through the existing flow, exactly like an
    auto-generated denial-review batch would. Nothing here is privileged
    or touches the running policy - only compilation (checkmodule +
    semodule_package), same division of labor as everywhere else in this
    module.

    One bad file (unreadable, unparseable/invalid module name, fails to
    compile) is recorded and skipped rather than aborting the whole batch
    - a single typo'd file, or one whose module name collides with
    something already pending, shouldn't block importing the rest.
    """
    if not shutil.which("checkmodule") or not shutil.which("semodule_package"):
        raise RuntimeError(
            "'checkmodule'/'semodule_package' aren't installed. Install them with: pacman -S policycoreutils"
        )

    results: list[ImportedTeFile] = []
    for path_str in paths:
        path = Path(path_str)
        try:
            te_content = path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            results.append(ImportedTeFile(path_str, path.stem, None, f"Couldn't read file: {exc}"))
            continue

        module_name = _module_name_from_te(te_content, path.stem)
        try:
            _validate_module_name(module_name)
            pp_path = _compile_te(te_content, module_name, REVIEW_MODULES_DIR)
            results.append(ImportedTeFile(path_str, module_name, pp_path, None))
        except (ValueError, RuntimeError) as exc:
            results.append(ImportedTeFile(path_str, module_name, None, str(exc)))
    return results


def install_pp_file(pp_path: str) -> CommandResult:
    """
    Installs an already-compiled .pp (from a review batch or elsewhere) via
    semodule -i. If it was sitting in the pending modules/ directory, its
    files move to approved/ on success.
    """
    if not shutil.which("semodule"):
        raise RuntimeError("'semodule' isn't installed. Install it with: pacman -S policycoreutils")
    path = Path(pp_path)
    if not path.exists():
        raise RuntimeError(f"{pp_path} no longer exists")
    result = run_privileged(["semodule", "-i", str(path)])
    if result.ok and path.parent == REVIEW_MODULES_DIR:
        _move_to_approved(path.stem, REVIEW_MODULES_DIR)
    return result


def remove_semodule(module_name: str) -> CommandResult:
    """
    Unloads a module (semodule -r). Its files stay in approved/ as history -
    list_approved_modules() reports it as inactive rather than deleting the
    record, so you can see what used to be installed and re-enable it later.
    """
    _validate_module_name(module_name)
    return run_privileged(["semodule", "-r", module_name])


def list_pending_modules() -> list[tuple[str, str]]:
    """
    Compiled .pp files sitting in the pending (modules/) directory - drafts
    that haven't been installed yet. Returns (module_name, pp_path) pairs.
    """
    if not REVIEW_MODULES_DIR.exists():
        return []
    loaded = set(list_semodules())
    return [
        (pp.stem, str(pp))
        for pp in sorted(REVIEW_MODULES_DIR.glob("*.pp"))
        if pp.stem not in loaded
    ]


def list_approved_modules() -> list[dict]:
    """
    Everything that has ever been installed via this app (approved/ dir),
    with its current live status - a module can be 'approved' (installed
    at some point) but currently inactive if it was later removed, or if
    the active policy store changed (each SELINUXTYPE has its own module
    list, so switching stores makes every previously-installed module
    show up as inactive here even though nothing was actually removed).
    """
    if not APPROVED_MODULES_DIR.exists():
        return []
    loaded = set(list_semodules())
    return [
        {"name": pp.stem, "path": str(pp), "active": pp.stem in loaded}
        for pp in sorted(APPROVED_MODULES_DIR.glob("*.pp"))
    ]


def reinstall_all_approved_modules() -> CommandResult:
    """
    Reinstalls every approved-but-currently-inactive module in a single
    `semodule -i` call covering all of them - one privileged invocation,
    one pkexec prompt, rather than one per module. Mainly useful right
    after switching SELINUXTYPE (see list_approved_modules()'s docstring),
    where a whole batch can go inactive at once for a reason that has
    nothing to do with any single module being untrustworthy.
    """
    if not shutil.which("semodule"):
        raise RuntimeError("'semodule' isn't installed. Install it with: pacman -S policycoreutils")
    inactive = [m for m in list_approved_modules() if not m["active"]]
    if not inactive:
        return CommandResult(0, "nothing to reinstall", "")
    return run_privileged(["semodule", "-i", *(m["path"] for m in inactive)])



# ------------------------------------------------- per-application review --
#
# Ported from a shell workflow: instead of reviewing one AVC line at a time,
# group denials by the program that triggered them (comm=) and generate one
# .te per program - audit2allow produces a much more sensible policy when it
# sees all of a program's related denials together rather than one at a time.

_SKIP_PROGRAMS_RE = re.compile(r"^(systemd|kernel|audit|kworker|swapper)")


@dataclass
class ProgramPolicyReview:
    program: str
    safe_name: str
    denial_count: int
    sample_denials: list[str] = field(default_factory=list)
    te_content: str = ""
    why_text: str = ""
    pp_path: str | None = None
    error: str | None = None


def _sanitize_program_name(prog: str) -> str:
    return re.sub(r"[^a-zA-Z0-9_-]", "_", prog) or "unknown"


# Distinguishes "the caller didn't pass `since` at all" from "the caller
# explicitly passed since=None" - see build_policy_review()'s docstring.
_SINCE_UNSET = object()


def build_policy_review(
    source: str = "journal", denial_limit: int = 500, sample_size: int = 5, since=_SINCE_UNSET
) -> list[ProgramPolicyReview]:
    """
    Fetches denials, groups them by program, and for each program:
    generates a .te (audit2allow), an explanation (audit2why), and compiles
    - but does not install - a .pp for review. Kernel/audit-subsystem noise
    (systemd, kworker, etc.) is skipped since it's rarely what you want a
    custom policy for and mostly reflects normal system operation.

    `since` (an ISO timestamp - typically Setup Mode's start time)
    switches the fetch from the small "recent N" window to
    list_all_denials()'s uncapped fetch scoped to that window - one batch
    covering everything since a given point, grouped by program, instead
    of hoping the last `denial_limit` lines happened to catch everything.

    The default is a **sentinel**, not `None`, and that distinction is
    load-bearing - confirmed as a real bug on bare metal, not a
    hypothetical: the plain SELinux page's ad-hoc "Per-Application Policy
    Review" button never passes `since` at all, and intentionally wants
    the small bounded window - a quick, cheap look at whatever's fresh,
    not the same uncapped fetch as a full Denial Review pass. The Denial
    Review page always passes `since` explicitly - `self._last_review.since`,
    a real timestamp if Setup Mode was used, or `None` if it wasn't - and
    in *either* case wants `list_all_denials()`'s own boot-scoped fallback
    for `since=None`, matching exactly what its own "Review" button had
    already shown, not a narrower window found nowhere else in that page's
    flow. Treating a passed `since=None` the same as an omitted `since`
    meant "Generate Policy for All New Denials" silently used a much
    narrower window than the review it was supposedly generating policy
    for, on any system not using Setup Mode - which is the common case,
    since Setup Mode is opt-in.
    """
    if since is not _SINCE_UNSET:
        lines = list_all_denials(since=since, source=("audit_log" if source == "audit_log" else "journal"))
    else:
        lines = list_avc_denials_from_audit_log(denial_limit) if source == "audit_log" else list_avc_denials(denial_limit)

    groups: dict[str, list[str]] = {}
    for line in lines:
        if _UNDEFINED_PERM_RE.search(line) or _UNDEFINED_CLASS_RE.search(line):
            # audit2allow can't do anything useful with these - they have no
            # comm=/scontext= fields, and the fix isn't a rule it could draft
            # anyway (see the "undefined_in_policy" classification instead).
            continue
        m = re.search(r'comm="([^"]+)"', line)
        prog = m.group(1) if m else "unknown"
        if _SKIP_PROGRAMS_RE.match(prog):
            continue
        groups.setdefault(prog, []).append(line)

    reviews: list[ProgramPolicyReview] = []
    for prog, denials in sorted(groups.items(), key=lambda kv: -len(kv[1])):
        safe_name = _sanitize_program_name(prog)
        joined = "\n".join(denials)
        review = ProgramPolicyReview(
            program=prog, safe_name=safe_name, denial_count=len(denials), sample_denials=denials[:sample_size]
        )

        try:
            review.te_content = generate_te(joined, safe_name)
        except Exception as exc:  # noqa: BLE001 - surfaced per-program, one bad program shouldn't abort the batch
            review.error = str(exc)
            reviews.append(review)
            continue

        try:
            review.why_text = explain_denial(joined)
        except Exception as exc:  # noqa: BLE001
            review.why_text = f"(explanation unavailable: {exc})"

        try:
            review.pp_path = _compile_te(review.te_content, safe_name, REVIEW_MODULES_DIR)
        except RuntimeError as exc:
            review.error = str(exc)

        reviews.append(review)

    return reviews


# ------------------------------------------------- extensive denial review --
#
# "All denials, not just recent" for someone bootstrapping a policy from
# scratch, plus a cross-check against whatever Atropa has already
# installed: a denial that recurs despite a matching rule already being
# loaded usually means a file-context/labeling problem (fix: restorecon),
# not a missing rule - this tells those two situations apart instead of
# reflexively drafting another allow rule every time.
#
# "All" always really means "all still retained by the log backend" -
# journald and audit.log both rotate - so this is upfront about scope
# rather than implying a literal complete history.

# SELinux context format is user:role:type, optionally followed by an
# MLS/MCS sensitivity range (:s0, :s0-s0:c0.c1023, ...) - that range is
# genuinely optional, not always present. Confirmed as a real bug on bare
# metal, not a hypothetical: a policy running without MLS/MCS (e.g. the
# user's own real audit output - scontext=user_u:user_r:pipewire_t, no
# trailing :s0 at all) has exactly three colon-separated parts, and the
# previous version of this regex required a mandatory trailing segment
# after the type, so it silently matched nothing on any such system -
# every denial showed "? → ?" instead of the real source/target types,
# while comm=/tclass=/the permission set (parsed by separate regexes)
# still worked fine, which was the tell that pointed at this regex
# specifically rather than a broader parsing failure. `[^:\s]+` (not
# `\S*?`) is what makes the trailing range genuinely optional: it can't
# consume a colon, so the type-capturing group naturally stops at the
# next colon if one exists, or at whitespace if it doesn't - no lookahead
# needed for either case.
_CONTEXT_TYPE_RE_TEMPLATE = r"{field}=[^:\s]+:[^:\s]+:([^:\s]+)"
_TCLASS_RE = re.compile(r"tclass=(\w+)")
_PERM_SET_RE = re.compile(r"\{\s*([\w\s]+?)\s*\}")
_ALLOW_RULE_RE = re.compile(r"allow\s+(\S+)\s+(\S+):(\w+)\s*\{\s*([\w\s]+?)\s*\};")

# "Permission bpf in class capability2 not defined in policy." / "Class
# mctp_socket not defined in policy." - the kernel knows about a
# permission/class the compiled policy predates (common when the kernel
# gains newer capability bits like bpf/perfmon faster than the policy is
# updated). Under a deny_unknown=deny policy these get silently blocked
# exactly like a real denial, but there's no allow rule that fixes them -
# the policy's own class/permission definitions need updating (rebuild
# with UNK_PERMS=allow, or an updated policy source). Handled as a
# distinct classification in group_denials()/classify_denials() rather
# than folded into "new", since the remedy is different.
_UNDEFINED_PERM_RE = re.compile(r"[Pp]ermission (\S+) in class (\S+) not defined in policy")
_UNDEFINED_CLASS_RE = re.compile(r"[Cc]lass (\S+) not defined in policy")


def _extract_context_type(line: str, field_name: str) -> str:
    m = re.search(_CONTEXT_TYPE_RE_TEMPLATE.format(field=field_name), line)
    return m.group(1) if m else "?"


def _extract_path(line: str) -> str | None:
    """
    `path="..."` in an AVC record is always a genuine absolute filesystem
    path when present. `name="..."` is a different, weaker field - often
    just the bare directory-entry name being looked up (e.g. `name="journal"`
    for a denial on `/var/log/journal`), not a path at all. Confirmed as a
    real bug on bare metal: this used to fall back to `name=` unconditionally,
    which fed a bare filename straight into `restorecon` as if it were a
    real path - restorecon then resolved it relative to whatever the
    privileged process's own working directory happened to be (`/root` in
    the report), producing either a loud "No such file or directory" (the
    lucky outcome) or, worse, a *successful* relabel of some unrelated file
    that happened to share that same bare name in the wrong directory - a
    silent-wrong-target risk, not just a failure. Only treating an
    already-absolute `name=` value as usable, and returning None otherwise
    (same as when no path-like field exists at all), means "Try restorecon"
    only ever appears when there's a real path behind it.
    """
    m = re.search(r'path="([^"]+)"', line)
    if m:
        return m.group(1)
    m = re.search(r'name="([^"]+)"', line)
    if m and m.group(1).startswith("/"):
        return m.group(1)
    return None


def _to_journalctl_since(iso_str: str) -> str:
    dt = datetime.fromisoformat(iso_str)
    return dt.strftime("%Y-%m-%d %H:%M:%S")


def _to_ausearch_since(iso_str: str) -> str:
    dt = datetime.fromisoformat(iso_str)
    return dt.strftime("%m/%d/%Y %H:%M:%S")


def list_all_denials(since: str | None = None, source: str = "both") -> list[str]:
    """
    Fetches every AVC denial (and 'not defined in policy' message - see
    _is_relevant_selinux_line) still available on this machine - the
    kernel log, the audit log, or both. 'since' is an ISO timestamp
    (typically Setup Mode's start time) translated into each tool's own
    --since/-ts format. Without `since`, this is still bounded by what
    journald/auditd have actually retained, not literal all-time history.
    """
    lines: list[str] = []

    if source in ("journal", "both"):
        argv = ["journalctl", "-k", "--no-pager", "-g", "avc:|not defined in policy", "--output=cat"]
        if since:
            argv += ["--since", _to_journalctl_since(since)]
        result = run_unprivileged(argv)
        lines += [ln.strip() for ln in result.stdout.strip().splitlines() if ln.strip() and _is_relevant_selinux_line(ln)]

    if source in ("audit_log", "both") and shutil.which("ausearch"):
        argv = ["ausearch", "-m", "avc", "-ts", _to_ausearch_since(since) if since else "boot"]
        result = run_privileged(argv)
        lines += [ln.strip() for ln in result.stdout.strip().splitlines() if "avc:" in ln.lower() and "denied" in ln.lower()]

    return lines


@dataclass
class GroupedDenial:
    key: str
    scontext_type: str
    tcontext_type: str
    tclass: str
    permissions: list[str]
    program: str
    sample_line: str
    sample_path: str | None
    count: int
    sources: list[str] = field(default_factory=list)
    classification: str = "new"  # "new" | "already_allowed" | "undefined_in_policy" | "resolved"
    matched_module: str | None = None


def group_denials(lines: list[str]) -> list[GroupedDenial]:
    """
    Collapses raw denial lines to one entry per unique (source type, target
    type, class, permission set) combination - the granularity an actual
    policy rule operates at - with an occurrence count, rather than one row
    per raw line. Kernel/audit-subsystem noise is skipped, same as
    build_policy_review().

    'Not defined in policy' lines are handled separately from normal AVC
    denials: they have no comm=/scontext=/tcontext= fields (they're raw
    kernel messages, not audit records), and the fix isn't a normal allow
    rule - see the "undefined_in_policy" classification.
    """
    groups: dict[str, GroupedDenial] = {}
    for line in lines:
        perm_match = _UNDEFINED_PERM_RE.search(line)
        class_match = _UNDEFINED_CLASS_RE.search(line) if not perm_match else None
        if perm_match or class_match:
            if perm_match:
                perm, tclass = perm_match.groups()
            else:
                perm, tclass = "", class_match.group(1)
            key = f"undefined|{tclass}|{perm}"
            if key not in groups:
                groups[key] = GroupedDenial(
                    key=key, scontext_type="(kernel)", tcontext_type="(kernel)", tclass=tclass,
                    permissions=[perm] if perm else [], program="kernel", sample_line=line, sample_path=None,
                    count=0, classification="undefined_in_policy",
                )
            entry = groups[key]
            entry.count += 1
            if "journal" not in entry.sources:
                entry.sources.append("journal")  # these are kernel printk lines, never audit records
            continue

        comm_m = re.search(r'comm="([^"]+)"', line)
        program = comm_m.group(1) if comm_m else "unknown"
        if _SKIP_PROGRAMS_RE.match(program):
            continue

        scontext_type = _extract_context_type(line, "scontext")
        tcontext_type = _extract_context_type(line, "tcontext")
        tclass_m = _TCLASS_RE.search(line)
        tclass = tclass_m.group(1) if tclass_m else "?"
        perm_m = _PERM_SET_RE.search(line)
        permissions = sorted(perm_m.group(1).split()) if perm_m else []
        source = "audit_log" if ("type=AVC" in line or "msg=audit(" in line) else "journal"

        key = f"{scontext_type}|{tcontext_type}|{tclass}|{','.join(permissions)}"
        if key not in groups:
            groups[key] = GroupedDenial(
                key=key, scontext_type=scontext_type, tcontext_type=tcontext_type, tclass=tclass,
                permissions=permissions, program=program, sample_line=line, sample_path=_extract_path(line), count=0,
            )
        entry = groups[key]
        entry.count += 1
        if source not in entry.sources:
            entry.sources.append(source)

    return sorted(groups.values(), key=lambda g: -g.count)


def _load_approved_allow_rules() -> list[tuple[str, str, str, set, str]]:
    """
    Parses every .te file this app has installed (approved/) into (source
    type, target type, class, permissions, module_name) tuples. Can only
    see modules Atropa itself compiled - a rule from the base policy or
    a module installed outside this app is invisible here, since only a
    compiled .pp (binary) exists for those, not readable .te source text.
    """
    rules: list[tuple[str, str, str, set, str]] = []
    if not APPROVED_MODULES_DIR.exists():
        return rules
    for te_file in APPROVED_MODULES_DIR.glob("*.te"):
        try:
            text = te_file.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for m in _ALLOW_RULE_RE.finditer(text):
            src_type, tgt_type, tclass, perms = m.group(1), m.group(2), m.group(3), set(m.group(4).split())
            rules.append((src_type, tgt_type, tclass, perms, te_file.stem))
    return rules


def classify_denials(grouped: list[GroupedDenial]) -> list[GroupedDenial]:
    """
    Marks each grouped denial "already_allowed" if a matching rule exists
    in a module Atropa has installed AND that module is currently
    loaded - otherwise it stays "new". "Already allowed but still denied"
    usually means a file-context/labeling problem (try restorecon on
    sample_path), not a missing rule, so it's worth telling apart from a
    genuine gap. Only Atropa-installed modules can be checked this way;
    see _load_approved_allow_rules().

    Entries group_denials() already marked "undefined_in_policy" are left
    alone - a normal allow rule doesn't fix a permission the policy's own
    class definitions don't know about, so there's nothing to match here.
    """
    approved_rules = _load_approved_allow_rules()
    loaded = set(list_semodules())

    for denial in grouped:
        if denial.classification == "undefined_in_policy":
            continue
        for src_type, tgt_type, tclass, perms, module_name in approved_rules:
            if module_name not in loaded:
                continue
            if (
                src_type == denial.scontext_type
                and tgt_type == denial.tcontext_type
                and tclass == denial.tclass
                and set(denial.permissions).issubset(perms)
            ):
                denial.classification = "already_allowed"
                denial.matched_module = module_name
                break

    return grouped


def _load_last_review() -> dict:
    if not LAST_REVIEW_FILE.exists():
        return {}
    try:
        return json.loads(LAST_REVIEW_FILE.read_text())
    except (OSError, json.JSONDecodeError):
        return {}


def _save_review_snapshot(grouped: list[GroupedDenial]) -> None:
    REVIEW_BASE_DIR.mkdir(parents=True, exist_ok=True)
    data = {
        g.key: {
            "scontext_type": g.scontext_type, "tcontext_type": g.tcontext_type, "tclass": g.tclass,
            "permissions": g.permissions, "program": g.program, "sample_line": g.sample_line,
            "sample_path": g.sample_path, "count": g.count,
        }
        for g in grouped
    }
    LAST_REVIEW_FILE.write_text(json.dumps(data, indent=2))


@dataclass
class ExtensiveDenialReview:
    new: list[GroupedDenial]
    already_allowed: list[GroupedDenial]
    undefined_in_policy: list[GroupedDenial]
    resolved: list[GroupedDenial]
    since: str | None
    source: str
    total_raw_lines: int


def review_all_denials(source: str = "both", since_setup_mode: bool = True) -> ExtensiveDenialReview:
    """
    The main entry point for the extensive review: fetches every denial
    still retained (scoped to Setup Mode's start time if in it and
    since_setup_mode is True), groups/dedupes them, classifies each as new
    vs already-allowed-but-still-denied vs undefined-in-policy (a kernel
    permission/class the compiled policy predates - see
    _is_relevant_selinux_line), and diffs against the previous review's
    snapshot to find anything that stopped recurring since then
    ("resolved"). Saves this run as the new snapshot for next time.
    """
    since = get_setup_mode_started_at() if since_setup_mode else None
    lines = list_all_denials(since=since, source=source)
    grouped = classify_denials(group_denials(lines))

    previous = _load_last_review()
    current_keys = {g.key for g in grouped}
    resolved = [
        GroupedDenial(
            key=key, scontext_type=data["scontext_type"], tcontext_type=data["tcontext_type"],
            tclass=data["tclass"], permissions=data["permissions"], program=data["program"],
            sample_line=data["sample_line"], sample_path=data.get("sample_path"), count=data["count"],
            classification="resolved",
        )
        for key, data in previous.items()
        if key not in current_keys
    ]

    _save_review_snapshot(grouped)

    return ExtensiveDenialReview(
        new=[g for g in grouped if g.classification == "new"],
        already_allowed=[g for g in grouped if g.classification == "already_allowed"],
        undefined_in_policy=[g for g in grouped if g.classification == "undefined_in_policy"],
        resolved=resolved,
        since=since,
        source=source,
        total_raw_lines=len(lines),
    )


# ------------------------------------------------- policy source diagnostic --
#
# For an "undefined_in_policy" denial: read-only check against a policy
# SOURCE tree (not the compiled/loaded policy) to tell you whether the
# permission is already defined there or genuinely missing. Atropa never
# writes to a policy source or ships policy content of its own - this is
# purely diagnostic, so you know where to look before editing anything
# yourself.

_CLASS_DEF_RE_TEMPLATE = r"class\s+{cls}\b([^{{}}]*)(\{{[^}}]*\}})?"


def _extract_class_block(text: str, class_name: str) -> tuple[bool, str | None, str]:
    """Returns (class_found, inherited_parent_or_None, own_block_text).
    Best-effort text search over refpolicy's `class X [inherits Y] { ... }`
    syntax - not a full policy-language parser, so an m4 macro or unusual
    formatting could hide a real definition from this."""
    m = re.search(_CLASS_DEF_RE_TEMPLATE.format(cls=re.escape(class_name)), text)
    if not m:
        return False, None, ""
    inherits_m = re.search(r"inherits\s+(\w+)", m.group(1) or "")
    parent = inherits_m.group(1) if inherits_m else None
    block = m.group(2) or ""
    return True, parent, block


def check_policy_source_for_permission(policy_src_dir: str, tclass: str, permission: str = "") -> dict:
    """
    Best-effort, read-only check: does <policy_src_dir>/policy/flask/
    access_vectors define `permission` for `tclass` (following one level
    of `inherits`)? Leave `permission` empty to just check whether the
    class itself is defined at all (the "whole class undefined" case).

    Never writes anything, and doesn't attempt anything beyond a plain
    text search - treat a "not found" result as a strong hint to check
    manually, not a certainty, and always double check before editing
    the policy source yourself; Atropa doesn't do that part for you.
    """
    av_path = Path(policy_src_dir) / "policy" / "flask" / "access_vectors"
    result = run_unprivileged(["cat", str(av_path)])
    if not result.ok:
        return {
            "checked_path": str(av_path), "class_found": False, "permission_found": False,
            "inherits": None, "error": f"Couldn't read {av_path}: {result.stderr.strip()}",
        }

    text = result.stdout
    class_found, parent, own_block = _extract_class_block(text, tclass)
    if not class_found:
        return {"checked_path": str(av_path), "class_found": False, "permission_found": False, "inherits": None, "error": None}

    if not permission:
        return {"checked_path": str(av_path), "class_found": True, "permission_found": True, "inherits": parent, "error": None}

    permission_found = bool(re.search(rf"\b{re.escape(permission)}\b", own_block))
    if not permission_found and parent:
        parent_found, _, parent_block = _extract_class_block(text, parent)
        if parent_found:
            permission_found = bool(re.search(rf"\b{re.escape(permission)}\b", parent_block))

    return {
        "checked_path": str(av_path), "class_found": True, "permission_found": permission_found,
        "inherits": parent, "error": None,
    }
