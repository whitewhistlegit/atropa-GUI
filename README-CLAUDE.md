# README-CLAUDE.md — start here if you're a new session picking this up

This is a **session handoff note**, not the technical reference. For that,
read `DOCUMENTATION.md` first — it has the full architecture, every
function's contract, design decisions and why they were made, and the
TODO list. This file is the shorter "what were we just doing, and what do
you need to know about the human" briefing that doesn't belong in the
permanent technical doc.

## What this project is

**Atropa** — a YaST-inspired system control center for Arch Linux (GTK4 +
libadwaita). Was named **ArchYaST** until a deliberate full rename partway
through this project's life (see DOCUMENTATION.md's "Done" list for why -
short version: "ArchYaST" sounded awkward, and Atropa has a much better
backstory — Atropos, the Greek Fate who cuts the thread of life; deadly
nightshade, *Atropa belladonna*, carries her name).

Current scale: 22 backend modules, 21 UI pages, ~10,000 lines, 521 tests,
all passing. Everything compiles/lints clean (`py_compile` + `ruff check .`).

## Who you're working with

- Runs **Arch Linux**, multi-boots several kernels on the same machine:
  `linux` (vanilla), `linux-zen`, `linux-lts`, `linux-hardened` — all via
  DKMS-built `nvidia-open` (610.43.03). Ex-Gentoo, genuinely comfortable
  building from source, rebuilding policy trees, reading kernel logs — you
  don't need to hold their hand through anything technical.
- Runs **SELinux** via `selinux-refpolicy-arch-git` (switched from the
  non-`-git` package after discovering it hadn't been updated since 2023 -
  see the big SELinux troubleshooting saga below).
- Communication style: direct, terse, sometimes typo-heavy, occasionally
  swears when frustrated (not at you specifically). Wants substance over
  hedging. Explicitly said "just brainstorming mode" a few times when they
  wanted ideas discussed *without* code changes — respect that distinction
  when they say it.
- Tests every handoff on **real bare-metal hardware**, often within
  minutes, frequently with screenshots. This is a real, active feedback
  loop — findings from actual runs have driven real bug fixes (see below).
  Treat "seems to work fine" as a meaningful, hard-won signal, not a
  throwaway remark.

## The big recent arc: a real SELinux boot-hang investigation

A large chunk of this session was live troubleshooting a genuine SELinux
enforcing-mode boot hang on the user's actual machine — not a hypothetical.
Worth knowing the shape of it because it produced two real product fixes:

1. Traced through: permissive boots fine → enforcing-from-desktop fine →
   enforcing-from-boot hangs → eventually found `kauditd_printk_skb: N
   callbacks suppressed` (an audit-message flood, likely from BPF
   permission checks retry-looping) → root cause was the policy's
   `deny_unknown: denied` setting combined with the kernel exposing newer
   capability bits (`bpf`, `perfmon`, `checkpoint_restore`) the 2023-era
   policy never defined.
2. **This directly led to two real Atropa fixes**, both already shipped:
   - `selinux.py` gained an `"undefined_in_policy"` classification distinct
     from a normal missing-`allow`-rule denial (the kernel message format
     `Permission X in class Y not defined in policy` has no `scontext=`,
     so it needed entirely different parsing/handling than a normal AVC
     line) — plus a read-only "Help → check my policy source" diagnostic.
   - `selinux.reinstall_all_approved_modules()` — a real one-shot batch fix
     (single `semodule -i` call, not a loop) for the "switched
     `SELINUXTYPE`, now every approved module shows inactive, don't make
     me re-authenticate 12 times" pain the user hit directly.
3. Eventually resolved on their end via a full `restorecon` relabel after
   switching policy sources — confirmed working on real hardware.

If the user brings up SELinux, boot issues, or `refpolicy-arch` again,
this history is relevant context, not a fresh topic.

## What got built this session, roughly in order

1. Pytest suite + CI (from zero → the current 471-test baseline)
2. UX polish pass (loading spinners, streaming-progress dialogs, longer
   error toasts) + Dependencies page
3. Security Quick Setup (batch + guided-wizard baseline across
   firewall/fail2ban/sysctl/faillock/AppArmor/auditd/USBGuard/SELinux)
4. Security Profiles (export/import posture as JSON) + Compliance Report
   (CIS-*inspired*, explicitly disclaimed as not an official assessment)
5. SELinux: Denial Review (Setup Mode, extensive fetch, three-way
   classification against currently-loaded policy)
6. The plugin system (`backend/plugins.py` + `plugin_registry.py`) —
   **declarative TOML only, never code**; manifests and enabled-state both
   live under root-owned `/etc/atropa/`, so placing/editing/enabling all
   require root. This was a deliberate, discussed security-model decision,
   not a default — see DOCUMENTATION.md for the reasoning.
7. **The ArchYaST → Atropa rename** (full: package, imports, paths, GTK
   app ID, desktop/polkit files) + a migration feature for anyone with old
   ArchYaST data (never automatic, never destructive, existing-file-wins).
8. System Config page (hostname/timezone/locale/keyboard via
   `hostnamectl`/`timedatectl`/`localectl`)
9. The SELinux boot-hang saga (above) → `undefined_in_policy` handling +
   the policy-source diagnostic + `reinstall_all_approved_modules()`
10. **CIS DIL Benchmark, Phase 1**: confirmed there's
    no official CIS Benchmark for Arch, so the real target is the CIS
    *Distribution Independent Linux* Benchmark. Built SSH depth (7 new
    settings in `security.py`), password complexity policy
    (`pwquality.conf` handling in `hardening.py`), and real auditd rule
    *content* (new `backend/audit_rules.py`, 5 rule sets, with
    path-existence checking since several standard CIS watch paths are
    RHEL/Debian-era conventions Arch doesn't have).
11. **CIS DIL Benchmark, Phase 2** (current/latest work): the two areas
    deferred out of Phase 1. New `backend/inventory.py` (CIS 2.2/2.3
    service inventory — 16 catalog entries, real Arch package/unit names
    verified via web search rather than assumed, e.g. `dhcp` ships
    `dhcpd4.service`+`dhcpd6.service`, Samba's unit renamed
    `smbd`→`smb` in 4.8+) and new `backend/account_hygiene.py` (CIS
    6.1/6.2 file/account hygiene — perms, duplicate UID/GID, stray UID-0
    accounts, home directory ownership, empty shadow passwords, root
    `PATH` integrity), both wired into a new read-only
    `pages/inventory_hygiene.py` page and into `compliance.py`'s report
    as two new categories. Real finding worth knowing: CIS's own
    2.2-servers/2.3-clients split doesn't map onto how Arch packages
    things (`inetutils` bundles legacy telnet/rsh/talk clients *and*
    their listening sockets together) — `inventory.py`'s docstring
    explains why it reports installed-vs-active per entry instead of
    forcing that split. `su`-restriction-to-wheel (CIS 6.1.x) was
    explicitly *not* built — it needs the same live `/etc/pam.d/su` edit
    Phase 1 already declined for faillock/pwquality, so it's deferred
    alongside real PAM-wiring automation instead.
12. **CIS DIL Benchmark, Phase 3** (current/latest work): filesystem
    integrity checking (CIS 1.3) via AIDE — the one phase explicitly
    flagged as needing a real scoping conversation before starting, and
    it earned that flag. Key discovery: AIDE was dropped from Arch's
    official repos and is AUR-only now — first time this project had to
    decide how to handle an AUR-only *security tool*, not just an
    AUR-only dev convenience like paru/yay. Kept the same posture as
    those: new `backend/aide.py` never builds/installs anything, only
    manages AIDE once it's already present. Asked the user directly
    whether Atropa should probe for the AUR package's own systemd
    timer (names have shifted across package revisions —
    `aide.timer`/`aidecheck.timer` both seen in the wild) or write its
    own dedicated one; they said "you pick," went with detecting the
    existing one (`detect_timer_unit()` tries known candidate names in
    order) since a second duplicate timer risks drifting out of sync
    with the package's own config. New `pages/aide_page.py` — baseline
    init/re-init, run-check with parsed added/removed/changed summary,
    and an "Update baseline" action gated behind an explicit confirm
    dialog since re-baselining accepts everything currently reported as
    the new normal.

**Bare-metal confirmation**: AIDE via Phase 3 tested clean over 72+ hours
on the user's real SELinux-enabled install, using `aide-selinux` rather
than plain `aide` (the latter has real build failures in the wild; both
provide the same `aide` binary Atropa looks for, so no code changes were
needed) - noted in `dependencies.py` and `aide.py`'s docstring as a
troubleshooting path for anyone hitting the same AUR build failure.

13. **Bug fix from bare-metal feedback (current/latest)**: user reported
    the app spamming `pkexec` password prompts badly enough to trip
    `pam_faillock` and lock themselves out. Root cause was two things in
    `main_window.py`: (a) all ~20 pages were constructed eagerly at
    startup, and nearly every page's `__init__` ends with `self.refresh()`
    — for privileged pages (AppArmor's `aa-status`, and Phase 2/3's own
    Inventory & Hygiene + Compliance Report) that meant a batch of
    `pkexec` prompts on every single launch before the user touched
    anything; (b) worse, `_on_row_activated()` was calling
    `page_widget.refresh()` again on *every sidebar click*, so revisiting
    an already-loaded tab re-triggered the same privileged reads over and
    over. Fixed by making page construction lazy (`_ensure_page_
    materialized()`, only touches `main_window.py`, no changes needed to
    any of the ~20 individual page files) and dropping the
    refresh-on-every-click. Also consolidated `account_hygiene.py`'s
    `_check_root_path()` from 2 separate `pkexec cat` calls down to 1
    (both root dotfiles in one invocation — cat concatenates them fine
    since the check never needs to know which file a line came from).
    **Known remaining gap, explicitly not fixed**: Inventory & Hygiene and
    Compliance Report still each independently call
    `account_hygiene.scan_all()`, so visiting both in one session still
    means re-authenticating a second time — no cross-page caching added,
    left for a deliberate follow-up rather than bundled into an urgent
    fix. Like all UI changes in this project, **not visually verified** —
    checked via `py_compile`/`ruff`/tests plus a manual trace of the call
    sequence only; confirming the real prompt count on next launch is
    still owed to the user.
14. **Third bug, same bare-metal session**: firewall toggle showed off
    with an empty rules list even though ufw was genuinely active - root
    cause was `firewall_status()` reading `ufw status`/`firewall-cmd
    --list-all` via `run_unprivileged()`. Both genuinely need root and,
    critically, don't fail loudly without it - just return limited/empty
    output that parsed as "inactive, no rules" regardless of reality.
    Switched both to `run_privileged()` (confirmed the root requirement
    via search first, not assumed); `systemctl is-active firewalld` stays
    unprivileged since that one genuinely doesn't need it. Every existing
    caller (`hardening.run_audit()`, `profiles.py`, `quicksetup.py`)
    inherits the fix automatically. Updated 10 stubbed-call sites across
    5 test files that all hardcoded the old unprivileged argv.
15. **Fourth bug, same family, same session**: SELinux Load Policy page's
    "approved" section showed installed modules as inactive/needing
    reinstall - but only when Atropa ran unprivileged; running Atropa as
    root showed it correctly. That launch-dependent symptom was the
    giveaway - same root cause as the ufw bug above. `list_semodules()`
    (`semodule -l`) needs root to read the real policy module store;
    reading unprivileged silently returned nothing rather than erroring.
    `list_pending_modules()`, `list_approved_modules()`, and
    `classify_denials()` (Denial Review page) all derive their "is this
    loaded" set from `list_semodules()`, so all three inherited the fix
    automatically once that one function was corrected. Updated 9 stubbed
    call sites in `test_selinux.py`; two tests that asserted a raw
    privileged-call *count* as a stand-in for "reinstalls batch into one
    `semodule -i` call" needed rewriting to assert the batching directly,
    since the count itself legitimately went up by one (the now-privileged
    status check) without the batching guarantee actually changing.
16. **Fifth bug, different shape - a scoping mismatch, not a missing
    `pkexec`**: on the Denial Review page, "Generate Policy for All New
    Denials" used a much narrower time window than the "Review" button
    that populated the list it was generating policy from - bad on a
    system with lots of setup-time denials, where "recent" catches a
    fraction of what "boot" catches. `build_policy_review()` is called
    from two places with different intent: the plain SELinux page's ad-hoc
    review never passes `since` (wants the small "recent" window on
    purpose), Denial Review always passes it explicitly as
    `self._last_review.since` - `None` on any system not using Setup Mode,
    the common case. The function treated "omitted" and "explicitly None"
    as the same thing. Fixed with a sentinel default (`_SINCE_UNSET`) so
    only a truly omitted `since` gets the narrow window; an explicitly
    passed `None` now correctly routes to the same uncapped, boot-scoped
    fetch the Review button already used. Neither UI page needed a code
    change - the bug was entirely in how the backend interpreted an
    already-correct call. Two new regression tests lock in the
    distinction.
17. **Sixth bug, found immediately after by a second person testing the
    same build**: every "New" denial on the Denial Review page showed
    `? → ?` instead of real source/target types, even though class and
    permissions next to it parsed fine on the same lines. Asked the user
    for a real raw line before guessing at a regex fix - the answer
    (`scontext=user_u:user_r:pipewire_t`, no `:s0` at all) showed it
    immediately: `_CONTEXT_TYPE_RE_TEMPLATE` required a mandatory fourth
    colon-segment (an MLS/MCS range) after the type, but a policy running
    without MLS/MCS - the user's real system - only has three parts.
    Fixed with `[^:\s]+` instead of `\S*?` so the trailing range is
    genuinely optional, not assumed; verified against no-range, `:s0`,
    and full MCS-range (`:s0-s0:c0.c1023`) shapes before touching tests.
    Every existing test fixture for this path used the classic `:s0`
    shape, which is exactly why the gap was invisible to the whole suite
    until a real system without it hit it - added one regression test
    using the user's exact raw line verbatim.
18. **Seventh bug, a real safety issue, not just a display glitch**:
    "Try restorecon" ran against a bare filename (`journal`) instead of a
    real path - restorecon resolved it relative to the privileged
    process's own working directory (`/root`), giving
    `lstat(/root/journal) failed`. The actual risk was worse than the
    visible error, though: if a file with that bare name happened to
    exist there, restorecon would have silently relabeled the *wrong
    file*. `_extract_path()` was falling back from `path="..."` (always
    genuine) to `name="..."` unconditionally, but `name=` is often just a
    bare directory-entry name, not a path. Fixed by only accepting
    `name=` as a fallback when it's already absolute; a bare one now
    correctly returns `None`, same as "no path available" already showed
    elsewhere. One existing test had been asserting the buggy behavior
    outright (`sample_path == "a"` from a bare `name="a"`) - fixed with
    the reasoning documented inline. `sample_path` has exactly one
    consumer in the whole codebase (the restorecon button), so no other
    blast radius to check.

19. **SELinux page: lock-before-toggle on the enforcing/permissive
    switch**, requested by the user directly (a feature ask, not a bug
    report). Switch starts locked on every refresh; a lock icon
    (`changes-prevent-symbolic`/`changes-allow-symbolic` - confirmed real
    GNOME icon names via search, not guessed) must be clicked to arm it,
    on top of the existing confirm dialog rather than instead of it - the
    lock stops an accidental drag from registering as a request at all,
    the dialog stops a confirmed request from completing. One unlock
    authorizes exactly one change. Found and fixed a real pre-existing
    bug in the same code while implementing this: the `state-set` handler
    returned `False` unconditionally, which per GTK's own contract means
    the default handler always applies the requested position regardless
    of the dialog's response - cancelling left the switch showing the
    wrong mode until the page was next refreshed. Fixed by returning
    `True` and explicitly reverting via `set_active()` on cancel.
    Extended `BasePage.confirm()` (37 call sites) with an optional
    `on_cancel` callback to support this cleanly rather than duplicating
    the dialog construction in `selinux.py` - backward compatible, every
    existing caller already omits the new parameter. Not visually
    verified - same GTK-less-sandbox limitation as everything UI-side.

20. **Eighth/ninth bugs, from the user's own screenshot of the lock
    feature**: real `sestatus` output is lowercase
    ("enforcing"/"permissive"), but two places compared it against
    Title-case - the SELinux page's mode toggle (`_mode_toggleable`,
    `set_active()` - the lock button came back permanently disabled on
    any real system, not just showing the wrong position) and, more
    consequentially, `hardening.py`'s Compliance Report SELinux check (a
    fully enforcing setup silently scored as "warn" instead of "pass" on
    every real system). Existing test coverage never caught #2 because it
    only checked a `"SELinux"` key existed, in a sandbox where SELinux
    isn't available at all - the buggy branch was never exercised. Fixed
    both with `.lower()` comparisons, added two `hardening.py` tests that
    actually monkeypatch `get_status()` to exercise the enforcing/
    permissive branches directly, and corrected the Title-case example in
    `SelinuxStatus.mode`'s own docstring comment, likely the actual source
    of the original mistake.

21. **Installer fix + new refpolicy build feature**: `install.sh` now
    uses `pipx install --system-site-packages --force .` instead of
    `pip install --break-system-packages` (added `python-pipx` to the
    pacman deps; `--system-site-packages` so the venv inherits pacman's
    PyGObject/GTK4 rather than rebuilding it). New
    `backend/refpolicy_build.py` + `pages/refpolicy_build.py`: build
    (`make conf all`, unprivileged)/install (`make install`, privileged,
    not active yet)/activate (sets `SELINUXTYPE=`, maps `__default__`
    login to `unconfined_u` with `-a`-then-`-m` fallback, schedules a
    relabel) as three separate confirmed stages for a user-maintained
    refpolicy fork - never an AUR package build. Added
    `run_unprivileged_streaming()` to `privilege.py` (was missing - only
    had blocking unprivileged + streaming privileged before). No kernel
    params touched, no reboot triggered, ever - regression-tested
    directly. Explicitly did not build anything for the user's
    `nvidia-workaround.service` (a one-off boot-order diagnostic hack,
    not a generalizable feature) or the full monolithic-vs-modular
    refpolicy build system beyond the modular target set their
    `build.conf` actually uses.
22. **Batch `.te` import**: `import_te_files()` in `selinux.py` +
    "Import .te files…" button on the Load Policy page - compiles a
    batch of pre-written `.te` files into Pending (not installed
    directly, unlike the single-file flow) for individual review.

**Explicitly not yet started**: `su`-restriction-to-wheel (deferred from
Phase 2, needs live PAM editing). Partition/mount-scheme controls are
permanently out of scope — that's an install-time decision, not something
a running system's control panel can retrofit.

## Patterns worth knowing before you write code

- **This sandbox has no GTK/libadwaita at all.** UI code is verified by
  `py_compile` + `ruff check .` + careful reasoning, never by running it.
  Given that, **always check for an existing precedent** in the codebase
  before using a GTK widget/signal/property you haven't seen used here
  already (`grep` for it first). This caught two real bugs this session:
  `Gtk.Switch.set_state()` vs the actually-used `set_active()`, and an
  unverified live `Gtk.Editable::changed` filter binding where every other
  filter in the app uses an explicit "Apply" button instead.
- **The sandbox has real `/sys/fs/selinux` and `/sys/kernel/security/apparmor`
  mounts inherited from the host**, even though neither LSM is actually in
  use here. Any test touching `is_available()`-style filesystem checks
  needs the autouse `Path.exists()`-patching fixture already established
  in `test_selinux.py`/`test_quicksetup.py`/`test_compliance.py` — copy
  that pattern, don't rediscover the bug.
- **`conftest.py`'s `FakeRun.call_containing(needle)` checks exact
  list-element equality, not substring matching.** `["pkexec", "sed", "-i",
  "s/foo/bar/"]` — `call_containing("foo")` returns `None` even though
  "foo" is in there, because it's embedded inside a longer single argv
  element. Use `any(needle in arg for call in fake_run.calls for arg in
  call)` for substring checks. This exact mistake has been made and fixed
  multiple times this session — don't repeat it.
- **Packaging**: `find . -name __pycache__ -exec rm -rf {} +` (and
  `.pytest_cache`/`.ruff_cache`), then `tar -czf atropa.tar.gz --exclude=
  '__pycache__' -C /home/claude atropa`, copy to `/mnt/user-data/outputs/`,
  `present_files`. The user's local machine has working tarball support
  again (a `.zip` fallback was only needed once, for an Android sticker-
  pack-detection false-positive on `.tar.gz` — not a recurring issue).
- **Memory tool vs file tools**: `memory_write`/`memory_append`/etc. are
  for the *persistent cross-session memory filesystem*, completely
  separate from this project's actual files on disk. Mixing them up has
  happened once already this session (caught immediately, fixed, no
  lasting harm) — always double check which tool you're reaching for.
- **Every new backend function gets tests before the UI is wired to it.**
  This has caught real logic bugs (regex issues, escaping mismatches
  between Python and sed, off-by-one context extraction) before they ever
  reached working code, several times over. Don't skip straight to UI.
- **Full validation sweep before every package**: `py_compile` on
  everything, `ruff check .`, full `pytest -q`, and a duplicate-function-
  definition grep across every file — all four, every time, no exceptions.

## Where to actually look for "what's left"

`DOCUMENTATION.md`'s "Still open" section at the bottom has the running
TODO list (kernel-param/PAM automation, Btrfs snapshots, journal viewer,
kernel management, plus the CIS DIL Phase 2/3 items above). That list is
kept current — trust it over trying to reconstruct scope from git-log-style
archaeology through this file.
