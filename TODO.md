# Atropa TODO

The target is a single-user Arch desktop or laptop. The background and
reasoning for the existing items are in
[`DOCUMENTATION.md`](DOCUMENTATION.md), section 6.

## Single-user desktop features

Rough priority order. The first three cover most of what breaks on a
single-user Arch machine.

- [x] **`.pacnew` / `.pacsave` handling** - list them, diff each against the
      live file, and keep or replace (merging is a manual edit). Backed up
      through the existing backup mechanism first.
- [x] **Snapshot before upgrade, with rollback**
  - [x] Package rollback from the pacman cache (any filesystem): Package
        History lists transactions from `pacman.log` and reinstalls the
        versions one replaced; Clean keeps the previous version.
  - [x] Btrfs: Snapper + snap-pac (automatic pre/post snapshots), list,
        file restore, and booting a snapshot via grub-btrfs.
  - [ ] Boot a grub-btrfs snapshot entry once by hand (the menu entries
        were checked in the VM's grub-btrfs.cfg, not booted).
- [x] **Upgrade checks**
  - [x] Before: show recent Arch news items that need manual steps.
  - [x] After: list failed units (`systemctl --failed`).
  - [x] Say "reboot needed" when the running kernel no longer matches the
        installed one.
  - [x] Check for the right CPU microcode package (`intel-ucode` /
        `amd-ucode`).
- [x] **pacman configuration** - toggles for `ParallelDownloads`, `Color`
      and `[multilib]`, backed up and validated with `pacman-conf`.
- [x] **Mirror ranking** - rank mirrors with `reflector`.
- [x] **"What went wrong this boot" page** - errors from this boot, failed
      units and recent crashes (`coredumpctl`), rather than a raw journal
      tail. (Supersedes the plain journal viewer below.)
- [x] **Firmware updates via `fwupd`** - list devices, refresh metadata,
      apply updates.
- [x] **Disk encryption and Secure Boot status** - report whether root is on
      LUKS; set up and sign with `sbctl`. Feed both into the security audit
      score.
- [x] **Disk health and space** - SMART status, enable `fstrim.timer`, and
      cleanup beyond the pacman cache (journal size, `~/.cache`, coredumps).
- [x] **Power and memory** - `power-profiles-daemon` or TLP, laptop battery
      charge limits, zram swap. Sleep/hibernate state is reported.
- [x] **Sleep/hibernate configuration** - lid close (on battery and
      plugged in), power button and the suspend-then-hibernate delay, in
      Atropa's own logind/sleep drop-ins. logind is reloaded, not
      restarted, so the session stays up.
- [x] **Flatpak** - updates and removing unused runtimes, next to the
      pacman page.

### Desktop focus for existing modules

- [x] **Desktop profile in Security Quick Setup** - when `sshd` isn't
      installed, skip fail2ban and SSH hardening and offer a desktop
      baseline: firewall on with no incoming connections, encryption check,
      Secure Boot.
- [x] Move **Users & Groups** lower in the sidebar.
- [x] Frame the **audit score** around how exposed this machine is, rather
      than a CIS enterprise audit.

## Existing TODO (from DOCUMENTATION.md)

- [x] **`su` restriction to the wheel group** (CIS 6.1.x) - uncomments the
      stock `pam_wheel.so use_uid` line in `/etc/pam.d/su` and `su-l`
      (Hardening page); hand-edited files are left alone.
- [x] **Bootloader/AppArmor kernel parameter and PAM-wiring automation** -
      Bootloader > Kernel parameters (AppArmor/SELinux LSM lists, hardening
      parameters, free-form), keeping the current boot entry with its old
      parameters first (GRUB: `custom.cfg`; systemd-boot: an
      `atropa-previous-*.conf` entry). PAM: pam_pwquality wired into
      system-auth's password section (stock layout only); pam_faillock is
      already wired by pambase.
- [ ] **Disk/partition management** (explicitly out of scope at project
      start).
- [x] **Btrfs snapshots** - Snapper + snap-pac + grub-btrfs (see "Snapshot
      before upgrade" above). Timeshift isn't integrated; Snapper covers the
      same need.
- [x] **Journal/log viewer** - superseded by the Boot Report page.
- [x] **Kernel management** - Kernels page: installed kernels (found by
      their `pkgbase` file, so AUR kernels count) with running / headers /
      boot entry, a fallback-kernel warning, install (headers added when
      DKMS is in use, GRUB menu regenerated, upgrade-and-install when the
      system is behind) and remove (never the running or last kernel), a
      copied systemd-boot entry, and removal of leftover DKMS module
      folders. Editing `mkinitcpio.conf` stays out of scope.
  - [ ] Boot the fallback kernel once on real hardware with DKMS (checked in
        the VM's GRUB menu, not booted).

### From the full-repo audit

- [ ] Run the SELinux path once on x86_64 through Atropa: Quick Setup's
      SELinux step through to installed tools, then Get, Build and Install
      on the Build Policy page.
- [ ] Check Restart, the journal dialog and USBGuard's "Turn off" on a
      machine with systemd.
- [ ] Check bootloader detection on a real UEFI machine that boots GRUB
      (relies on GRUB 2.12 writing "GRUB ..." to `LoaderInfo` and on
      `bootctl --print-esp-path` answering there).
- [x] CI: a GTK smoke test that builds every page under Xvfb, Python
      3.13/3.14 in the matrix next to 3.11/3.12.
- [x] CI: parser tests against real config files rather than hand-written
      snippets - `tests/test_stock_configs.py` runs the parsers and edits
      against unmodified files from Arch's packages (`tests/fixtures/stock`).
- [x] **Single privileged helper** - one root-owned helper
      (`/usr/lib/atropa/atropa-helper`) with an `auth_admin_keep` polkit
      action, so one password covers an operation instead of one prompt per
      command. The helper runs a bare-name allowlist of tools, never a
      shell.
- [x] **Helper phase 1: file operations** - `tee`/`install`/`replace-in-file`
      are performed by the helper against an exact path policy; `sed` is
      refused; `cp`/`mkdir`/`touch`/`rm`/`chown` validate their paths.
      A policy-coverage test keeps `WRITE_FILES` in sync with the backend.
- [x] **Helper phase 2: a validator per command, two tiers** - the open
      allowlist is gone; every program has a validator for the exact
      argument shapes Atropa uses, `cat` reads only managed files (no
      `/etc/shadow`: `shadow-status` instead), and root-equivalent
      operations go through `atropa-helper-ask`, which always asks.
- [ ] **Check the two prompts by hand in a desktop session** - pkexec's own
      text agent can't authenticate over SSH with polkit's socket-activated
      helper ("No session for cookie"), so the keep-vs-ask prompting was
      verified by polkit's action choice and by running both helpers via
      sudo, not by typing a password.
- [x] **Root-owned backups** - the helper backs a file up itself, as root,
      before overwriting it, into `/var/lib/atropa/backups`; `backup-show`
      and `backup-restore` read and restore them. Old home backups stay
      viewable but aren't restored while the helper is installed.

## SELinux Denial Review

Seen when its generated modules were reviewed in the Arch test VM,
2026-10-31. (The policy findings themselves are tracked outside this repo.)

- [x] **Suggest `dontaudit` for known noise** instead of an `allow` - e.g.
      `net_admin` for auth helpers like `polkit-agent-helper-1`, and
      nss-systemd's writes to the `io.systemd.Home` / nsresourced sockets.
      Granting these weakens the policy for nothing.
- [x] **Flag likely mislabeling** - `execute_no_trans` on `lib_t` (and
      similar) almost always means a file is missing its file context, e.g.
      Arch's `/usr/lib/...` helpers where the policy expects `/usr/libexec/`.
      Say "this path probably needs a file context" instead of drafting an
      `allow`.
- [x] **Flag rules that can't work on their own** - e.g. `sock_file write`
      without `unix_stream_socket connectto`.
- [x] **Skip list hid real denials** - `^(systemd|kernel|audit|kworker|swapper)`
      matched as a prefix, hiding systemd-tmpfiles, systemd-coredump,
      systemd-logind, systemd-homed and auditd: 292 of 1226 denials in one
      enforcing GNOME boot. Now exact names only.
- [x] **Offer booleans before modules** - when `audit2why` / `audit2allow -b`
      says a boolean would allow the denial, show that first (e.g. SSH logins
      blocked under refpolicy: `ssh_sysadm_login`), with what else the boolean
      opens up.
- [x] **Check "already allowed" against the whole loaded policy** with
      `sesearch` (setools), not only Atropa's own approved modules - including
      which boolean gates a rule.
- [x] **Sort by impact, not count** - one boot had 901 `polkitd` denials,
      nearly all nss-systemd noise, on top of everything that actually broke.
      Put recognized noise in its own group.
- [x] **Name modules after the SELinux domain**, not the process name: `comm`
      is cut at 15 characters, giving `atropa_polkit-agent-he_policykit_auth_t`
      and `atropa__sd-worker__systemd_nsresourced_t`.

### Over-permissive module warnings (design, not built yet)

Warn when a drafted (or hand-edited) module grants more than the program
should need, judged against what kind of program it is. Builds on what's
already there: `te_warnings()`, `PolicyChecker`, `noise_reason()`,
`label_hint()`, `te_booleans()`.

- [ ] **Parser** - new `backend/te_lint.py` turns a `.te` into rules
      (kind, source, target, class, perms, line) plus its `require` block;
      handles hand edits (braces, `~`, `*`, attributes). With setools,
      attribute targets expand, so `file_type:file write` counts as
      touching thousands of types.
- [ ] **Base rules** - a data table: id, severity, match, why, fix.
  - Dangerous (root-equivalent or switches protection off): `security_t`
    (`setenforce`/`load_policy`/`setbool`), `selinux_config_t`,
    `policy_config_t`, `mac_admin`/`mac_override`; `module_load`,
    `sys_module`, `sys_rawio`, `memory_device_t`, raw disks, `mmap_zero`;
    `shadow_t`, writes to `passwd_file_t`/`sudo_exec_t`/`etc_t`/PAM;
    writes to `bin_t`/`lib_t`/`boot_t`/`*_exec_t`; transition to
    `unconfined_t`, `setcurrent`/`dyntransition`, `ptrace` on another
    domain; write/unlink on `auditd_log_t`; anything widening a confined
    user or sandbox domain (`user_t`, `guest_t`, `*_sandbox_t`).
  - Review (over-permissive): generic targets (`default_t`, `file_t`,
    `unlabeled_t`, `var_t`, `etc_t`, `tmp_t`, `usr_t` - usually a label
    problem); `*`/`~` or a full manage set on a shared type; execute on a
    type the domain can also write; `name_bind`/`name_connect` on
    `port_t`/`unreserved_port_t`/`reserved_port_t`, rawip/packet sockets,
    netlink writes; `sys_admin`, `net_admin`, `setuid`/`setgid`,
    `sys_ptrace`; signals to other domains; more than ~25 rules or
    distinct targets (suggest `semanage permissive -a` while
    investigating).
  - Note (better route exists): `dac_override`/`dac_read_search` (usually
    a Unix permission bug), boolean-covered rules, already-allowed rules,
    noise that should be `dontaudit`. The existing sock_file/connectto
    check becomes one rule here.
- [ ] **Program categories** - linked toggle buttons per pending module:
      System service, Boot, User service, D-Bus service, Desktop app, Not
      sure (= base rules only). The choice is saved next to the `.te` and
      re-lints live.
  - Auto-detect a preselected guess, with the reason shown: AVC pid ->
    systemd unit (system unit -> System service; `BusName=`/`Type=dbus` or
    a `dbus-1/system-services` file -> D-Bus service; user manager -> User
    service; `DefaultDependencies=no`/before `sysinit.target`/initrd or
    generator path -> Boot); user domain plus display-server sockets ->
    Desktop app; otherwise Not sure.
  - Expected / out of place per category:
    - System service: own `*_var_lib_t`/`*_log_t`/`*_run_t`, syslog, its
      own port, `/etc` reads | home folders, display/audio, exec from tmp.
    - Boot: device nodes, mount, sysfs/proc writes, raw disk reads, module
      loading (Review, not Dangerous) | network, home folders.
    - User service: `user_home_t`, `user_tmp_t`, session bus, PipeWire |
      `/etc` writes, `var_lib`, any capability, reserved ports, shadow.
    - D-Bus service: `system_dbusd_t` send_msg/acquire_svc, polkit | home
      folders, broad capabilities, binding ports.
    - Desktop app: home, display server, DRI, audio, outgoing HTTP(S) |
      any capability, `/etc` writes, other users' files, ptrace, binding
      ports.
  - A category can lower a severity where something is expected (Boot:
    `sys_module` -> Review) or raise one (Desktop app: any capability ->
    Dangerous), but never clears the hard Dangerous list.
  - Out-of-place findings say so plainly ("a user service shouldn't need
    to write /etc - wrong category, or this program is doing something
    odd"); a module mostly outside its category gets a "looks more like a
    System service" banner.
- [ ] **UI** - badge per module (Looks fine / Review / Dangerous); each
      finding shows the highlighted line, why, and a one-click safer option
      where it's mechanical (switch to `dontaudit`, enable boolean X,
      relabel with `restorecon`/`semanage fcontext`, drop these perms, split
      the module). Live re-lint of hand edits. Install: fine -> as today;
      Review -> confirm listing findings; Dangerous -> disabled until each
      dangerous finding is acknowledged.
- [ ] **Backend gate** - `compile_and_load_te()` lints itself and refuses
      unacknowledged Dangerous findings (`acknowledged={rule ids}`,
      recorded with the category), so "reinstall all approved" and future
      callers can't skip it. On top of the ask-tier `semodule -i`, not
      instead of it.
- [ ] **Installed modules** - lint approved/installed Atropa modules on page
      load; compliance report gains "Custom SELinux modules" (warn per
      module with Dangerous findings).
- [ ] **Tests** - a should/shouldn't-flag `.te` fixture per rule and per
      category; detection tests from captured AVCs plus unit files; real
      drafts (host pending modules incl. Brave/flatpak, the VM's) as a
      calibration corpus; the backend refusing unacknowledged rules.
- [ ] **Open decisions** - hard block vs loud warning for Dangerous (design
      assumes acknowledge-to-proceed); also lint the Build Policy page's
      modules?; tune the ~25-rule threshold on real modules.

### SELinux pages redesign (design, not built yet)

Today denials and modules are spread over four sidebar entries, and the
same job lives in three places: the SELinux status page has its own denial
list with "Generate .te" and Install, Denial Review has drafts with View
and Install, and Load Policy has Pending/Approved plus an editor. Denial
Review itself is one long scroll of eight groups sorted by classification,
while modules (and now program categories) are per program, and a draft
opens as plain text in a popup with nowhere to show lint findings.

- [ ] **Three entries instead of four**:
  - *SELinux* - configuration only: mode, Setup Mode, relabel, booleans.
    Its own denial list and review buttons go; one row says "N programs
    need attention" and opens Denials.
  - *SELinux: Denials* - replaces Denial Review (below).
  - *SELinux: Modules* - replaces Load Policy: installed Atropa modules
    (with lint badges, so old approvals get checked), pending, approved but
    inactive, "Load .te from disk". Opening any module uses the same
    detail view as Denials, so a hand-loaded `.te` is linted too.
  - *SELinux: Build Policy* stays as it is.
- [ ] **Denials: a list of programs, not of classifications** -
      `Adw.NavigationSplitView`: programs (SELinux domain + executable) on
      the left, the selected program on the right (pushed as a page on a
      narrow window).
  - Top of the list: "Review now" with the source (kernel log / audit.log,
    the latter asking for the password) and filter chips with counts:
    Needs action, Noise, Done.
  - Each row: program name, category, denial count, and one badge for the
    best next step: Dangerous / Review / Boolean / Relabel / Noise / Done.
    Sorted by that badge, then count - impact first.
- [ ] **Program page**, top to bottom:
  - Header: program, domain, executable, systemd unit if any.
  - "What kind of program is this?" - the category toggle buttons, with
    the detected reason under them; changing it re-lints at once.
  - Recommended: the single best route first - boolean (with how many of
    the denials it covers and what else it opens), relabel (`restorecon` /
    `semanage fcontext`), `dontaudit` for noise, and a module only when
    none of those cover it.
  - Draft module: lint findings above the source, each with its badge, a
    plain reason and the one-click safer option; clicking a finding jumps
    to its line. The source is an editable view (GtkSourceView if
    available, a monospace TextView otherwise) with flagged lines tinted
    by severity; edits re-lint after a short pause.
  - Denials: expandable rows with the raw AVC, count, path, already-allowed
    / undefined-class status (the old "Undefined" and "Already allowed"
    groups become per-denial states here, with the existing Help dialog).
  - Bottom bar: Discard, Save for later (goes to Modules > Pending), and
    Install - gated by the linter (Review: confirm listing findings;
    Dangerous: install stays locked until each dangerous finding is ticked
    as understood).
- [ ] **Keep what works** - Setup Mode, the restorecon button, boolean
      "Turn on" with its rule count, the Undefined-class Help dialog and
      the per-domain module naming all move into the new views unchanged.
- [ ] **Smoke test and screenshots** - every new view built under Xvfb in
      `tests/test_ui_smoke.py`, and rendered in the VM against real denials
      before merging.

## Packaging

- [x] Do a full `makepkg -si` with the real `python-build`,
      `python-installer` and `python-pytest` from pacman (done in a fresh
      Arch VM, 2026-10-31).
- [x] Tag releases and add a stable (non-`-git`) PKGBUILD that builds from
      the release tarball (`v0.2.0` + `packaging/arch/atropa/PKGBUILD`).
