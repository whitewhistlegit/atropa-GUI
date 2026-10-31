# Atropa TODO

The target is a single-user Arch desktop or laptop. The background and
reasoning for the existing items are in
[`DOCUMENTATION.md`](DOCUMENTATION.md), section 6.

## Single-user desktop features

Rough priority order. The first three cover most of what breaks on a
single-user Arch machine.

- [ ] **`.pacnew` / `.pacsave` handling** - list them, diff each against the
      live file, and keep, replace or merge. Back up through the existing
      backup mechanism first.
- [ ] **Snapshot before upgrade, with rollback** - Snapper or Timeshift on
      Btrfs: snapshot automatically before a full upgrade or a risky
      change, and offer booting the previous snapshot. (Also an existing
      TODO, below.)
- [ ] **Upgrade checks**
  - [ ] Before: show recent Arch news items that need manual steps.
  - [ ] After: list failed units (`systemctl --failed`).
  - [ ] Say "reboot needed" when the running kernel no longer matches the
        installed one.
  - [ ] Check for the right CPU microcode package (`intel-ucode` /
        `amd-ucode`).
- [ ] **pacman configuration** - rank mirrors with `reflector`, and offer
      toggles for `ParallelDownloads`, `Color` and `[multilib]`.
- [ ] **"What went wrong this boot" page** - errors from this boot, failed
      units and recent crashes (`coredumpctl`), rather than a raw journal
      tail. (Supersedes the plain journal viewer below.)
- [ ] **Firmware updates via `fwupd`** - list devices, refresh metadata,
      apply updates.
- [ ] **Disk encryption and Secure Boot status** - report whether root is on
      LUKS; set up and sign with `sbctl`. Feed both into the security audit
      score.
- [ ] **Disk health and space** - SMART status, enable `fstrim.timer`, and
      cleanup beyond the pacman cache (journal size, `~/.cache`, coredumps).
- [ ] **Power and memory** - `power-profiles-daemon` or TLP, laptop battery
      charge limits, zram swap, sleep/hibernate settings.
- [ ] **Flatpak** - updates and removing unused runtimes, next to the
      pacman page.

### Desktop focus for existing modules

- [ ] **Desktop profile in Security Quick Setup** - when `sshd` isn't
      installed, skip fail2ban and SSH hardening and offer a desktop
      baseline: firewall on with no incoming connections, encryption check,
      Secure Boot.
- [ ] Move **Users & Groups** lower in the sidebar.
- [ ] Frame the **audit score** around how exposed this machine is, rather
      than a CIS enterprise audit.

## Existing TODO (from DOCUMENTATION.md)

- [ ] **`su` restriction to the wheel group** (CIS 6.1.x) - needs a live
      edit of `/etc/pam.d/su`; pair it with PAM-wiring automation.
- [ ] **Bootloader/AppArmor kernel parameter and PAM-wiring automation** -
      lean on the backup mechanism; e.g. keep the previous kernel cmdline as
      a separate boot entry so a bad boot can pick the old one.
- [ ] **Disk/partition management** (explicitly out of scope at project
      start).
- [ ] **Btrfs snapshots / Timeshift integration** (see "Snapshot before
      upgrade" above).
- [ ] **Journal/log viewer** (see "What went wrong this boot" above).
- [ ] **Kernel management** - multiple kernels, `mkinitcpio`, headers. Keep
      a fallback kernel alongside snapshots.

### From the full-repo audit

- [ ] Run the SELinux path once on x86_64 through Atropa: Quick Setup's
      SELinux step through to installed tools, then Get, Build and Install
      on the Build Policy page.
- [ ] Check Restart, the journal dialog and USBGuard's "Turn off" on a
      machine with systemd.
- [ ] Check bootloader detection on a real UEFI machine that boots GRUB
      (relies on GRUB 2.12 writing "GRUB ..." to `LoaderInfo` and on
      `bootctl --print-esp-path` answering there).
- [ ] CI: a GTK smoke test that builds every page under Xvfb, Python
      3.13/3.14 in the matrix next to 3.11/3.12, and parser tests against
      real config files rather than hand-written snippets.
- [ ] **Single privileged helper** - one root helper per operation instead
      of one pkexec prompt per command; agree on the design before any
      code. Move backups to root-owned storage at the same time (anything
      running as the user can currently change a backup in
      `~/.local/share/atropa/backups`).

## SELinux Denial Review

Seen when its generated modules were reviewed in the Arch test VM,
2026-10-31. (The policy findings themselves are tracked outside this repo.)

- [ ] **Suggest `dontaudit` for known noise** instead of an `allow` - e.g.
      `net_admin` for auth helpers like `polkit-agent-helper-1`, and
      nss-systemd's writes to the `io.systemd.Home` / nsresourced sockets.
      Granting these weakens the policy for nothing.
- [ ] **Flag likely mislabeling** - `execute_no_trans` on `lib_t` (and
      similar) almost always means a file is missing its file context, e.g.
      Arch's `/usr/lib/...` helpers where the policy expects `/usr/libexec/`.
      Say "this path probably needs a file context" instead of drafting an
      `allow`.
- [ ] **Flag rules that can't work on their own** - e.g. `sock_file write`
      without `unix_stream_socket connectto`.
- [x] **Skip list hid real denials** - `^(systemd|kernel|audit|kworker|swapper)`
      matched as a prefix, hiding systemd-tmpfiles, systemd-coredump,
      systemd-logind, systemd-homed and auditd: 292 of 1226 denials in one
      enforcing GNOME boot. Now exact names only.
- [ ] **Offer booleans before modules** - when `audit2why` / `audit2allow -b`
      says a boolean would allow the denial, show that first (e.g. SSH logins
      blocked under refpolicy: `ssh_sysadm_login`), with what else the boolean
      opens up.
- [ ] **Check "already allowed" against the whole loaded policy** with
      `sesearch` (setools), not only Atropa's own approved modules - including
      which boolean gates a rule.
- [ ] **Sort by impact, not count** - one boot had 901 `polkitd` denials,
      nearly all nss-systemd noise, on top of everything that actually broke.
      Put recognized noise in its own group.
- [ ] **Name modules after the SELinux domain**, not the process name: `comm`
      is cut at 15 characters, giving `atropa_polkit-agent-he_policykit_auth_t`
      and `atropa__sd-worker__systemd_nsresourced_t`.

## Packaging

- [x] Do a full `makepkg -si` with the real `python-build`,
      `python-installer` and `python-pytest` from pacman (done in a fresh
      Arch VM, 2026-10-31).
- [ ] Tag releases and add a stable (non-`-git`) PKGBUILD that builds from
      the release tarball.
