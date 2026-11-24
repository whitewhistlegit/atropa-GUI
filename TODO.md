# Atropa TODO

The target is a single-user Arch desktop or laptop. How things work now is
in [`DOCUMENTATION.md`](DOCUMENTATION.md); the reasoning behind past work,
including the design specs for what was built, is in
[`docs/HISTORY.md`](docs/HISTORY.md).

## Open

### Checks only a real machine can do

- [ ] Boot a grub-btrfs snapshot entry once by hand (the menu entries were
      checked in a VM's `grub-btrfs.cfg`, not booted).
- [ ] Boot the fallback kernel once on real hardware with DKMS (checked in
      a VM's GRUB menu, not booted).
- [ ] Check the two password prompts in a desktop session: two service
      restarts in a row ask once, two group changes ask twice. (Over SSH,
      pkexec's text agent can't authenticate with polkit's socket-activated
      helper, so the tiers were checked by running both helpers via sudo.)
- [ ] Run the SELinux path once on x86_64 through Atropa: Quick Setup's
      SELinux step through to installed tools, then Get, Build and Install
      on the Build Policy page.
- [ ] Run SELinux: Denials "Review now" on an enforcing desktop and check
      the detected program categories (the VM had too few denials).
- [ ] Check Restart, the journal dialog and USBGuard's "Turn off" on a
      machine with systemd.
- [ ] Check bootloader detection on a real UEFI machine that boots GRUB
      (relies on GRUB 2.12 writing "GRUB ..." to `LoaderInfo` and on
      `bootctl --print-esp-path` answering there).
- [ ] Try the systemd-boot paths on a machine that boots it: kernel
      parameters with the kept `atropa-previous-*.conf` entry, and "Add
      boot entry" for a new kernel (unit-tested only).
- [ ] Lid and power-button settings on a laptop (the VM has no lid).

### Code

- [ ] Lint the Build Policy page's modules the way drafts and loaded
      modules are linted.

### Out of scope (decided)

- Disk and partition management.
- Timeshift integration (Snapper covers it).
- Editing `mkinitcpio.conf`, and unified kernel images' `/etc/kernel/cmdline`.
- GRUB reinstall (picking the wrong disk is destructive).

## Done

Single-user desktop features:

- [x] `.pacnew` / `.pacsave` handling (Config Changes)
- [x] Package rollback from the pacman cache (Package History)
- [x] Btrfs snapshots: snapper + snap-pac + grub-btrfs (Snapshots)
- [x] Upgrade checks: Arch news before, failed units / reboot needed /
      microcode after
- [x] pacman.conf toggles, mirror ranking, Flatpak
- [x] Boot Report (errors, failed units, crashes from this boot)
- [x] Firmware updates (fwupd), Disk Health, Encryption & Secure Boot
- [x] Power: profiles, charge limits, zram; lid, power button and
      hibernate delay through logind/sleep drop-ins
- [x] Kernels: installed kernels, fallback kernel, headers for DKMS, boot
      entries, leftover module folders
- [x] Kernel parameters with a kept boot entry (GRUB `custom.cfg`,
      systemd-boot `atropa-previous-*.conf`)
- [x] Desktop profile in Security Quick Setup; exposure-framed audit score

Security:

- [x] `su` restricted to wheel; pam_pwquality wiring
- [x] Privileged helper: validator per command, two tiers (keep / ask),
      helper-performed file writes, root-owned backups made on write
- [x] SELinux: Denials by program with the best next step, judged denials
      (loaded policy, booleans, noise, label hints), per-domain drafts
- [x] SELinux module linter with program categories and an
      acknowledge-to-install gate; fails closed on anything it can't read
- [x] SELinux pages redesign: Denials, Modules, one module view

Tests and packaging:

- [x] CI on Python 3.11-3.14 plus a GTK smoke test under Xvfb
- [x] Parser tests against Arch's stock config files
- [x] `atropa-git` and tagged-release PKGBUILDs, tested with a full
      `makepkg -si` in a fresh Arch VM
