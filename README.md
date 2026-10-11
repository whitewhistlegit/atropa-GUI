<p align="center">
  <img src="atropa/resources/icons/hicolor/256x256/apps/org.atropa.Atropa.png" alt="Atropa logo" width="180">
</p>

# Atropa

A YaST-inspired system control center for Arch Linux, built with GTK4 and
libadwaita. Atropa runs as your normal user and asks for authentication
(via polkit/`pkexec`) only for the individual actions that need root.

> Developer/internals reference: see [`DOCUMENTATION.md`](DOCUMENTATION.md).

## Features

Each sidebar entry is a module:

| Module | What it does |
|---|---|
| **Package Management** | Pending updates (checked without touching the package database), full system upgrade (live output), search repo + AUR (via `paru`/`yay` if installed), install/remove, orphans, cache cleanup |
| **System** | Hostname, timezone/NTP, locale (incl. `locale.gen`), console keymap and X11 layout |
| **Network** | NetworkManager devices, Wi-Fi, static IP/DHCP (systemd-networkd is detected but read-only) |
| **Users & Groups** | Create/modify/delete users and groups, lock/unlock and set passwords |
| **Services** | systemd units: start/stop/restart/enable/disable, journal tail |
| **Bootloader** | GRUB / systemd-boot detection, entries, timeout |
| **Security Quick Setup** | One-click recommended baseline (firewall, fail2ban, sysctl, faillock, AppArmor, auditd, USBGuard, SELinux permissive), as a checklist or a guided wizard. Can also add the unsigned SELinux package repository, locked behind the administrator password |
| **Security Profiles** | Export this machine's security posture to JSON and import it elsewhere, per-section |
| **Security** | Firewall (ufw or firewalld), SSH hardening with validate-before-reload and automatic rollback, sudoers syntax check |
| **Hardening** | Kernel sysctl hardening, fail2ban, USBGuard, auditd + CIS audit rule sets, login lockout, password complexity, `arch-audit` vulnerability scan, security audit score |
| **Compliance Report** | Categorized, scored report modeled on CIS DIL categories, exportable as Markdown (not an official CIS assessment) |
| **Inventory & Hygiene** | Read-only scans for unneeded network services and account/file hygiene issues |
| **File Integrity** | AIDE baseline/check/timer management (AIDE itself is AUR-only; install it first) |
| **AppArmor** | Profile modes, capability/network rule toggles, denial review with rule suggestions |
| **SELinux** | Status, enforcing/permissive (lock-gated), booleans, denial review, per-application policy drafts |
| **SELinux: Load Policy** | Compile/load `.te` modules, batch-import `.te` files, pending/approved module history |
| **SELinux: Denial Review** | Setup Mode, grouped and classified denials, one-click `restorecon`, policy generation |
| **SELinux: Build Policy** | Build/install/activate a Reference Policy source tree (modular builds); fetches Atropa's own policy on request |
| **Dependencies** | Which external tools each module needs, with install buttons for the ones `pacman` can install |
| **Add-ons** | Enable/disable declarative TOML plugins (see below) |
| **Activity & Backups** | Log of every privileged command, automatic config-file backups with restore, migration from old ArchYaST data |

Every config file Atropa edits is backed up first to
`~/.local/share/atropa/backups/`, and every privileged command is logged to
`~/.local/share/atropa/actions.log`. Changes that can lock you out or end
your session ask first and say what they affect: stopping a service like
the display manager or sshd, locking a password, turning the firewall on,
changing SSH logins.

## Requirements

- Arch Linux (or a derivative with `pacman`)
- Python ≥ 3.11
- `python-gobject`, `gtk4`, `libadwaita`, `polkit`
- Optional, per module: `networkmanager`, `ufw` or `firewalld`, `openssh`,
  `fail2ban`, `apparmor`, `usbguard`, `audit`, `arch-audit`, and
  `pacman-contrib` with `fakeroot` (to check for updates without touching
  the package database).
- Optional, from the AUR: `aide`, and SELinux's userspace tools
  (`policycoreutils`, `checkpolicy`, `semodule-utils`, `selinux-python`).
  The SELinux tools can also come from the
  [archlinuxhardened](https://github.com/archlinuxhardened/selinux) binary
  repository, which Security Quick Setup can add for you. That repository
  is unsigned, so pacman doesn't verify what it installs from it - which is
  why Atropa keeps it locked until you unlock it with the administrator
  password.
- Optional: `git` and `make`, to fetch and build
  [Atropa's SELinux policy](https://github.com/whitewhistlegit/refpolicy-atropa).

The **Dependencies** page shows what's missing.

## Install

```bash
git clone https://github.com/whitewhistlegit/atropa-GUI.git
cd atropa-GUI
./install.sh
```

`install.sh` will:

1. install system dependencies with `pacman` (needs `sudo`), plus `arch-audit` optionally;
2. install Atropa with `pipx install --system-site-packages --force .` so it
   gets its own venv but reuses the system PyGObject;
3. copy the desktop launcher to `~/.local/share/applications/` and its icon
   to `~/.local/share/icons/hicolor/`;
4. install the polkit policy to `/usr/share/polkit-1/actions/`.

Then launch **Atropa** from your app menu, or run `atropa` (open a new
terminal first if `pipx ensurepath` just updated your `PATH`).

To uninstall: `pipx uninstall atropa`, then remove
`~/.local/share/applications/atropa.desktop`,
`~/.local/share/icons/hicolor/*/apps/org.atropa.Atropa.png` and
`/usr/share/polkit-1/actions/org.atropa.pkexec.policy`.

### Run from source

```bash
sudo pacman -S python-gobject gtk4 libadwaita polkit
python3 -m atropa.main
```

## Plugins

Plugins are pure-data TOML manifests. They can only call actions that Atropa
explicitly exposes in `atropa/backend/plugin_registry.py`, and they can
never run arbitrary commands. Manifests live in
`/etc/atropa/plugins/<id>/manifest.toml`, which only root can write. You
enable them from the **Add-ons** page, which asks for authentication, and
the change takes effect on the next launch. See
[`examples/plugins/example-plugin/manifest.toml`](examples/plugins/example-plugin/manifest.toml)
for an annotated example.

## Development

The backend (`atropa/backend/`) has no GTK dependency, so you can lint and
test it anywhere:

```bash
pip install pytest ruff
python3 -m py_compile atropa/*.py atropa/ui/*.py atropa/ui/pages/*.py atropa/backend/*.py tests/*.py
ruff check .
python3 -m pytest -q
```

CI (`.github/workflows/ci.yml`) runs the same three steps on Python 3.11 and
3.12. Architecture, design decisions and the change history are in
[`DOCUMENTATION.md`](DOCUMENTATION.md).

## License

GPL-3.0-or-later — see [`LICENSE`](LICENSE).
