# Atropa — Technical Documentation

This is the full technical reference for the project, written so a new session
(with no prior context) can pick up development without re-deriving anything
from the code. `README.md` is the user-facing quickstart; this file is the
internals reference — architecture, every function's contract, design
decisions and *why* they were made, bugs already hit and fixed, and what's
still on the TODO list.

Current size: **~12,500 lines of Python across 23 backend modules and 22 UI
pages, plus a 727-test pytest suite (~7,800 lines).** No GTK4/libadwaita is
available in the dev sandbox this was built in, so UI code is verified via
`py_compile` + `ruff` + the backend test suite, and visually only when the
user runs a build on bare-metal Arch (see "Testing approach" below).

---

## 1. Architecture

```
atropa/
  main.py                     GTK4 + libadwaita Adw.Application entry point (app ID org.atropa.Atropa)
  ui/
    main_window.py             Adw.NavigationSplitView sidebar + Gtk.Stack of pages;
                               MODULES list = sidebar order; lazy page construction
    pages/
      __init__.py               BasePage (shared scaffolding) + esc() markup helper
      packages.py, system_config.py, network.py, users.py, services.py,
      bootloader.py, quicksetup.py, profiles.py, security.py, hardening.py,
      compliance.py, inventory_hygiene.py, aide_page.py, apparmor.py,
      selinux.py, selinux_load.py, selinux_review.py, refpolicy_build.py,
      dependencies.py, addons.py, activity.py
                                 one file per built-in sidebar entry
      plugin_page.py            generic page rendered from a plugin manifest
  backend/
    privilege.py                run_(un)privileged[_streaming] + backup/restore/log
    pacman.py, system_config.py, network.py, users.py, services.py,
    bootloader.py, security.py, hardening.py, audit_rules.py, apparmor.py,
    selinux.py, refpolicy_build.py, aide.py, inventory.py,
    account_hygiene.py, compliance.py, quicksetup.py, profiles.py,
    dependencies.py, plugins.py, plugin_registry.py, migration.py
                                 all GTK-free, pure subprocess wrappers
  resources/
    atropa.desktop            app launcher
    icons/hicolor/<N>x<N>/apps/org.atropa.Atropa.png
                              the logo as the app icon, 16 to 256 px
    org.atropa.pkexec.policy  polkit policy for nicer auth prompts
tests/                          pytest suite, one test_<module>.py per backend module
                                (plus test_resources.py for the app icon)
examples/plugins/example-plugin/manifest.toml   reference plugin manifest (parsed by a test)
install.sh                      Arch installer (pacman deps + pipx + launcher + icon + polkit policy)
.github/workflows/ci.yml        py_compile + ruff + pytest on Python 3.11/3.12
```

Sidebar order (from `MODULES` in `main_window.py`): Package Management,
System, Network, Users & Groups, Services, Bootloader, Security Quick Setup,
Security Profiles, Security, Hardening, Compliance Report, Inventory &
Hygiene, File Integrity, AppArmor, SELinux, SELinux: Load Policy, SELinux:
Denial Review, SELinux: Build Policy, Dependencies, Add-ons, Activity &
Backups — followed by one entry per enabled plugin.

### Why the backend/ui split exists
`backend/*.py` has **zero GTK imports**. Every function is a plain Python
wrapper around a `subprocess` call (via `privilege.py`), returning either a
`CommandResult` dataclass or a typed dataclass of parsed data. This means:
- Every backend function is independently testable by faking the one
  function that starts commands (`privilege._subprocess_run`) — no display
  server, no GTK, no root needed.
- `ui/pages/*.py` never shells out directly; it only calls into `backend/`.

### Privilege model
The app runs as a normal user, never as root. `backend/privilege.py` is the
**only** place that escalates:

```python
run_unprivileged(argv, input_text=None, timeout=120)   # current user
run_privileged(argv, input_text=None, timeout=600)     # via pkexec (falls back to sudo -A)
```

`run_privileged` prepends `pkexec` to the argv and shells out — this pops a
**native polkit auth dialog** scoped to that one command; there's no
persistent root session and no setuid binary.

**The shipped polkit policy is not actually in effect.** `resources/org.atropa.pkexec.policy`
declares an `org.atropa.pkexec.run` action with `allow_active = auth_admin_keep`,
but pkexec only switches to a custom action when it carries an
`org.freedesktop.policykit.exec.path` annotation naming the program being run
(pkexec(1)). This one has none, so every call uses the generic
`org.freedesktop.policykit.exec` action, which asks for the password every time -
one prompt per privileged *primitive* (`sed`, `tee`, `systemctl`, ...), not per
operation. The planned fix is a single privileged helper invoked once per
operation; annotating generic binaries like `tee`/`bash` with `auth_admin_keep`
is not a safe shortcut (it would make them passwordless root for the keep window).

**Timeouts hold, even for a child that runs as root.** Commands start in
`privilege._subprocess_run()`, which has `subprocess.run()`'s interface but
runs through `Popen`. At a timeout `subprocess.run()` kills the child and
then waits for it with no limit - and a child `pkexec` started runs as
root, so the kill raises `PermissionError` and that wait never returned,
hanging the worker thread for good. Such a child is now left running and
reported: `PrivilegeError` names its PID. The streaming runners read output
on a separate thread, so their timeout counts while the command runs
instead of after it has closed its output.

**Every subprocess call uses an argv list, never `shell=True`** — this is a
hard rule across the whole codebase, to avoid shell-injection from anything
user-supplied (package names, hostnames, usernames, etc.) ending up
interpreted by a shell. There are no exceptions left: nothing in the
backend runs `bash -c` any more. Root-owned files are written with `tee`
(or `tee -a`, or `install -m` when the file needs a particular mode) with
the content on stdin. The redirections that used to need a root shell -
USBGuard's `generate-policy > rules.conf` and the append-if-missing
branches for `sshd_config`, `faillock.conf` and `pwquality.conf` - are gone.

**Every command is logged** — privileged *and* unprivileged — to
`~/.local/share/atropa/actions.log` by `privilege._run()` (Python
`logging`: `RUN: <argv>`, `RUN (streaming, privileged|unprivileged): ...`,
`FAILED (<rc>): <stderr>`, plus backup/restore events). Browsable in the
Activity & Backups page.

### Backup-before-edit mechanism (added in the hardening pass)
Any function that edits an **existing** config file calls
`privilege.backup_file(path)` first:

```python
def backup_file(path: str) -> str | None:
    """Returns the backup's filename (not full path), or None if path doesn't exist yet."""
```

Backups land in `~/.local/share/atropa/backups/<name>.<timestamp>.bak`,
with a JSONL manifest (`manifest.jsonl`) recording `{timestamp, original_path,
backup_file}`. `list_backups()` and `restore_file(backup_file_name,
original_path)` (writes it back via `tee`, privileged) power the Activity &
Backups page's restore button. The manifest sits in the user's home, where
any program they run can add entries, so `restore_file()` only writes to
paths `restorable()` accepts: the files listed below, profiles under
`/etc/apparmor.d/`, and `loader/loader.conf` on the ESP. `list_backups()`
marks each entry `restorable`, and the page disables Restore for the rest.

**Functions currently wired to call `backup_file()` before editing:**
| Function | File | What it edits |
|---|---|---|
| `_set_sshd_option` | `security.py` | `/etc/ssh/sshd_config` |
| `apply_sysctl_hardening` | `hardening.py` | `/etc/sysctl.d/99-atropa-hardening.conf` |
| `fail2ban_protect_ssh` | `hardening.py` | `/etc/fail2ban/jail.d/sshd.local` |
| `set_faillock_policy` | `hardening.py` | `/etc/security/faillock.conf` |
| `set_password_complexity_policy` | `hardening.py` | `/etc/security/pwquality.conf` |
| `usbguard_generate_and_enable` | `hardening.py` | `/etc/usbguard/rules.conf` |
| `set_timeout` | `bootloader.py` | `/etc/default/grub`, or systemd-boot's `loader/loader.conf` on the ESP |
| `set_mode` | `selinux.py` | `/etc/selinux/config` |
| `activate` | `refpolicy_build.py` | `/etc/selinux/config` (`SELINUXTYPE=`) |
| `set_locale_gen_enabled` | `system_config.py` | `/etc/locale.gen` |
| `append_rule_to_profile` / `_set_rule_presence` | `apparmor.py` | an AppArmor profile file |

**SSH gets an extra safety step beyond backup**: `_set_sshd_option` runs
`sshd -t` to validate the new config *before* reloading anything. If
validation fails, the original text - held in memory, so this doesn't depend
on the backup - is written back and sshd is **never** reloaded; the error
says plainly if even the write-back failed. The reload is `systemctl
try-reload-or-restart sshd`, a no-op when sshd isn't running (plain `reload`
failed there and reported the change as an error). Verified end-to-end with
a real (mocked) broken-config scenario, see Testing section.

**The same write-back-on-failure pattern** covers the other edits that can
leave a broken system behind: an AppArmor profile `apparmor_parser -r`
rejects, a GRUB timeout change after which `grub-mkconfig` fails, and a
refpolicy activation whose relabel can't be scheduled. Each puts the
previous content back and says so, or says plainly that the write-back
failed too.

### Markup-escaping (a real bug we hit and fixed)
`Adw.ActionRow`/`PreferencesGroup` titles/subtitles and `Adw.Toast` messages
all render as **Pango markup**, not plain text. Any raw `&`, `<`, `>` in
dynamic content (usernames, package descriptions, SSIDs, GECOS full names —
which historically often contain literal `&`) breaks markup parsing, and GTK
**silently renders blank text** instead of erroring. This is exactly what
caused a real user-reported bug ("Users tab shows no letters").

Fix, in `ui/pages/__init__.py`:
```python
def esc(text: object) -> str:
    """GLib.markup_escape_text wrapper; use on every dynamic title/subtitle."""
```
- `BasePage.notify()` auto-escapes (every `self.notify(f"...{error}...")` call
  across the app is safe without touching each call site)
- `BasePage.add_group()` and `BasePage.start_loading()` escape their title,
  description and message too - a plain `&` in a group title ("Account &
  File Hygiene") rendered it blank
- `BasePage.confirm()` disables markup entirely on the dialog (`heading`/`body`
  often embed raw package/user names via f-strings)
- Plain-text widgets go the other way: a `Gtk.Label` or button label that
  isn't markup must **not** be escaped, or it shows literal `&amp;`
- Every `Adw.ActionRow(title=..., subtitle=...)` built from live system data
  wraps the dynamic parts in `esc()` — this was done file-by-file across
  every page; if you add a new row with dynamic content, wrap it in `esc()`.

---

## 2. Module-by-module reference

### `privilege.py` (foundation, not a sidebar page)
```python
CommandResult(returncode, stdout, stderr)          # .ok property = returncode == 0
run_unprivileged(argv, input_text=None, timeout=120) -> CommandResult
run_privileged(argv, input_text=None, timeout=600)   -> CommandResult   # via pkexec, else sudo -A, else PrivilegeError
run_privileged_streaming(argv, on_line, input_text=None, timeout=1800)   -> CommandResult   # live line-by-line output
run_unprivileged_streaming(argv, on_line, input_text=None, timeout=1800) -> CommandResult   # same, no escalation
path_exists(path) -> bool | None                     # None = can't tell
backup_file(path) -> str | None                      # filename only, not full path
restorable(path) -> bool                             # one of the files Atropa backs up?
restore_file(backup_file_name, original_path) -> CommandResult   # PrivilegeError unless restorable()
list_backups(limit=200) -> list[dict]                # most-recent-first, each with a "restorable" flag
get_recent_actions(limit=200) -> list[str]           # most-recent-first tail of actions.log
```
A timeout raises `PrivilegeError` (see "Timeouts hold" in section 1); the
streaming runners return everything in `.stdout`, with `.stderr` always empty.
`path_exists()` is there because `Path.exists()` raises `PermissionError` on
Python 3.11-3.13 when a directory on the way isn't searchable - a root-only
ESP, a 0700 `/var/lib/aide`. `backup_file()` treats "can't tell" as "try the
privileged read" rather than crashing.

### Packages (`pacman.py` / `pages/packages.py`)
- `Package(name, version, installed=True, description="", repo="")` — `repo`
  is `"core"`, `"extra"`, ... or `"aur"`
- `PendingUpdate(name, old_version, new_version)` — parsed via regex
  `^(\S+)\s+(\S+)\s*->\s*(\S+)`, correctly stops before an `[ignored]`
  suffix (IgnorePkg-held packages)
- `check_updates() -> list[PendingUpdate]` — the "Check for updates" button.
  Uses `checkupdates` (pacman-contrib; it needs `fakeroot`) when
  `live_update_check_available()`: it syncs a private copy of the database,
  so it needs no root and leaves the real one alone. Exit status 2 is its
  "no updates"; any other failure raises instead of reading as "up to
  date". Without it the list falls back to `pacman -Qu`, which only knows
  what the last full upgrade's sync saw, and the page says so.
- **No partial upgrades.** Nothing runs `pacman -Sy`: the old "Refresh
  database" button left the sync database newer than the installed
  packages, which turns every later `pacman -S` - this page's own Install
  included - into the partial upgrade Arch doesn't support. `sync_database()`
  and `update_single_package()` ("Update only this") are gone with it.
  `install(names)` runs `pacman -S --needed` and raises `PartialUpgradeError`
  when `_behind_local_database()` finds the database already ahead
  (something else ran `-Sy`); the page then offers "Upgrade and install",
  `upgrade_and_install_streaming(names, on_line)` = `pacman -Syu --needed
  <names>`, the Arch wiki's way.
- `search(query, include_aur=True)` merges official repo (`pacman -Ss`) with
  AUR helper results if `paru`/`yay` is installed (checked in that priority
  order). AUR results carry `repo="aur"`; the page marks them "AUR" and
  points at the helper instead of offering an Install button that would run
  `pacman -S` and fail with "target not found".
- `upgrade_system_streaming(on_line)` — the `-Syu` used by the UI, streamed
  into a live progress dialog
- `remove(names, purge_config=False)`, `upgrade_system`, `clean_cache`,
  `list_installed`, `list_explicit`, `list_orphans` — straightforward pacman
  wraps (`list_orphans()` has no caller yet, see the open items in section 6)

### Network (`network.py` / `pages/network.py`)
NetworkManager (`nmcli`) only — systemd-networkd is detected
(`backend_available()` returns `"networkmanager" | "networkd" | "none"`) but
**read-only**, no write support yet (noted as a known limitation).
- `list_devices`, `list_wifi(rescan=False)`, `connect_wifi(ssid, password=None)`
  (the password goes to `nmcli --ask` on **stdin**, never argv - see the
  last bug-fix entry in section 6),
  `disconnect`, `set_static_ip(connection_name, ip_cidr, gateway, dns)`,
  `set_dhcp`, `toggle_networking`

### Users & Groups (`users.py` / `pages/users.py`)
Reads `/etc/passwd`/`/etc/group` directly via `pwd`/`grp` modules (unprivileged,
always accurate); writes via `useradd`/`usermod`/`userdel`/`groupadd`/`groupdel`.
`DEFAULT_MIN_UID = 1000` filters out system accounts by default.
- `list_users(include_system=False)` / `list_groups(include_system=False)`
  (root/UID 0 is always included), `create_user`, `modify_user` (full name,
  shell, extra groups, lock/unlock), `delete_user(remove_home=False)`,
  `create_group`, `delete_group`
- `set_password` pipes `user:pass` to `chpasswd` via **stdin**, never argv
  (argv would leak into `ps` output)
- Guards for the one-click changes that can't be undone from Atropa:
  `lock_refusal(username)` refuses the account you're signed in with, and
  root when nobody is in `ADMIN_GROUP` (`wheel` - polkit then asks for
  root's password); `lock_warning(username)` says what else locking breaks
  (the only wheel member, an administrator); `delete_refusal(username)`
  refuses your own account and root. The page asks before locking, has an
  unlock button, disables what's refused, and its delete dialog offers
  "Delete" or "Delete with home folder".

### Services (`services.py` / `pages/services.py`)
`systemctl`/`journalctl` wraps: `list_services(pattern="*.service")`,
`status`, `start`, `stop`, `restart`, `enable(unit, now=False)`,
`disable(unit, now=False)`, `journal_tail(unit, lines=100)`.
`list_services()` fills in `Service.enabled` from one `systemctl show
--property=Id,UnitFileState` call for every unit - it used to run
`systemctl is-enabled` per service, hundreds of commands per refresh, each
one a line in the Activity log. `stop_impact(unit)` returns what stopping or
disabling a unit breaks (polkit, D-Bus, logind, the display manager,
networking, sshd, the firewall, auditd, ...); the page shows it in the
confirmation it asks before stop and disable. The page renders at most
`MAX_ROWS = 150` services and says when the list is cut short.

### Bootloader (`bootloader.py` / `pages/bootloader.py`)
Auto-detects GRUB vs systemd-boot (`detect()`). The loader that started this
boot names itself in the `LoaderInfo` EFI variable (`_loader_info()`), and
that settles it: "systemd-boot ..." with `bootctl` installed is
systemd-boot, "GRUB ..." with `/etc/default/grub` and `grub-mkconfig` is
GRUB. It goes by the name, not by the variable existing - GRUB sets it too
since 2.12 (its `bli` module). When no loader says (a BIOS boot, an older
GRUB), it goes by what's installed: GRUB first, since systemd-boot would
have said, then systemd-boot when `bootctl` is installed and `loader/` on
the ESP or XBOOTLDR has a `loader.conf` or an `entries` directory. An ESP
by itself decides nothing - every UEFI machine has one, the ones that boot
GRUB included.

The ESP isn't assumed to be under `/boot`: `esp_path()` asks `bootctl
--print-esp-path` and falls back to the first of `/efi`, `/boot`,
`/boot/efi` that has a `loader/` directory. Entries are also read from
XBOOTLDR (`bootctl --print-boot-path`), and a root-only ESP (`umask=0077`)
is read with one privileged `grep -rH` instead of crashing. `get_info()`
returns a `BootloaderInfo(kind, entries, default_timeout)`.

`set_timeout` backs the file up and edits it by content (`_with_setting()`):
every active line for the key is replaced, else the first commented-out one
is restored, else the line is added. The old `s/^timeout.*/` changed nothing
when the line was commented out - which is how `loader.conf`'s example
ships it - or missing. For systemd-boot it also clears the
`LoaderConfigTimeout` EFI variable (`bootctl set-timeout ""`) when present:
a timeout picked in the boot menu is stored there and overrides
`loader.conf`. For GRUB it then regenerates `/boot/grub/grub.cfg` — if
`grub-mkconfig` fails, the previous `/etc/default/grub` is written back
directly. `regenerate_config()` runs
`grub-mkconfig -o /boot/grub/grub.cfg` or `bootctl update`. **`reinstall()` deliberately refuses to automate GRUB
reinstall** — picking the wrong disk/EFI target is destructive; it raises
`RuntimeError` pointing at manual `grub-install` instead. systemd-boot reinstall
(`bootctl install`) is safe enough to automate since there's no disk target
ambiguity.

### Security (`security.py` / `pages/security.py`)
Firewall abstraction over `ufw` **or** `firewalld` (whichever is installed;
`firewall_backend()` returns `"ufw" | "firewalld" | "none"`). SSH hardening
(`set_ssh_root_login`, `set_ssh_permit_root_login`, `set_ssh_password_auth`,
`set_ssh_port`, plus the CIS settings `set_ssh_log_level` (INFO/VERBOSE
only), `set_ssh_x11_forwarding`, `set_ssh_max_auth_tries`,
`set_ssh_ignore_rhosts`, `set_ssh_hostbased_authentication`,
`set_ssh_permit_empty_passwords`, `set_ssh_permit_user_environment` — all
route through `_set_sshd_option`, which has the backup, `sshd -t` validation
and write-back logic described above).

Reading and editing `sshd_config` both follow sshd's own rules: the first
value read for a keyword wins (`Port` and `ListenAddress` accumulate
instead), `Include` files are read where they appear, and nothing after a
`Match` line applies globally until `Match all` (a `Match` inside an
included file ends with that file). Reading only the main file and letting
the last line win reported settings sshd wasn't using.
- `ssh_status() -> SshStatus` reports the global values sshd reads.
  `effective(name)` fills in OpenSSH's own default for a keyword that's
  never set (`SSHD_DEFAULTS`: unset `PasswordAuthentication` means password
  login is on), `ports` lists every port sshd listens on, and
  `unreadable_includes` names included files that couldn't be read - the
  audit judges effective values and won't award a pass when there are any.
- `_edit_sshd_global_option()` is a Python read-modify-write of the global
  section only, never a line inside a `Match` block: replace the first
  active line, else uncomment the template, else insert before the first
  `Include`/`Match`. The line goes above an `Include` that could override
  it, later dead duplicates are rewritten to match, and "set the port" is
  refused when several `Port` lines (or an included file) set it.
- The Security page's switches show effective values and re-read
  `sshd_config` after every attempt. Root login is a choice between sshd's
  actual values, so going from "no" to the `prohibit-password` default no
  longer passes through "yes".

`firewall_status()` reads `ufw status verbose` / `firewall-cmd --list-all`
**privileged** (both silently return empty output without root);
`firewall_allow_port`/`firewall_deny_port(port, protocol="tcp")` (on a stopped
firewalld these go through `firewall-offline-cmd`, since `firewall-cmd` needs
the daemon). `sudoers_check() -> CommandResult` runs `visudo -cf /etc/sudoers`
**privileged** - sudoers is 0440 root:root, so unprivileged visudo can only
report "Permission denied" - read-only, syntax-check only; callers go by `.ok`.

### Hardening (`hardening.py` / `pages/hardening.py`)
The "basic toggle" layer — NOT the deep AppArmor/SELinux pages (those are
separate, richer modules; see below). Covers:
- **Kernel sysctl hardening**: 20 curated settings in `SYSCTL_RECOMMENDATIONS`
  (ASLR, ptrace restriction, anti-spoofing, SYN cookies, hardlink/symlink
  protection, etc.), checkbox-select which to apply, written to a dedicated
  `/etc/sysctl.d/99-atropa-hardening.conf` (never mixed with user's own
  config). Status is read live: `get_sysctl_status()` runs `sysctl -n` per
  key, and `SysctlSetting.is_hardened` is also true for a value stricter
  than the recommendation (`_STRICTER_SYSCTL_VALUES`: `ptrace_scope` 2/3,
  `sysrq` 0). `apply_sysctl_hardening(keys)` leaves such values alone
  instead of lowering them. The audit goes by `sysctl_hardening_gaps()` -
  the recommended keys not in effect right now - not by whether Atropa's
  file exists: a later file can override it, and the same settings can come
  from somewhere else.
- fail2ban (enable/disable, one-click "protect SSH" jail)
- AppArmor **service-level only** here (`apparmor_status`/`apparmor_enable_service`).
  `apparmor_kernel_enabled()` asks the kernel - the active LSM list in
  `/sys/kernel/security/lsm`, falling back to AppArmor's own
  `/sys/module/apparmor/parameters/enabled` - instead of looking for
  `apparmor=1` in `/proc/cmdline`, which never matched the `lsm=` parameter
  the Arch wiki recommends. The guidance shown is that parameter
  (`APPARMOR_KERNEL_PARAMETER`); it is deliberately not added automatically
  (bad kernel params risk an unbootable system)
- USBGuard — `usbguard_generate_and_enable()` **always generates a policy from
  currently-plugged-in devices before enabling enforcement**; enabling blind
  would block the next USB replug including your own keyboard. The policy is
  generated first and written only if it has rules (the old
  `generate-policy > rules.conf` emptied the file before generating, so a
  failure left a policy that blocks every device). The previous file is
  backed up, the new one is installed with mode 0600 (`usbguard-daemon`
  refuses any other), and a daemon that was already running is restarted so
  it loads it. `usbguard_status().extra["has_policy"]` is `None` when
  `/etc/usbguard` can't be looked into
- CIS audit rule sets (`audit_rules.py`): `active_rule_set_keys()` reads the
  loaded rules with **one** privileged `auditctl -l` for every set - the
  page used to run one per set, five password prompts on opening it - and
  matches keys as whole tokens. `apply_all_rule_sets()` does one `mkdir -p`
  and one `augenrules --load`
- auditd, `vulnerability_scan()` (via `arch-audit`), login lockout
  (`faillock_status`/`set_faillock_policy` — **only touches
  `/etc/security/faillock.conf`**, never auto-wires `pam_faillock` into the PAM
  stack itself, since a bad PAM edit can lock out every account with no easy
  recovery outside a live USB). `faillock_wired_into_pam()` /
  `pwquality_wired_into_pam()` follow `include`/`substack`/`@include` and ignore
  comments - on Arch, `system-login` only includes `system-auth`, which is
  where pambase wires faillock in; pwquality also checks the `passwd` service.
  A key that isn't in `faillock.conf`/`pwquality.conf` yet is appended with
  `tee -a` and the line on stdin (`_append_line()`), not a root shell.
  `vulnerability_scan()` raises when `arch-audit` itself fails (e.g. offline)
  rather than returning an empty "nothing vulnerable" list.
- `run_audit() -> list[AuditCheck]` — rollup pass/warn/fail/info across all of
  the above plus firewall/SSH from `security.py` plus SELinux status; powers
  the "Security Audit" score section

### Compliance Report (`compliance.py` / `pages/compliance.py`)
Categorized, scored security-posture report built **on top of**
`hardening.run_audit()` plus two extra checks (login lockout, sudoers) -
never duplicates detection logic, only re-labels/aggregates it. Explicitly
**not** a real CIS Benchmark assessment or compliance certification -
`DISCLAIMER` says so, and every markdown/file export carries it too, since
an enterprise reader handing this to an auditor needs to see the caveat on
the artifact itself, not just in a docstring. `generate_report()` also
folds in `inventory.scan_all()` and `account_hygiene.scan_all()` as two
more categories ("Service Inventory", "Account & File Hygiene") - those
go straight into their own categories rather than through
`_CATEGORY_MAP`, since their check names are per-entry/per-account (one
row per installed service, one per user's home directory) rather than the
fixed small set `_CATEGORY_MAP` was built for. The header's total
(`total_check_count`) counts every check in the report; it used to count
only `run_audit()`'s, so it could read "29 scored checks, 3 total".

### File Integrity / AIDE (`aide.py` / `pages/aide_page.py`)
CIS DIL Phase 3 - see the Phase 3 write-up in section 6 for the full
scoping rationale (AUR-only trust boundary, timer-detection-not-
duplication). No `install()` function on purpose.
- `is_installed()` / `baseline_initialized()` / `detect_timer_unit()` /
  `get_status()` - read-only detection, all unprivileged.
  `baseline_initialized()` returns `None` - "can't tell without root" -
  when `/var/lib/aide` isn't searchable (it's often 0700) instead of
  raising, and promoting a fresh baseline doesn't call a successful
  `--init` a failure just because the new database can't be seen from here.
- `initialize_baseline(on_line)` / `update_baseline(on_line)` - same
  mechanism (`aide --init` + promote), two names for two different human
  intents. `run_check(on_line)` - `aide --check`, parse via
  `parse_check_summary(output, returncode)`. AIDE prints its "Summary:"
  block only when it found differences, so a clean run is recognized from
  its own "found NO differences" message or exit status 0; otherwise
  `None` (never a fabricated `0/0/0`) when there's no report at all.
  All three stream through `run_streaming_operation()` - a full-tree walk
  can take minutes.
- `enable_timer(unit)` / `disable_timer(unit)` - operate on whatever
  `detect_timer_unit()` found, never a hardcoded name.
- UI's "Update baseline" action requires an explicit `self.confirm()`
  with copy stating it accepts everything currently reported as normal -
  deliberate friction, not an oversight.

### Service Inventory & Account Hygiene (`inventory.py` + `account_hygiene.py` / `pages/inventory_hygiene.py`)
CIS DIL Phase 2 - see the Phase 2 write-up in section 6 for the full
rationale (especially why CIS's server/client 2.2/2.3 split doesn't map
onto Arch's actual packaging). Both read-only, no fix actions on the page.
- `inventory.CATALOG` - 16 special-purpose services (avahi, cups, dhcp,
  openldap, nfs, bind, vsftpd, httpd/nginx, dovecot, samba, squid, snmpd,
  rsyncd, xinetd, legacy inetutils telnet/rsh/talk). `scan_entry()` →
  `pass` (not installed) / `warn` (installed, inactive) / `fail`
  (installed AND actively listening).
- `account_hygiene.scan_all()` - file perms (passwd/group/shadow/gshadow),
  duplicate UID/GID/username/groupname, stray UID-0 accounts, system
  accounts with a login shell, home directory ownership/perms, empty
  shadow password fields (privileged read, hash itself never surfaced),
  root `PATH` integrity (checked against `/root/.bash_profile`,
  `/root/.bashrc`, `/etc/profile` directly - **not** `pkexec`'s own
  environment, which is a fixed sanitized `PATH` that would make this
  check trivially pass regardless of root's real shell config). Root's two
  files are read with one privileged `cat`, and whatever it printed is kept
  even when `cat` exits 1 because one of them is missing, as on a fresh
  install. If the privileged read itself fails (prompt dismissed), the
  result is `info` with the reason, not a pass.

### Custom Reference Policy build (`refpolicy_build.py` / `pages/refpolicy_build.py`)
Builds/installs/activates a user-maintained refpolicy fork (e.g. Arch-
specific paths/contexts fixed upstream) - never an AUR package build,
that stays the existing "install it yourself first" posture. Only
handles `MONOLITHIC = n` (modular) source trees - detected from the
target set used, not auto-sensed from `build.conf`.
- `build(source_dir, on_line)` - `make conf all`, unprivileged, via the
  newly-added `run_unprivileged_streaming()` in `privilege.py`.
- `install(source_dir, on_line)` - `make install load`, privileged. Plain
  `make install` only copies the module packages and context files in a
  modular build; `load` is what has `semodule` build NAME's own policy
  store and write the compiled policy (`/etc/selinux/NAME/policy/policy.NN`)
  a boot into NAME loads. Does not touch `/etc/selinux/config`, so the
  running system stays on its current policy. Because `make` runs as root
  inside the user's source tree, the files it creates there are handed back
  afterwards (`chown -R -h --from=0:0`, symlinks not followed) - left
  root-owned they broke the next unprivileged Build. The confirmation says
  plainly that the tree's Makefile runs as root.
- `activate(policy_name, default_login_seuser="unconfined_u")` - refuses up
  front unless the name is a plain one (`_POLICY_NAME_RE`) and
  `/etc/selinux/NAME/policy` holds a compiled policy: `SELINUXTYPE` pointing
  at a missing policy leaves an enforcing system unable to boot. Then, in
  order: maps the `__default__` login in the **new** policy's own store
  (`semanage login -S NAME -N`, `-a` then `-m` if already mapped), so a
  failure there changes nothing; sets `SELINUXTYPE=` by content (backed up
  first, adding the line when there is none); schedules a relabel via
  `selinux.relabel_filesystem()`, putting the previous config back if that
  fails. Returns one `CommandResult` per step; stops on first failure.
  Never touches kernel boot params or triggers a reboot - both stay the
  user's explicit, separate, manual next step.

### AppArmor (`apparmor.py` / `pages/apparmor.py`)
The **dedicated** AppArmor module (richer than `hardening.py`'s basic toggle).
- `list_profiles()` parses `aa-status` (regex `^\d+\s+profiles are in (\w+)
  mode`, stops before the "processes" section which duplicates entries with
  PIDs — verified against realistic synthetic output)
- `set_profile_mode(profile_path, mode)` — `mode` is `"enforce"|"complain"|"disable"`,
  maps to `aa-enforce`/`aa-complain`/`aa-disable`
- **Real category toggles** — `COMMON_CAPABILITIES` (net_admin, sys_ptrace,
  dac_override, setuid, setgid, ...) and `COMMON_NETWORK_RULES` (`"inet
  stream"`, `"inet6 dgram"`, `"unix stream"`, ...) are genuine single-line
  AppArmor rules, so on/off is unambiguous. `set_capability_rule`/
  `set_network_rule` → `_set_rule_presence()` adds/removes the exact line,
  idempotently (verified: toggling on twice doesn't duplicate, toggling off
  removes only the target line and leaves everything else in the profile
  intact), then reloads via `apparmor_parser -r`. When the parser rejects
  the result, `_write_and_reload()` writes the previous content back - the
  kernel keeps the profile it already had loaded, and the broken file would
  otherwise sit on disk for the next boot or reload to trip over.
  `append_rule_to_profile()` ("Append & Reload") goes through the same path.
- `resolve_profile_file(identifier)` — profile files are conventionally named
  by replacing `/` with `.` (e.g. `/usr/bin/firefox` → `usr.bin.firefox`),
  with a `grep -rl` fallback for child profiles/hats/named profiles
- **Denial review**: `list_denials()` reads `apparmor="DENIED"` lines from
  `journalctl -k`. That's only complete while auditd isn't running: once it
  is, the kernel hands audit records to auditd instead of printing them. So
  the page says when `auditd_running()` and offers a second source,
  `list_denials_from_audit_log()` (privileged `ausearch -m
  AVC,APPARMOR_DENIED -ts boot --input-logs`), which raises on a failed read
  instead of showing "no denials". **There's no `audit2allow` equivalent for AppArmor** —
  `generate_rule_suggestion()` builds a best-effort rule directly from the
  denial's own fields:
  - file access: `name=` + `requested_mask=` → `<path> <mask>,`
  - capability: `capname=`/`capability=` → `capability <cap>,`
  - network: `family=` + **`sock_type=`** → `network <family> <sock_type>,`
    — ⚠️ **bug already caught and fixed**: an earlier version extracted
    `protocol=` instead of `sock_type=`, which happened to pass its own test
    because the test used a made-up `protocol="tcp"` field. Real AppArmor
    network denials carry `sock_type=` (stream/dgram), and the actual rule
    grammar is `network <family> <sock_type>,` not `<family> <protocol>,`.
    Fixed and re-verified against the corrected field.
  - `explain_denial()` just formats the denial's fields as readable text
    (no separate explain tool exists, unlike SELinux's `audit2why`)

### SELinux (`selinux.py` / `pages/selinux.py` + `pages/selinux_load.py`)
Two pages: the main SELinux page (status, booleans, denial review,
per-application batch review) and a separate **Load Policy** page (paste/load/compile/install
arbitrary `.te` text, manage loaded + pending + approved-history modules).

- `get_status()` parses `sestatus` (verified against the actual user's real
  output on a system running `refpolicy-arch`, an AUR SELinux policy for
  Arch — note this means the boolean list will be **much sparser** than
  Fedora/RHEL's targeted policy, since fewer people have written per-app
  policy modules for it). Installed tools aren't an enabled SELinux: when
  `sestatus` says "disabled", the result is `available=False` with mode
  `"disabled"`, which is what every caller already took "available" to
  mean - it used to come back available with mode "unknown", and Quick
  Setup then ran `setenforce` on a disabled SELinux. The page says the
  tools are installed but SELinux is off.
- `SELINUX_TOOL_PACKAGES` names the package behind each tool Atropa runs -
  all AUR-only on Arch: `checkmodule` is in `checkpolicy`,
  `semodule_package` in `semodule-utils`, `audit2allow`/`audit2why`/
  `semanage` in `selinux-python` (not `audit`), `getsebool` in
  `libselinux`, the rest in `policycoreutils`. `missing_tool_error(tool)`
  builds the "isn't installed" error from it, naming the package and the AUR.
- `set_mode(enforcing, persistent=True)` — `setenforce` (runtime) +
  optionally edits `/etc/selinux/config` (backed up first) so it survives reboot.
  The enforcing/permissive switch itself is lock-gated in the UI (a
  `changes-prevent-symbolic`/`changes-allow-symbolic` lock button must be
  clicked before the switch accepts input at all, on top of the existing
  confirm dialog) and re-syncs from a fresh `sestatus` read after every
  attempt rather than trusting its own last-dragged position — see the
  Phase-adjacent bug-fix write-up in section 6 for why (a real cancel-
  doesn't-revert bug got fixed in the same pass).
- `list_booleans(filter_text="")` / `set_boolean(name, value, persistent=True)`
  — `getsebool -a` / `setsebool` (`-P` when persistent).
  `set_booleans(values, persistent=True)` sets several in one `setsebool`
  call: with `-P` each call rebuilds the whole policy and is its own prompt
- `restorecon(path, recursive=True)`, `restorecon_streaming(...)`,
  `relabel_filesystem()` (schedules a full relabel on next boot)
- **Setup Mode**: `start_setup_mode()` (`set_mode(enforcing=False,
  persistent=True)` — runtime *and* `/etc/selinux/config` — + records a start
  timestamp in `~/.local/share/atropa/selinux-review/setup_mode_state.json`),
  `get_setup_mode_started_at()`, `is_in_setup_mode()`, `clear_setup_mode()`
- **Denial Review page backend**: `list_all_denials(since=None, source="both")`
  → `group_denials()` → `classify_denials()` (`new` / `already_allowed` /
  `undefined_in_policy`), wrapped by `review_all_denials(source="both",
  since_setup_mode=True) -> ExtensiveDenialReview` which also diffs against
  `last_review.json` to produce `resolved`. Details in section 6. Time
  scoping uses absolute instants: journalctl gets `--since @<epoch>`, and
  audit-log records are filtered on their own `msg=audit(<epoch>)` stamps
  rather than via ausearch's locale-dependent `-ts`; a failed audit-log read
  raises when the audit log is the requested source.
- `list_semodules()` — `semodule -l`, **privileged** (unprivileged it
  silently returns nothing)
- `compile_and_load_te(te_content, module_name)` — the single-file
  paste/Compile-&-Load flow (compile unprivileged, then `semodule -i`)
- `install_pp_file`, `remove_semodule`, `list_pending_modules`,
  `list_approved_modules`, `reinstall_all_approved_modules()` (all inactive
  approved modules in **one** `semodule -i` call = one auth prompt)
- `check_policy_source_for_permission(policy_src_dir, tclass, permission="")`
  — read-only search of a refpolicy source tree's `access_vectors`
- **Denial review**: `list_avc_denials()` (unprivileged, `journalctl -k`)
  only sees AVCs while auditd isn't running - once it is, the kernel hands
  audit records to auditd instead of printing them, so they're only in the
  audit log. `list_avc_denials_from_audit_log()` reads that (privileged
  `ausearch -m avc -ts boot --input-logs`): the whole boot rather than
  ausearch's "recent" 10 minutes, the log files even when stdin is a pipe,
  and a failed read - a dismissed prompt included - raises instead of
  showing "no denials". The "not defined in policy" messages are plain
  printk lines and stay in the kernel log either way. Per-denial:
  `explain_denial()` runs `audit2why`, `generate_te(raw_line, module_name)`
  runs `audit2allow -m <name>`
- **Per-application batch review** (`build_policy_review(source="journal",
  denial_limit=500, sample_size=5, since=<unset>)`) — ported from a
  user-supplied shell script. Groups denials by **(program, source
  domain)**, skips kernel noise (`^(systemd|kernel|audit|kworker|swapper)`),
  and for each group: generates a `.te`, an `audit2why` explanation, and
  compiles (but does **not** install) a `.pp`. Rationale for grouping:
  `audit2allow` produces a much better policy seeing all of a program's
  related denials together vs. one denial at a time. `comm=` alone isn't
  enough - it's whatever name a process gives itself, so one name running
  in two domains used to become one module granting both domains' rules.
  Generated modules are named `atropa_<program>_<domain>`
  (`_review_module_name()`): named after the program alone, a denial from
  `ssh`, `mount` or `sudo` produced `ssh.pp`, `mount.pp` or `sudo.pp`, and
  installing one replaces the policy's own module of that name.
- **Compile pipeline hardening vs. the original script**: `checkmodule` and
  `semodule_package` run **unprivileged** (`run_unprivileged`, not
  `run_privileged`) — they only read/write local files and don't touch the
  live policy, so running them as root (as the original script did via
  blanket `sudo`) was an unnecessary escalation. Only `ausearch` (reading the
  audit log) and `semodule -i`/`-r` (touching the live policy) stay privileged.
- **Pending → Approved folder split**: compiled `.pp` files live in
  `~/.local/share/atropa/selinux-review/modules/` (pending, not installed)
  and move automatically to `.../approved/` (via `_move_to_approved`) the
  moment `semodule -i` succeeds — verified end-to-end with real file-move
  assertions. `list_approved_modules()` reports `active: bool` per entry
  (a module can be "approved" — installed at some point — but currently
  inactive if later `semodule -r`'d); removing a module does **not** move
  its files back to pending, they stay in approved marked inactive, with a
  one-click reinstall.
- Module names are validated everywhere via `_validate_module_name` (`^[a-zA-Z0-9_-]{1,64}$`)
  before touching any file path or argv — blocks path traversal / injection attempts.
- **Batch import** (`import_te_files(paths)`): compiles a batch of
  already-written `.te` files (e.g. a personal or third-party policy
  "addon" collection) into Pending, same bucket `build_policy_review`
  uses — deliberately does **not** install any of them directly, unlike
  the single-file paste/load-then-Compile-&-Load flow, since a batch of
  files that may never have been individually opened doesn't get that
  flow's "the person clicking the button just read this" assumption. One
  bad file (unreadable, invalid/unparseable module name, fails to
  compile) is recorded and skipped rather than aborting the whole batch.
  Module name comes from the file's own `module <name> <version>;`
  declaration line if present (matches `audit2allow`'s own output format,
  which is what these files typically already are), falling back to the
  filename stem.

### System (`system_config.py` / `pages/system_config.py`)
Built on `hostnamectl` / `timedatectl` / `localectl`:
`get_hostname_status`/`set_hostname`, `get_time_status`/`list_timezones`/
`set_timezone`/`set_ntp`, `get_locale_status`/`list_generated_locales`/
`set_locale`, `list_locale_gen_entries`/`set_locale_gen_enabled(locale,
charmap, enabled)` (the one raw-file edit: `cat` → edit in Python → `tee`,
backed up, then `locale-gen`), `list_keymaps`/`set_keymap`,
`list_x11_layouts`/`set_x11_layout`. Filter lists render at most 40 matches
(`_MAX_RENDERED_MATCHES`).

### Security Quick Setup (`quicksetup.py` / `pages/quicksetup.py`)
`CATALOG` of `SetupItem(key, title, description, default_selected, risk_note)`
for firewall, fail2ban, sysctl, faillock, AppArmor, auditd, USBGuard
(`default_selected=False`) and SELinux (permissive only). `status_summary()`,
`apply_single(key, on_line)`, `apply_items(keys, on_line) -> dict[str,
CommandResult]` — checklist and wizard share these. The firewall step
allows every port sshd listens on (`SshStatus.ports` - `Port` lines
accumulate and `ListenAddress` can name its own) before enabling
deny-by-default, and doesn't enable the firewall at all if an allow fails.
`apply_items()` records a step that raises - a `PartialUpgradeError` from
`pacman.install()`, say - as that step's failure and carries on with the
next one instead of aborting the batch. The AppArmor step's guidance is the
`lsm=` kernel parameter (`hardening.APPARMOR_KERNEL_PARAMETER`). The SELinux
step installs `audit` and, since SELinux's userspace is AUR-only, points at
the packages in `selinux.SELINUX_TOOL_PACKAGES` instead of running a
`pacman -S` that could only fail; a SELinux that's disabled in the kernel is
reported as a manual step.

### Security Profiles (`profiles.py` / `pages/profiles.py`)
`export_profile() -> dict`, `save_profile_to_file`, `load_profile_from_file`,
`summarize_profile -> ProfileSummary`, `import_profile(profile, sections,
on_line) -> dict[str, CommandResult]`. Quick-setup modules are replayed via
`quicksetup.apply_items()`; AppArmor modes and SELinux booleans value-for-
value; the `ssh` section is unchecked by default on import (UI). Only
explicit, recognized values are applied: SSH settings exported as `unknown`
(not set in `sshd_config`, so OpenSSH's default applies - including the port)
are left alone, `PermitRootLogin` is replayed exactly via
`security.set_ssh_permit_root_login()` (validated against sshd's own keywords),
AppArmor modes other than enforce/complain are skipped, and anything already
at the target value isn't re-applied. Each section runs isolated. Changed
SELinux booleans go in a single `selinux.set_booleans()` call - one prompt
and one policy rebuild, not one of each per boolean.

### Dependencies (`dependencies.py` / `pages/dependencies.py`)
A static catalog of `Dependency(name, module, description, package,
required, note)`; `check_all() -> list[DependencyStatus]`,
`missing_required()`, `summary_counts()`. AUR-only tools (paru/yay, aide,
and SELinux's userspace tools - their notes are built from
`selinux.SELINUX_TOOL_PACKAGES`) have `package=None` and a note instead of
an Install button that would run `pacman -S` and fail. `checkupdates`
(pacman-contrib) and `fakeroot` are listed for the Packages page's live
update check.

### Add-ons / plugins (`plugins.py` + `plugin_registry.py` / `pages/addons.py`, `pages/plugin_page.py`)
- `plugin_registry.REGISTRY` — the only actions a manifest may reference:
  `pacman.{check_updates,list_explicit,clean_cache}` (no `sync_database`:
  plugins can't set up a partial upgrade either),
  `services.{list_services,start,stop,restart,enable,disable}`,
  `network.list_devices`, `hardening.run_audit`,
  `compliance.generate_report`, `dependencies.check_all`.
  `get_action(key)`, `describe_call(key, params)` (shown in every mutating
  action's confirm dialog).
- `plugins.discover_plugins()` scans `/etc/atropa/plugins/<id>/manifest.toml`
  (folder name must equal `id`); `enabled_plugins()` (valid + enabled per
  `/etc/atropa/plugins-enabled.json`); `set_plugin_enabled(id, enabled)`
  writes via pkexec; `run_plugin_action(action_key, params)`.
- Manifest fields: `id`, `title`, `description`, `icon` (default
  `application-x-addon-symbolic`), `author`, `version`, `[[groups]]` with `title`,
  `description`, `[[groups.rows]]` with `title`, `action`, `button_label`,
  plus any parameter names the registry action declares.

### Activity & Backups (`pages/activity.py`, backed by `privilege.py` + `migration.py`)
Browses `list_backups()` (view raw content, restore with confirm) and
`get_recent_actions()` (read-only tail). When old ArchYaST data exists, a
migration section appears, backed by `migration.py`:
`detect_legacy_data() -> LegacyDataStatus`, `migrate_user_data(on_line)`
(`~/.local/share/archyast` → `atropa`, non-destructive, logs prepended),
`migrate_plugin_data(on_line)` (`/etc/archyast` → `/etc/atropa`,
privileged, `cp -n`), and separate confirm-gated
`remove_legacy_user_data()` / `remove_legacy_plugin_data()`.

---

## 3. UI conventions (`ui/pages/__init__.py` — `BasePage`)

Every page subclasses `BasePage`, which provides:
```python
self.toast_overlay          # Adw.ToastOverlay wrapping all content
self.preferences_page       # Adw.PreferencesPage, scrollable
self.add_group(title, description="") -> Adw.PreferencesGroup
self.notify(message, timeout=None, is_error=False)  # auto-escapes markup; errors stay up 6s vs 3s
self.clear_rows(group, rows)                        # remove previously-added dynamic rows
self.start_loading(group, message="Loading…")       # spinner placeholder row while refresh() runs
self.run_async(work_fn, on_done)                    # backend call -> worker thread -> GLib.idle_add back to main thread
self.handle_command_result(result, error, success_message="Done", refresh=True)
                                                    # shared on_done for CommandResult-returning calls
self.run_action(work_fn, on_done) -> bool           # run_async for a state change: one at a time per page
self.apply_switch(switch, requested, work_fn, confirm=None, on_done=None) -> bool
                                                    # body of a Gtk.Switch "state-set" handler
self.run_streaming_operation(title, work_fn, on_done=None)
                                                    # modal live-log dialog; work_fn(on_line)
self.confirm(heading, body, danger_label, on_confirm, on_cancel=None)
                                                    # markup disabled, for destructive actions
```
`run_async` is **mandatory** for any backend call — backend functions block on
subprocess I/O, so calling them directly on the main thread would freeze the GTK
event loop (e.g. during a full `pacman -Syu`).

**State-changing buttons use `run_action()`**, not `run_async()` directly. It
refuses to start a second change on a page while one is still running (and
says so), instead of racing two privileged sequences - two pacman
transactions fighting over the lock, two `sshd_config` edits racing each
other's validate/restore. It returns `False` when it refused, so the caller
can put a widget back.

**Switches that change the system use `apply_switch()`.** A handler returns
its result from "state-set"; it takes over GTK's default state handling,
optionally asks first (`confirm=(heading, body, button label)`), runs
`work_fn` through `run_action()`, and settles the switch on the new state
only once the change succeeded - it flips back when the change fails, is
refused or is cancelled. A switch must never keep showing a state that was
never applied. The firewall, fail2ban, auditd, SELinux boolean and AppArmor
rule switches all go through it; SSH settings re-read `sshd_config` after
every attempt for the same reason.

**Risky one-click changes ask first** and say what they break: turning the
firewall on, turning SSH password logins off, moving the SSH port, allowing
empty passwords, locking a password, stopping or disabling a service.

**The progress dialog has "Hide".** `run_streaming_operation()`'s dialog
used to be unclosable until its command finished or timed out (30 minutes
for an upgrade). Hiding it leaves the command running, and the usual
notification reports how it ended. A page won't start a second streaming
operation while one is running.

**A row has to live in a list box.** An `Adw.ActionRow` placed directly in
a `Gtk.Box` makes GTK assert when it gets focus; wrap it in a
`Gtk.ListBox` with the `boxed-list` class, as the progress dialog's status
row does.

**Row-building pattern**, used identically across every page:
```python
def _on_X_loaded(self, result, error) -> bool:
    for row in list(getattr(self, "_X_rows", [])):
        self.X_group.remove(row)
    self._X_rows = []
    if error: ...; return False
    for item in result:
        row = Adw.ActionRow(title=esc(item.name), subtitle=esc(...))
        row.add_suffix(some_button)
        self.X_group.add(row)
        self._X_rows.append(row)
    return False
```

**Cross-page communication** (one instance): `main_window.py` calls
`set_load_page(SelinuxLoadPage instance)` on both the SELinux page and the
SELinux: Denial Review page, so their "Generate .te" / "View Review" dialogs
can offer an "Open in Load Policy page" button that calls
`load_page.load_te_text(text, module_name)` directly. Because pages are built
lazily, this wiring happens in `_ensure_page_materialized()` in whichever
order the pages are first visited.

**Lazy construction, no auto-refresh on navigation**: a page is only
constructed (and its initial `refresh()` run) the first time its sidebar
entry is clicked; `_on_row_activated` deliberately does **not** call
`refresh()` again on later visits, so privileged reads don't re-prompt for
authentication on every click (see the pkexec-prompt-spam bug in section 6).
Pages that need fresh data have their own Refresh/Re-scan button.

---

## 4. Testing approach

**There's a real pytest suite**: `tests/`, 727 tests across
one file per `backend/` module (all 23), run via `python3 -m pytest` (config in
`pyproject.toml`). A shared `conftest.py` provides four fixtures —
`fake_run` (replaces `privilege._subprocess_run`, the one place commands are
started from, and `subprocess.run`, with a prefix-matching response registry),
`fake_which` (controls which CLI tools "exist"), `privilege_paths`
(**autouse**: redirects `HOME`, the action log, backups, SELinux review
artifacts and the legacy ArchYaST dir into `tmp_path`) and `kernel_state`
(**autouse**: points the checks that read live kernel state - the active LSM
list, AppArmor's enabled flag and its securityfs directory - at files under
`tmp_path`) — which is enough to unit-test
parsing/logic across every module, since they all funnel through
`privilege.run_privileged`/`run_unprivileged`. CI (`.github/workflows/ci.yml`)
runs `py_compile` + `ruff check` + the full suite on push/PR.

`fake_run` is **not** autouse: a test that doesn't ask for it runs real
commands. One did for a long time - `apply_sysctl_hardening([])` made 20
real `sysctl -n` reads before raising, so the test read the kernel of
whatever machine ran it and failed on one without `sysctl`. Give every test
that reaches a backend call the fixture, even when its body never refers
to it. `kernel_state` exists for the same reason from the other side:
GitHub's Ubuntu runners have AppArmor enabled, so an "AppArmor isn't
available" test passed locally and failed in CI until the paths it reads
became module constants the fixture can redirect.

`tests/test_resources.py` is the one file that isn't about a backend module.
The app icon is wired by name in three places - `APP_ID` in `main.py` (the
window icon), `Icon=` in `atropa.desktop` (the launcher) and the file names
under `resources/icons/` - and a mismatch just shows a generic icon with no
error, so the test checks they agree and that every size is packaged.

Before this pass, verification was manual, every turn:
1. `python3 -m py_compile` on every file, every turn (catches syntax errors immediately)
2. **Logic tests with real data structures** — e.g. feeding the exact
   `sestatus`/`aa-status`/`pacman -Qu` output format through the actual
   parsing regex, asserting the parsed dataclass matches expectations
3. **Subprocess-mocked end-to-end tests** for anything privileged — patch
   `atropa.backend.privilege.subprocess.run` (the actual boundary
   everything funnels through) and `shutil.which` (to simulate `pkexec`
   being present), then call the real function and assert on real file
   contents afterward (not just that a mock was called)

The pytest suite formalizes exactly this pattern (same subprocess-boundary
mocking approach) rather than replacing it with something different, so the
lessons below still apply to writing new tests.

**A meta-lesson worth preserving**: an early rollback test mocked
`security.run_privileged` (the name imported into `security.py`'s own
namespace) and appeared to pass — but for the wrong reason. `backup_file`/
`restore_file` live in `privilege.py` and call `run_privileged` via *that
module's own* internal reference, which a mock on `security.run_privileged`
never touches (`from x import y` copies a reference at import time; it isn't
a live alias). The test's "expected RuntimeError" was actually a real
`PrivilegeError` (pkexec not found in the sandbox) being mis-caught by the
same `except RuntimeError` clause (`PrivilegeError` subclasses it). **Fix**:
always patch the one real boundary every path funnels through, regardless of
which module holds which imported name. That boundary was
`atropa.backend.privilege.subprocess.run`; since the timeout fix it is
`privilege._subprocess_run`, and the `fake_run` fixture patches both. The
streaming runners call `subprocess.Popen` directly and aren't covered by it.

`privilege_paths` is autouse, so every test gets those redirects without
asking for them; request it by name only to get at the paths
(`.log_path`, `.backup_dir`, `.manifest`, `.home`). It used to be opt-in, and
the action log's file handler was opened at import time (ignoring any
redirect) - between them, a single test run wrote ~1,250 fake log lines and
several restorable "backups" into the developer's real `~/.local/share/atropa`.
The handler now resolves `LOG_PATH` per record, and importing `privilege.py`
creates nothing on disk.

Known bugs caught **only** by these tests, not by reading the code back:
- Duplicate `install_pp_file` definitions in `selinux.py` (second silently
  shadowed the first, which had the approved-folder move logic) — caught by
  `grep -c "^def install_pp_file"`
- Duplicate `check_updates` in `pacman.py` (same shadowing pattern) — same detection method
- AppArmor network rule using the wrong denial field (`protocol=` instead of
  `sock_type=`) — caught by checking the *real* AppArmor rule grammar against
  the test's assumptions, not just the test passing

**Lesson**: whenever editing near an existing function definition rather than
replacing it cleanly, `grep -n "^def <name>"` afterward to confirm there's
exactly one definition.

---

## 5. Known limitations (intentional, not oversights)

- **systemd-networkd**: read-only detection only, no write support
- **GRUB reinstall**: not automated (disk-target ambiguity is destructive if wrong)
- **AppArmor kernel parameter** (`lsm=landlock,lockdown,yama,integrity,apparmor,bpf`):
  not auto-added to bootloader config (risk of unbootable system)
- **Partial upgrades**: no `pacman -Sy` and no single-package update; the
  only ways to change packages are a full upgrade, an install that refuses
  while the database is ahead, and "Upgrade and install"
- **pam_faillock wiring into the PAM stack**: not automated (risk of
  lockout with no easy recovery); only the already-safe
  `/etc/security/faillock.conf` parameters are editable, and only if
  `pam_faillock` is already referenced (same for `pwquality.conf` /
  `pam_pwquality`)
- **AUR-only tools** (AIDE, paru/yay, SELinux's userspace tools and policy):
  detected and managed once installed, never built or installed by Atropa
- **Plugins**: declarative TOML only, limited to actions in
  `plugin_registry.REGISTRY`; enabling/disabling takes effect on next launch
- **AUR builds**: shells out to `paru`/`yay` if present, no PKGBUILD review/sandboxing
- No i18n/l10n

## 6. TODO / brainstormed next steps (roughly priority order, per the last planning pass)

**Done since the brainstorm:**
- ✅ Config backup + restore mechanism (Activity & Backups page)
- ✅ SSH validate-before-reload with auto-rollback
- ✅ AppArmor parity with SELinux (profile toggles, denial review)
- ✅ Package management visibility (real pending-updates list, not just a count; gated single-package update -
  removed again later, see the second bug-fix batch at the end of this section)
- ✅ A real pytest suite (727 tests as of the latest pass, across all 23 `backend/` modules, one
  shared command-runner fake in `conftest.py`; covers the SSH and GRUB
  rollback-on-failure safety paths specifically)
- ✅ CI/lint config (`.github/workflows/ci.yml` runs `py_compile` + `ruff
  check` + the pytest suite on push/PR, Python 3.11 and 3.12; `ruff`
  config lives in `pyproject.toml`, deliberately scoped to `E9`/`F`/`W`
  only — real-bug categories like duplicate defs and unused
  imports/vars, not a full style rewrite of existing code)
- ✅ UX polish: every page's `refresh()` now shows a spinner placeholder row
  (`BasePage.start_loading()`) in place of a list that's empty one moment
  and full the next; error toasts get a longer timeout than success ones
  (`notify(is_error=True)`, 6s vs 3s); the copy-pasted `_on_command_done`
  from all 11 pages is now one shared `BasePage.handle_command_result()`;
  and the two genuinely long ops (`pacman -Syu`, `restorecon -R`) stream
  live output into a modal progress dialog (`BasePage.run_streaming_operation()`,
  backed by `privilege.run_privileged_streaming()`) instead of a single
  toast then silence. Fixed a self-introduced bug along the way: an early
  version of the spinner placeholder didn't clear old rows first, which
  would have caused duplicate rows to accumulate on every `refresh()` —
  caught before shipping via `BasePage.clear_rows()`. **Confirmed working
  on bare metal Arch** (screenshots of the live `-Syu` and `restorecon`
  streaming dialogs, and the Dependencies sidebar entry, all rendered
  correctly) — the user tests every handoff this way, which is the real
  validation signal for anything GTK-related since this sandbox has no
  GTK/libadwaita to run against.
- ✅ A "what's missing" dependency overview page (`backend/dependencies.py`
  + the Dependencies page) — one catalog of every external tool every
  module shells out to (pkexec/sudo, pacman/AUR helpers, systemd,
  NetworkManager, GRUB/systemd-boot, ufw/firewalld, SSH, fail2ban,
  AppArmor, USBGuard, auditd, arch-audit, every SELinux tool), grouped by
  module, each with an Install button where a real pacman package exists.
- ✅ A "Security Quick Setup" page (`backend/quicksetup.py` + the Quick
  Setup page) — one recommended baseline across firewall, fail2ban,
  sysctl, faillock, AppArmor, auditd, USBGuard, and SELinux at once,
  installing anything missing from scratch first. Both a checklist +
  "Apply Selected" batch (via the same streaming-dialog infra as the
  upgrade/relabel ops) and a step-by-step guided wizard with a per-item
  skip, sharing one set of per-item apply functions
  (`quicksetup.apply_items()` / `quicksetup.apply_single()`) so the two
  entry points can never drift out of sync with each other. Deliberately
  conservative: firewall always allows the actual configured SSH port
  *before* enabling deny-by-default (never the other order, to avoid a
  remote lockout mid-setup); USBGuard defaults unchecked (opt-in, since
  it can surprise-block USB devices plugged in later); SELinux is only
  ever set to permissive, never enforcing; and AppArmor kernel-parameter
  wiring and PAM-wiring for faillock are explicitly left as manual steps
  with an on-screen explanation, rather than silently no-op'd or
  automated in a way that risks a bad boot.

- ✅ Two features from thinking about the app from an enterprise sysadmin's
  point of view rather than a single-power-user one - the biggest gap
  there being that everything up to this point was single-machine-shaped:
  - **Security Profiles** (`backend/profiles.py` + the Security Profiles
    page) — export the current machine's posture (which quick-setup
    modules are configured, AppArmor profile modes, SELinux booleans, SSH
    hardening settings) as a portable JSON file, and import one elsewhere
    to clone that posture, with a per-section checklist so nothing gets
    applied blind. Deliberately does NOT replay arbitrary captured sysctl
    values - it records "was this quick-setup module configured" as a
    boolean and re-applies it through `quicksetup.apply_items()`/
    `apply_single()`, so an imported profile is exactly as safe as running
    Quick Setup by hand (same SSH-before-firewall ordering, same
    never-auto-enforce SELinux). AppArmor profile modes and SELinux
    booleans ARE captured and replayed value-for-value, since each is a
    single well-defined action already; anything captured that doesn't
    exist on the target machine is skipped and reported, never guessed
    at. SSH settings are included but default unchecked on import — the
    existing validate-before-reload rollback catches a broken config, not
    a *valid* one that just doesn't fit this particular machine.
  - **Compliance Report** (`backend/compliance.py` + the Compliance
    Report page) — a categorized, scored report built directly on top of
    `hardening.run_audit()` (plus two more checks: login lockout and
    sudoers) rather than duplicating any detection logic, organized into
    CIS-style categories and exportable as Markdown. Framed carefully:
    every export states plainly that this is modeled on common CIS-style
    categories for organization, NOT an official CIS Benchmark assessment
    or a certification of regulatory compliance - that distinction lives
    on the report itself (`compliance.DISCLAIMER`), not just in code
    comments, since a false sense of certified compliance is worse than
    no report at all.

- ✅ SELinux: Denial Review (`backend/selinux.py` extensions + the
  new SELinux: Denial Review page) — for someone bootstrapping a policy
  from scratch, this replaces "review the recent N denials" with an
  actually-scoped workflow: **Setup Mode** sets permissive and records a
  start timestamp (local state, doesn't touch SELinux's own behavior
  beyond that one setenforce call); `list_all_denials()` then fetches
  everything still retained by the kernel log and/or `audit.log` since
  that timestamp — explicitly NOT claiming literal all-time history,
  since both log backends rotate; `group_denials()` collapses raw lines
  to one entry per unique (source type, target type, class, permission)
  combination, which is the granularity an actual policy rule operates
  at, with an occurrence count rather than a flat list of duplicates;
  `classify_denials()` cross-checks each against every `.te` file
  Atropa has installed that's **currently loaded** (`semodule -l`),
  splitting results into New (needs a rule), Already Allowed But Still
  Denied (a rule matches yet it still happened - almost always a
  file-context/labeling problem, not a policy gap, so the UI offers a
  one-click `restorecon` on the affected path right there instead of
  drafting a redundant rule), and Resolved Since Last Review (diffed
  against a saved snapshot from the previous run). `build_policy_review()`
  itself also gained a `since` parameter, so generating the actual .te
  drafts can be scoped to the whole Setup Mode window in one batch
  instead of the old small recent-window default - directly answering
  "so generating a policy could be quicker for people just starting to
  set up SELinux." A real bug surfaced by the tests here, not just found
  by inspection: the context-type extraction regex was capturing the
  SELinux *role* (`system_r`) instead of the *type* (`myapp_t`) from the
  `user:role:type:level` context format - every classification would
  have silently matched on the wrong field. Caught before shipping.

- ✅ Add-ons / plugin system (`backend/plugin_registry.py`,
  `backend/plugins.py`, the Add-ons page, `ui/pages/plugin_page.py`) — a
  user asked for a way to add custom plugins "following the blueprint."
  Two design forks were resolved explicitly with the user rather than
  assumed, given how much this changes the app's trust model:
  - **Declarative, not code.** A plugin is a TOML manifest describing
    pages/groups/rows; `tomllib.loads()` reads it as plain data and
    nothing from it is ever imported, exec'd, or eval'd. A manifest can
    only reference action keys already defined in the fixed
    `plugin_registry.REGISTRY` - it cannot run an arbitrary command, and
    the registry deliberately excludes users, firewall/SSH, bootloader,
    SELinux/AppArmor policy, `restorecon`, and Quick Setup/profile
    import-export as higher-blast-radius domains that stay
    built-in-only. A test (`test_discover_plugins_never_imports_or_execs_manifest_content`)
    plants a manifest whose title/description look like Python code and
    confirms it's treated as inert string data.
  - **Root-owned storage, not just a root-gated toggle.** Both the
    manifest files (`/etc/atropa/plugins/<id>/manifest.toml`) and the
    enabled-state file (`/etc/atropa/plugins-enabled.json`) live under
    `/etc/atropa`, which only root can write to - so placing, editing,
    AND enabling a plugin all require root, not just the activation
    step. `set_plugin_enabled()` writes via `run_privileged()` (pkexec),
    the same authentication barrier as every other privileged action in
    this app; a test confirms the write genuinely goes through pkexec
    rather than a direct unprivileged file write. This was the stronger
    of two options offered to the user, chosen deliberately once they
    handed the security-priority call to whichever answer was safer.
  - **A plugin's own labeling is never trusted for a mutating action.**
    `plugin_registry.describe_call()` renders the real underlying call
    (`services.restart('sshd')`) and `PluginPage`'s confirm dialog always
    shows it, regardless of what friendly title/button label the
    manifest gives that row - closing (most of) the remaining
    social-engineering gap that removing code-execution risk doesn't by
    itself close.
  - Plugin discovery/loading happens once at Atropa startup, not
    live-reloaded - enabling/disabling from the Add-ons page takes
    effect on next launch, stated plainly in the UI, rather than
    building runtime sidebar/stack mutation for a first version.
  - A shipped, CI-validated reference manifest
    (`examples/plugins/example-plugin/manifest.toml`) is parsed by an
    actual test against the real parser, so the documentation example
    can't silently drift out of sync with the registry as it evolves.

- ✅ **Project renamed: ArchYaST → Atropa.** Chosen for its Greek-myth
  backstory (Atropos, the Fate who cuts the thread of life - deadly
  nightshade, *Atropa belladonna*, carries her name) after "BlueGuard"
  and "Cerulean" both turned out to collide with existing security
  products on a quick check, and "Solanum"/"ArchGuard" turned out to
  collide with real unrelated open-source projects. A **full** rename
  was chosen deliberately over a cosmetic one: package directory,
  imports, `pyproject.toml`, the GTK app ID and window/class names,
  the desktop launcher and polkit policy files, and every local data
  path (`~/.local/share/archyast` → `~/.local/share/atropa`,
  `/etc/archyast` → `/etc/atropa`) all changed together, verified with
  a case-insensitive grep across the entire repo for any leftover trace
  of the old name (found none outside build caches) plus a full
  compile/lint/test pass from the renamed structure.
- ✅ **Migration from the old ArchYaST paths** (`backend/migration.py` +
  a new section on the Activity & Backups page, shown only when
  there's actually something to migrate). Follows the rename's own
  logic through: migration is explicit and user-triggered, never
  automatic - discovering your history silently moved would be its own
  kind of surprise. It's also non-destructive by design: existing files
  at the new location always win, only genuinely missing pieces get
  copied in, so running it twice (or after some manual cleanup) is
  always safe. Append-only logs (the activity log, the backup manifest)
  get prepended rather than skipped-or-clobbered, since old entries
  logically precede whatever's been written since the rename - tested
  for idempotency specifically (running migration twice must not
  duplicate history). Deleting the old data entirely is a separate,
  explicit, confirm-gated step, never a side effect of migrating.
  Migrating `/etc/archyast` plugin data requires root, same
  authentication barrier as any other write under `/etc/atropa` -
  reuses `cp -n`/`cp -rn` (no-clobber) rather than reimplementing that
  merge logic in Python for the privileged half.

- ✅ **System** page (`backend/system_config.py` + the System page) —
  hostname, timezone/NTP, locale, and keyboard layout: the "basic system
  config" every distro's setup tool covers, added on request. Built on
  systemd's own trio (`hostnamectl`/`timedatectl`/`localectl`) rather
  than editing config files directly, parsed the same way every other
  `systemctl`-adjacent status text is parsed elsewhere in this app
  (colon-separated key/value lines) rather than guessing at
  `--json=short` output schemas I wasn't fully certain of from memory -
  consistency with a proven pattern over a fancier one I couldn't verify.
  Locale generation (`/etc/locale.gen` → `locale-gen`) is the one piece
  that touches a raw config file, since there's no systemd tool for it -
  it's the step people forget on a fresh Arch install (a locale exists
  in `/etc/locale.gen`, commented out, and never gets compiled). Caught
  and fixed a real bug before it shipped: an initial version built the
  locale.gen edit as a sed expression using `re.escape()`'d Python-regex
  syntax fed into sed's BRE - those two escaping conventions disagree
  (e.g. `\+`/`\?` mean "one or more"/"optional" in GNU sed BRE, not a
  literal `+`/`?`), which could have silently mismatched or corrupted
  the file for certain locale/charmap names. Replaced with a read
  (`cat`) → edit in Python → write (`tee`) round-trip, avoiding the
  cross-language escaping mismatch entirely and reusing the same
  privileged-write pattern already used throughout the app. Also caught
  two GTK API precedent mismatches while building the four filterable
  lists (timezones/locales/keymaps/X11 layouts, each capped to the top
  40 rendered matches for performance): an unverified live
  `Gtk.Editable::changed` filter-as-you-type binding with zero
  precedent anywhere else in the codebase (replaced with the same
  explicit "Apply"-button pattern every other filter row already uses),
  and `Gtk.Switch.set_state()` where every other page's precedent is
  `set_active()` for programmatically setting a switch. Both were
  caught by checking existing code for precedent before trusting an
  API I couldn't run, not by inspection alone.

- ✅ SELinux: Denial Review gained a fourth classification,
  **"undefined_in_policy"**, found via a real user-reported bug hunt (a
  boot hang on refpolicy-arch traced to `SELinux: Permission bpf in
  class capability2 not defined in policy.` kernel messages - a policy
  whose class/permission *definitions* predate what the running kernel
  exposes, distinct from a missing `allow` rule and not fixable with one
  - the actual fix is rebuilding the policy source with `UNK_PERMS=allow`
  in `build.conf`, or an updated policy). The review page previously
  couldn't see these at all: `journalctl -k -g "avc:"` - the grep
  pattern itself, not just the Python-side filter - excluded any line
  without the literal substring `avc:`, and these messages don't contain
  it. Fixed at the actual root: broadened the `-g` pattern to
  `avc:|not defined in policy` (journal source only - these are raw
  kernel printk lines, not audit records, so `ausearch` never returns
  them regardless of any Python-side filter). `group_denials()` handles
  them as a structurally distinct case (no `comm=`/`scontext=`/`tcontext=`
  fields to extract, so they get `scontext_type="(kernel)"`, `program="kernel"`
  rather than forcing them through AVC-shaped parsing that would just
  produce `"?"` fields), `classify_denials()` explicitly never
  reclassifies them as `already_allowed` (a normal allow rule can't fix
  an undefined permission, so that reclassification would be actively
  misleading), and `build_policy_review()` excludes them from what gets
  handed to `audit2allow` (which has no comm=/scontext= fields to work
  with and couldn't draft a rule for them if it tried). The UI's new
  "Policy doesn't define this permission" section explains the real
  remedy directly rather than offering a "Generate Policy" button that
  would be a dead end here.

- ✅ A "Help" dialog on each undefined-in-policy denial
  (`selinux.check_policy_source_for_permission()` + the dialog in
  `selinux_review.py`) — a deliberately narrow follow-up to the
  classification above. The user who reported the original bug asked
  whether Atropa should ship a fixed policy once they patched theirs;
  the answer landed on **no** - bundling policy content would make
  Atropa a source of truth for security-relevant content in a way
  nothing else in the app is (everything else orchestrates/curates
  existing system tools; it never *is* the security content), and it'd
  need updating in lockstep with every kernel release forever, for a
  gap that isn't Arch- or Atropa-specific and belongs fixed upstream
  (`SELinuxProject/refpolicy` or `archlinuxhardened/selinux-policy-arch`)
  where it helps everyone, not just Atropa users. What shipped instead:
  a read-only diagnostic - given a policy source directory, checks
  whether `policy/flask/access_vectors` already defines the permission
  for that class (following one level of `inherits`), and reports found/
  not-found plainly, with an explicit caveat that it's a best-effort
  text search over refpolicy's `class X [inherits Y] { ... }` syntax,
  not a real policy-language parser - a "not found" is a strong hint to
  check manually, not a certainty. Caught a real regex bug while writing
  the tests: the class-block pattern originally excluded newlines in the
  `inherits` clause (`[^\n{]*`), but `inherits` commonly sits on its own
  line before the opening brace in real refpolicy files - fixed to
  `[^{}]*`, which allows it to span lines. Never writes to the policy
  source or anywhere else; a test confirms no privileged call ever
  happens for this function specifically.

- ✅ `selinux.reinstall_all_approved_modules()` + a "Reinstall All Inactive"
  button on the SELinux: Load Policy page — surfaced by the same user's
  real-world use, this time hitting the practical pain of switching
  `SELINUXTYPE` (e.g. from a stale `selinux-refpolicy-arch` to
  `selinux-refpolicy-arch-git` after discovering the former hadn't been
  updated since 2023): every policy store has its own module list, so a
  whole batch of previously-approved modules goes "inactive" at once for
  a reason that has nothing to do with any single module being
  untrustworthy - and reinstalling them one at a time meant one `pkexec`
  authentication prompt per module. The fix is a real one-shot batch, not
  a UI loop dressed up to look like one: `semodule -i` accepts multiple
  `.pp` paths in a single invocation, so `reinstall_all_approved_modules()`
  collects every approved-but-inactive module's path and installs all of
  them in exactly one privileged call - one prompt total, regardless of
  count. Before landing on that as the actual fix, checked whether
  Atropa's own polkit policy was the real culprit (`auth_admin` prompting
  every time vs `auth_admin_keep` caching a recent auth) - it turned out
  `allow_active` was already set to `auth_admin_keep`, so that wasn't
  the bug; worth having checked rather than assumed, since the batch
  fix is deterministic regardless of how polkit's own caching behaves
  in practice, where the policy tweak would only have been a maybe.
  **Correction (later audit):** the policy was never in effect at all - it
  has no `org.freedesktop.policykit.exec.path` annotation, so pkexec uses the
  generic `org.freedesktop.policykit.exec` action (`auth_admin`, no caching)
  for every call. See the privilege-model note in section 1.

- ✅ **CIS DIL Benchmark, Phase 1** (`security.py` SSH depth,
  `hardening.py` password complexity, new `backend/audit_rules.py`) — a
  user asked how far Atropa could go toward helping pass a CIS audit.
  Two things established the actual scope before any code got written:
  **there is no official CIS Benchmark for Arch Linux** (confirmed
  directly from a compliance-vendor support thread: "we do not have SCA
  implementation for Arch Linux OS... we have a CIS Benchmark for
  Distribution Independent Linux which will very well work for your case
  here") - so the real target became the **CIS Distribution Independent
  Linux (DIL) Benchmark**, the closest thing to an official fallback for
  unsupported distros. And the user was explicit up front: Atropa
  automates what it safely can and stays honest about what it can't -
  never a validator or a certification claim, matching
  `compliance.py`'s existing disclaimer.
  Real control text was pulled from `dev-sec/cis-dil-benchmark` (an
  InSpec implementation of CIS DIL 2.0.0) rather than approximated from
  memory - a benchmark this detailed (exact sysctl values, exact PAM
  regexes, exact audit rule syntax) isn't something to guess at when
  getting it subtly wrong is worse than not building it. Given the true
  scope (100+ controls across 6 major sections), the work was explicitly
  phased rather than attempted all at once - Phase 1 covers the parts
  that extend cleanly onto existing, already-safe patterns:
  - **SSH depth** (`security.py`) - 7 new settings (`LogLevel`,
    `X11Forwarding`, `MaxAuthTries`, `IgnoreRhosts`,
    `HostbasedAuthentication`, `PermitEmptyPasswords`,
    `PermitUserEnvironment`) reusing the exact same `_set_sshd_option`
    validate-before-reload-with-rollback safety net the original 3
    settings already had - no new risk surface, just more coverage
    through a proven mechanism.
  - **Password complexity** (`hardening.py`) - `pwquality_wired_into_pam()`
    / `pwquality_status()` / `set_password_complexity_policy()` (CIS
    5.3.1: minlen 14+, at least one digit/upper/lower/special character),
    mirroring the existing faillock functions' shape exactly, including
    the same "only meaningful if already wired into PAM, never
    auto-wired" caution.
  - **Audit rule sets** (new `backend/audit_rules.py`) - the actual
    `auditctl`/`augenrules` rule *content* (time-change, identity,
    network environment, logins/sessions, sudoers scope), not just "is
    auditd running" (already covered). The one real safety property
    worth calling out: several standard CIS watch paths
    (`/var/log/faillog`, `/var/log/tallylog`, `/etc/network`) are
    RHEL/Debian-era conventions a stock Arch install simply doesn't have
    - a `-w` rule for a missing path can fail an entire rules file to
    load on some auditd versions, so each path is existence-checked and
    silently skipped if absent, rather than either failing outright or
    fabricating a rule for something that isn't there. `apply_all_rule_sets()`
    batches every rule set's file write into exactly one `augenrules --load`
    at the end, not one reload per set.
  40 new tests across the three areas (471 total). Caught and fixed a
  real UI bug before it shipped: an early draft of the audit-rule-set
  status indicator called `row.add_prefix()` from inside a callback that
  runs on every `refresh()` - since those are static rows built once at
  construction (not rebuilt each refresh like the app's dynamic list
  patterns elsewhere), that would have silently stacked duplicate
  checkmark icons on the same row every time the page was revisited.
  Fixed by pre-building a hidden icon at construction time and toggling
  `set_visible()` instead of accumulating widgets.
  **Explicitly deferred to a later phase, not attempted here:** service/
  package inventory (CIS 2.2/2.3 - an itemized "must not be installed"
  checklist), file/account hygiene scanning (CIS 6.1/6.2), and AIDE
  filesystem integrity checking (CIS 1.3, a whole new subsystem). Anything
  touching partition/mount scheme is explicitly out of scope permanently -
  that's an install-time decision, not something a running system's
  control panel can safely retrofit.

- ✅ **CIS DIL Benchmark, Phase 2** (new `backend/inventory.py`,
  new `backend/account_hygiene.py`, new `pages/inventory_hygiene.py`) -
  the two areas deferred out of Phase 1. Both are **read-only scans, no
  auto-fix anywhere on either page** - deciding a stray UID-0 account or
  an actually-running legacy service isn't wanted is a human judgment
  call, not something safe to batch away, the same reasoning Phase 1
  already applied to PAM wiring.
  - **Service inventory** (CIS 2.2/2.3) - real Arch package/unit names
    were verified via web search rather than assumed, since this runs for
    real on the user's bare-metal box (confirmed e.g. `dhcp` ships
    `dhcpd4.service`+`dhcpd6.service`, not a single `dhcpd.service`; Samba's
    unit was renamed `smbd.service`→`smb.service` in 4.8+). The bigger
    finding: **CIS's own 2.2 (servers) vs 2.3 (clients) split doesn't map
    onto how Arch actually packages things** - `inetutils` bundles the
    legacy telnet/rsh/talk *clients* together with their matching
    listening *sockets* in one package, and `openldap`/`nfs-utils`
    similarly bundle client and server pieces. Forcing the RHEL/Debian-
    style split would have meant fabricating a category that doesn't
    apply here, so `inventory.py` reports what's actually true instead:
    every catalog entry checks installed-vs-active independently
    (`pass`=not installed, `warn`=installed but inactive, `fail`=installed
    AND actively listening), with the docstring explaining why up front
    rather than leaving the mismatch to be discovered later.
  - **Account & file hygiene** (CIS 6.1/6.2) - passwd/group/shadow/gshadow
    permissions, duplicate UID/GID/username/groupname, stray UID-0
    accounts, system accounts with a login shell, home directory
    ownership/perms, empty `/etc/shadow` password fields (privileged read,
    never stores/surfaces the hash itself - only whether the field is
    empty), and root `PATH` integrity. The `PATH` check is a known
    imperfect proxy, documented as such in the module docstring: it reads
    `/root/.bash_profile`, `/root/.bashrc`, and `/etc/profile` directly
    rather than trusting `pkexec`'s own environment, because `pkexec` sets
    a fixed sanitized `PATH` for the command it runs - checking that would
    make the finding trivially pass regardless of what root's real
    interactive shell `PATH` actually contains.
  - `su` restriction to the wheel group (also originally scoped for Phase
    2) was **not implemented** - editing `/etc/pam.d/su` carries the exact
    same lockout risk Phase 1 already declined for `pam_faillock`/
    `pam_pwquality` wiring, and CIS DIL's own control here is itself a PAM
    edit, not a read-only check like everything else in this phase. Left
    for a future pass alongside real PAM-wiring automation (see "Still
    open" below), not silently dropped.
  30 new tests across the two modules (501 total). One correctness catch
  worth noting: an early draft's `/etc/shadow`/`/etc/gshadow` permission
  check used a flat `0o600` maximum on every system: fine for the file
  perms Arch itself ships (no `shadow` group by default, mode `600`/`000`),
  but would have falsely flagged the Debian/Ubuntu-standard `0o640
  root:shadow` convention (group-readable by design, not a misconfiguration)
  as a failure, and the CI test container itself uses that exact
  convention - if a Phase 2 test had assumed `0o640` was fine everywhere,
  it would have been silently wrong for Arch, so the check was verified
  against Arch's actual documented default (via web search, not memory)
  before deciding `0o600` was the correct ceiling here specifically.

- ✅ **CIS DIL Benchmark, Phase 3** (new `backend/aide.py`,
  new `pages/aide_page.py`) - filesystem integrity checking (CIS 1.3) via
  AIDE, the one Phase this doc's own TODO flagged as needing a real
  scoping conversation before starting, and it earned that flag: AIDE
  itself was dropped from Arch's official repos at some point and is
  AUR-only now (confirmed via the Arch forums, not assumed) - the first
  time this project has had to decide how to handle an AUR-only *security
  tool* rather than just an AUR-only dev convenience like `paru`/`yay`.
  Decision, matching precedent rather than introducing a new trust
  boundary: Atropa still never builds/installs AUR packages itself (same
  posture `dependencies.py` already takes for `paru`/`yay` - "AUR-only,
  build it yourself first") - `aide.py` has no `install()` function at
  all, only manages the tool once it's already present.
  The other real fork - covered in an actual back-and-forth with the user
  before writing code, not assumed - was scheduling: the AUR `aide`
  package ships its own systemd `.service`/`.timer` pair for periodic
  checks, but the exact unit names have shifted across package revisions
  (`aide.timer` vs `aidecheck.timer`, both documented in the wild).
  Decided against Atropa writing a second, duplicate timer (real risk of
  the two drifting out of sync with each other's config, plus doubling
  the filesystem scan for no reason) - `detect_timer_unit()` instead
  probes the known candidate names via `systemctl list-unit-files` and
  every timer-touching function operates on whichever one is actually
  found. If a future package revision ships a name not in the candidate
  list, this correctly reports "no timer found" rather than guessing.
  - `initialize_baseline()` / `update_baseline()` are deliberately the
    same underlying mechanism (`aide --init`, then promote the generated
    database over the active one) - kept as two named entry points
    because the *meaning* to a human differs (first-time setup vs "I
    reviewed the diff and it's fine"), not because the commands differ.
  - `run_check()` and both baseline operations use
    `run_streaming_operation()` (the same live-log dialog infra as a full
    pacman upgrade or an SELinux relabel) rather than blocking silently -
    a full-tree AIDE walk can genuinely take minutes.
  - `parse_check_summary()` returns `None`, not a fabricated `0/0/0`,
    when AIDE's own summary block doesn't appear in the output (e.g. it
    errored before producing one) - a missing summary is a materially
    different, worse situation than a genuinely clean run, and the two
    must never look identical to a caller. (Corrected later: AIDE prints
    that block only when it found differences, so a genuinely clean run
    showed up as "no summary could be parsed" - see the bug-fix batch at
    the end of this section.)
  - The UI's "Update baseline" action is gated behind `self.confirm()`
    with copy that says outright it accepts everything currently reported
    as the new normal - re-baselining is the correct workflow after a
    legitimate change, but it's also exactly the action that could paper
    over a real compromise if clicked reflexively, so the friction there
    is intentional, not an oversight to streamline later.
  20 new tests (521 total), reusing `test_pacman.py`'s existing
  `subprocess.Popen`-faking pattern for the streaming calls rather than
  inventing a second one.
  **Bare-metal result:** confirmed working over 72+ hours on the user's
  real SELinux-enabled Arch install - using `aide-selinux` rather than
  plain `aide`, since the plain AUR package has had real build failures
  in the wild (confirmed via its own AUR comments - a nettle-version
  incompatibility among others) while `aide-selinux` built cleanly.
  `dependencies.py`'s note and `aide.py`'s docstring both mention this as
  a troubleshooting path now: both packages provide the same `aide`
  binary, so nothing in this module needed to change to support it.

- 🐛 **Fixed a serious bug the user caught on bare metal, not in this
  sandbox: repeated `pkexec` prompt spam severe enough to trip
  `pam_faillock`.** Two compounding causes in `main_window.py`, only one
  of them new:
  1. Every page was constructed **eagerly** at app startup (`for key,
     title, icon, page_cls in self.modules: page_widget = page_cls()`),
     and nearly every page's own `__init__()` ends with `self.refresh()`.
     For privileged pages (AppArmor's `aa-status`, and now - the part
     this session's own Phase 2/3 work made worse - Inventory &
     Hygiene's account scan and Compliance Report, both of which call
     `account_hygiene.scan_all()`) that meant every single launch fired
     off a whole batch of `pkexec` authentication prompts at once, before
     the user had clicked anything.
  2. Worse, and pre-existing: `_on_row_activated()` called
     `page_widget.refresh()` again on **every sidebar click**, even
     re-visiting a page already loaded - so normal navigation between
     AppArmor/Inventory & Hygiene/Compliance/Security kept re-triggering
     the same privileged reads over and over, not just once at startup.
  Combined, a few minutes of ordinary use (or several rapid clicks while
  trying to dismiss the prompts) was enough failed/cancelled/re-tried
  authentication attempts to trip the login lockout policy - the exact
  outcome Phase 1's `pwquality`/`faillock` work exists to prevent, caused
  by this app itself rather than a real login attempt.
  **Fix, in `main_window.py` only** (no changes needed to any of the ~20
  individual page files): pages are now constructed lazily on first
  navigation via `_ensure_page_materialized()`, so a page's initial
  `refresh()` fires exactly once, only when the user actually opens that
  tab - and `_on_row_activated()` no longer force-refreshes an
  already-materialized page on every click. The SELinux/SELinux-Load/
  Denial-Review cross-wiring (previously assuming all three always exist
  together at startup) now wires itself in whichever order the three
  pages actually get visited. **Trade-off, stated plainly rather than
  hidden**: a page no longer auto-refreshes on every revisit, so data can
  go stale between visits if you don't hit its own "Re-scan"/refresh
  button - a small, safe cost against the alternative of silent
  re-authentication spam on every click.
  **Second fix, in `account_hygiene.py`**: `_check_root_path()` was
  issuing *two* separate `pkexec cat` calls (one for
  `/root/.bash_profile`, one for `/root/.bashrc`) where one would do -
  `cat` happily concatenates multiple files in a single privileged
  invocation, and the check only ever scans the combined output for
  `PATH=` lines, never needs to know which file a given line came from.
  Cut from 2 authentication prompts to 1 for that one check; combined
  with the still-separate `/etc/shadow` read, opening Inventory & Hygiene
  now needs 2 authentications instead of 3.
  **Not fixed, and worth knowing**: visiting both Inventory & Hygiene
  *and* Compliance Report in the same session still re-runs
  `account_hygiene.scan_all()` a second time (Compliance Report folds it
  in as a category), so that's still 2 more prompts the second time
  around - no caching/memoization across pages was added. A reasonable
  next step, not attempted here since it changes staleness semantics
  further and deserved its own decision rather than getting bundled into
  an urgent lockout fix.
  **Could not be visually verified** - same GTK-less-sandbox limitation
  as everything else UI-side in this project; verified via `py_compile` +
  `ruff check` + manual trace of the exact call sequence only. Confirming
  the prompt count is actually reduced on a real launch is still owed to
  the user.

- 🐛 **Second bug from the same bare-metal session, unrelated cause**: the
  Security page's firewall toggle showed **off** with an **empty rules
  list** even when ufw was genuinely active with real rules configured -
  enabling it via the toggle worked, but the very next status read
  immediately showed it as off again. Root cause in `security.py`'s
  `firewall_status()`: it was reading `ufw status verbose` (and
  `firewall-cmd --list-all`) via `run_unprivileged()`. Both genuinely
  require root - confirmed via search, not assumed, since this needed to
  be right the first time rather than debugged over another bare-metal
  round trip - and critically, **neither fails loudly without root**:
  `ufw status` without privilege doesn't raise a clear permission error
  Atropa's own error-handling would have surfaced, it just returns
  limited/empty output, which parsed as "inactive, no rules" regardless
  of the real state. Switched both reads to `run_privileged()`;
  `systemctl is-active firewalld` is the one read in that function that
  genuinely doesn't need root, so it stays unprivileged. Every existing
  caller (`hardening.run_audit()`, `profiles.py`'s export/import,
  `quicksetup.py`'s status checks) inherits the fix automatically since
  they all go through `firewall_status()` rather than duplicating the
  ufw/firewall-cmd calls themselves.
  **Interaction with the lazy-loading fix directly above**: this
  reintroduces a privileged call into the Security page's automatic
  load path, which is exactly the kind of thing the lazy-loading fix
  was written to contain the blast radius of - but this one is
  necessary correctness, not avoidable spam, so it's not a case of
  undoing that fix. Firewall status genuinely can't be read correctly
  without root; the earlier fix's job was making sure that authentication
  only happens once, on demand, not eliminating privileged reads that are
  actually needed. `run_audit()`/Compliance Report now also pick up one
  more legitimate `pkexec` call as a result - worth knowing, not a
  regression.
  Every existing `firewall_status()` test across `test_security.py`,
  `test_compliance.py`, `test_hardening.py`, `test_profiles.py`, and
  `test_quicksetup.py` had its stubbed `["ufw", "status", "verbose"]`
  call updated to `["pkexec", "ufw", "status", "verbose"]` (10 call sites
  across 5 files) - a real, if mechanical, reminder that changing which
  privilege tier a shared backend function uses has test blast radius
  wherever that function gets called, not just in its own test file.

- 🐛 **Third bug, same family, found by the user on the SELinux Load
  Policy page**: modules in the "approved" (installed-at-some-point)
  history section showed as inactive/"reinstall" even when genuinely
  loaded - but only when Atropa itself was launched unprivileged; running
  Atropa as root showed the correct state. That launch-dependent
  symptom was the tell: identical shape to the ufw bug directly above,
  same fix needed. `list_semodules()` (`semodule -l`) was reading via
  `run_unprivileged()`, but reading the real SELinux policy module store
  needs root, and again - no loud permission error, just quietly empty
  output. `list_pending_modules()`, `list_approved_modules()`, and
  `classify_denials()` (the Denial Review page's "Already Allowed But
  Still Denied" bucket) all build their "is this actually loaded" set
  from `list_semodules()`, so all three inherited the same silent-wrong
  answer, and all three now inherit the fix automatically from the one
  function - no other code changes needed.
  Fixed by switching to `run_privileged()`. Updated all 9 stubbed
  `["semodule", "-l"]` call sites in `test_selinux.py` to the
  `pkexec`-prefixed form. Two of those tests
  (`test_reinstall_all_approved_modules_installs_only_inactive_in_one_call`
  / `..._noop_when_all_already_active`) had asserted "exactly one/zero
  privileged calls total" as a proxy for "reinstalls are batched into one
  `semodule -i` call, not one per module" - that batching guarantee is
  still true and still worth testing, but the raw call-count assertion
  needed updating to account for the now-legitimately-privileged status
  check (`semodule -l`) that runs before it; rewritten to assert the
  batching specifically (one `-i` call, or none) rather than a total call
  count that was only ever a stand-in for it.

- 🐛 **Fifth bug, different shape from the previous four - not a missing
  `pkexec`, a data-scoping mismatch**: on the Denial Review page,
  "Generate Policy for All New Denials" used a much narrower time window
  than the "Review" button that had just populated the New/Already-
  Allowed/Undefined lists it was supposedly generating policy from -
  especially bad on a system with a lot of denials from initial SELinux
  setup, where "recent" (effectively the last few minutes) catches a
  fraction of what "boot" catches. Root cause in `build_policy_review()`:
  it's called from two different places with very different intent -
  the plain SELinux page's ad-hoc "Per-Application Policy Review" button
  never passes `since` at all (wants a small, cheap, bounded "recent"
  fetch on purpose), while the Denial Review page always passes `since`
  explicitly as `self._last_review.since`, which is `None` on any system
  not using Setup Mode - the common case, since Setup Mode is opt-in. The
  function was treating "`since` omitted" and "`since=None` passed" as
  identical, so the Denial Review page's explicit `None` silently fell
  into the narrow-window branch meant only for the other caller.
  **Fix**: a sentinel default (`_SINCE_UNSET`, not `None`) that
  distinguishes the two cases. `since is not _SINCE_UNSET` now routes to
  `list_all_denials()`'s uncapped, boot-scoped fetch whenever `since` was
  passed at all - even as `None` - matching exactly what that page's own
  "Review" button had already shown. Only a truly *omitted* `since`
  (the plain SELinux page's call) still gets the narrow window. Neither
  UI page needed a code change - `selinux_review.py` was already passing
  `since=since` explicitly either way; the bug was entirely in how the
  backend function was interpreting that. Two new regression tests lock
  in the distinction directly (`since=None` passed explicitly → uncapped
  fetch, no `-n`/`--since` flag; `since` omitted entirely → the capped
  `-n <limit>` fetch), on top of the existing since-given-a-real-timestamp
  test that was already passing and stayed unchanged.

- 🐛 **Sixth bug, found immediately after the fifth by a second person
  testing the same session's build - every "New" denial on the Denial
  Review page showed `? → ?` instead of real source/target types**, even
  though the class and permission set next to it (`dir {search}`,
  `file {map}`) were parsing correctly on the exact same lines. Rather
  than guess at a regex fix, asked the user for one real raw line first -
  the response (`scontext=user_u:user_r:pipewire_t`, no `:s0` suffix at
  all) showed the actual cause immediately: `_CONTEXT_TYPE_RE_TEMPLATE`
  (`r"{field}=\S*?:\S*?:(\w+):\S*"`) required a mandatory *fourth*
  colon-separated segment after the type, assuming every SELinux context
  carries an MLS/MCS sensitivity range (`:s0`, `:s0-s0:c0.c1023`). A
  policy running without MLS/MCS - which the user's real system is -
  has exactly three parts (`user:role:type`, no range at all), and the
  old regex silently matched nothing rather than erroring, which is
  exactly why `comm=`/`tclass=`/the permission set (parsed by separate,
  unrelated regexes) kept working while only the context-type extraction
  went blank - the tell that pointed straight at this one regex instead
  of a broader parsing failure.
  **Fix**: `r"{field}=[^:\s]+:[^:\s]+:([^:\s]+)"` - `[^:\s]` (can't
  consume a colon) instead of `\S*?` is what makes the trailing range
  genuinely optional rather than assumed: the type-capturing group
  naturally stops at the next colon if a range follows, or at whitespace
  if it doesn't, with no lookahead needed for either case. Verified
  against all three real shapes before touching the test suite: no range
  (the user's actual line), classic `:s0`, and a full MCS range
  (`:s0-s0:c0.c1023`) - all three now extract the type correctly. One new
  regression test uses the user's exact raw line verbatim, alongside the
  existing `:s0`-suffixed fixtures (unmodified, still passing, confirming
  no regression on the format every other test already covered).
  **Why this shipped in the first place**: every existing test fixture
  for this code path used the classic `scontext=...:s0` shape, so the
  gap was invisible to the whole suite - a real reminder that CIS-style
  correctness (does the regex match what a *real, currently-running*
  system emits) and test-suite-green correctness (does it match what the
  test fixtures assume) aren't automatically the same thing, especially
  for a format as build-configuration-dependent as SELinux context
  strings.

- 🐛 **Seventh bug, a correctness/safety issue rather than a display
  glitch**: "Try restorecon" on a Denial Review "New" row ran restorecon
  against a bare filename (`journal`) instead of a real path, which
  restorecon then resolved relative to whatever the privileged process's
  own working directory happened to be (`/root` in the actual report) -
  `lstat(/root/journal) failed: No such file or directory`. Root cause in
  `_extract_path()`: it fell back from `path="..."` (always a genuine
  absolute path when present) to `name="..."` unconditionally - but
  `name=` is frequently just the bare directory-entry name being looked
  up (common for `search`/`getattr` denials on a directory), not a path
  at all. **Worth being explicit about the severity**: this wasn't just a
  loud failure waiting to happen - if a file happened to exist with that
  same bare name relative to the resolved working directory, restorecon
  would have "succeeded" against the *wrong file entirely*, silently.
  A visible error was the lucky outcome, not the actual risk.
  **Fix**: only accept `name="..."` as a fallback path when it's already
  absolute (`startswith("/")`) - a bare name now correctly returns `None`,
  matching the existing (and already-correct) "no path available" state
  shown for denials with neither field. `sample_path` has exactly one
  consumer in the whole codebase (`_on_try_restorecon`'s button), so this
  fix has no other blast radius to trace through.
  One existing test (`test_group_denials_extracts_context_types_and_path`)
  had actually been asserting the buggy behavior (`sample_path == "a"`
  from a bare `name="a"`) - updated to assert the correct `None`, with the
  reasoning for why documented inline rather than just changed silently.
  Three new tests cover the real path field (extracts correctly), a bare
  `name=` (now `None` - the exact shape of the reported bug, using a
  `journald`/`journal` denial deliberately close to the real report), and
  an already-absolute `name=` (the rare case that's still safe to use).

- ✅ **SELinux page: lock-before-toggle on the enforcing/permissive
  switch**, requested by the user directly (not a bug report). The switch
  now starts locked (insensitive) on every status refresh; a lock icon
  button (`changes-prevent-symbolic` / `changes-allow-symbolic` - real
  GNOME icon-theme names, confirmed via search rather than guessed, since
  a wrong name here would just render a blank icon with no error) must be
  clicked to arm it before it accepts input at all. This sits on top of
  the existing confirm dialog, not instead of it - the dialog stops a
  confirmed request from completing, the lock stops an accidental
  drag/click from registering as a request in the first place. One
  unlock click authorizes exactly one change: the lock re-engages after
  any attempt (success, failure, or cancel), not just once per session.
  **A real, separate, pre-existing bug got fixed in the same pass**,
  found by tracing through the exact code being touched anyway: the
  `state-set` handler previously returned `False` unconditionally,
  which - per GTK's own contract for that signal - means the *default*
  handler always applies the requested visual position regardless of
  what the confirm dialog's response was. Cancelling "Switch to
  Permissive mode?" left the switch showing Permissive even though
  `set_mode()` was never called, until the page happened to be refreshed
  again. Fixed by returning `True` (taking over state application
  entirely) and explicitly restoring the switch's prior position via
  `set_active()` in a new `on_cancel` path. Extended `BasePage.confirm()`
  (used by 37 call sites across the codebase) with an optional
  `on_cancel` callback to support this, rather than hand-rolling a second
  `Adw.AlertDialog` construction in `selinux.py` - backward compatible,
  since it's a new keyword-only parameter with a default of `None` that
  every existing caller already omits.
  After a mode-change attempt, the switch re-syncs from a fresh
  `sestatus` read rather than trusting its own last-dragged position -
  `handle_command_result()` already does this via its own `refresh()`
  call on success, so `_on_mode_set_done()` only issues its own
  explicit re-fetch on the failure path, to avoid a redundant duplicate
  `sestatus` call on the (more common) success path.
  **Could not be visually verified** - same GTK-less-sandbox limitation
  as every other UI change in this project.

- 🐛 **Eighth/ninth bugs, both surfaced by the user's own screenshot of
  the freshly-shipped lock feature - real `sestatus` output is
  lowercase, and two separate pieces of code compared it against
  Title-case.** Real `sestatus` prints `Current mode: enforcing` -
  always lowercase, confirmed both by the user's own screenshot and by
  `backend/selinux.py`'s own test fixture, which already correctly
  asserted `status.mode == "enforcing"`. Two places compared that value
  against `"Enforcing"`/`"Permissive"` (Title-case) instead, so neither
  ever matched on any real system:
  1. **The SELinux page's mode toggle** - `_mode_toggleable` and
     `set_active()` both used the Title-case comparison, so on a real
     system the lock button itself came back permanently disabled (not
     just "shows the wrong position" - the lock feature shipped
     unusable on the exact system it was built for), and the switch
     always rendered off regardless of actual mode. This bug predates
     the lock-toggle work in this same session, but that work is what
     made it fully block the feature rather than just cosmetically
     mis-render.
  2. **`hardening.py`'s Compliance Report SELinux check** - the more
     consequential of the two, since it feeds a scored, exportable
     report rather than just a UI toggle. A fully enforcing SELinux
     setup silently fell through to the generic `warn: Mode: enforcing`
     branch instead of `pass`, on every real system, not just the
     user's. The existing test for this function never caught it because
     it only checked that a `"SELinux"` key existed in the results, run
     in a sandbox where SELinux isn't available at all - the buggy
     branch was never actually exercised.
  **Fix**: both now compare against `.lower()`'d mode strings. Added two
  new `hardening.py` tests that actually exercise the enforcing/permissive
  branches with real lowercase mode values (monkeypatching
  `selinux_mod.get_status()` directly) rather than relying on the
  "SELinux available" path, which the existing test infrastructure
  couldn't exercise in this sandbox. Also corrected the misleading
  Title-case example in `SelinuxStatus.mode`'s own docstring comment,
  which is very likely where the mistake originated from in the first
  place - a comment documenting the field as `"Enforcing" | "Permissive"`
  when the code beneath it never actually returns that casing.
  **Not touched**: the unrelated `mode="Disabled"` sentinel `get_status()`
  returns when SELinux isn't available at all (not sourced from real
  sestatus text, and nothing compares it case-sensitively against parsed
  output) - left as Title-case since changing it would only be cosmetic
  and would require updating an already-correct passing test for no
  functional gain.

- ✅ **Installer fix + new feature: build/install/activate a custom
  SELinux Reference Policy source tree**, both from the same debug
  session as the last two entries.
  **Installer**: `install.sh` no longer uses
  `pip install --user --break-system-packages` - that overrides Arch's
  PEP 668 protection and dumps Atropa into `~/.local`'s shared *user*
  site-packages with no isolation and no clean uninstall path. Now uses
  `pipx install --system-site-packages --force .` (`python-pipx` added to
  the pacman dependency list). `--system-site-packages` is the part that
  actually matters for a GTK app specifically: Atropa's one real
  dependency, PyGObject, has to match the system's own GTK4/libadwaita
  (installed via pacman in the same script) - it can't be pip-built fresh
  in an isolated venv without matching system dev headers, so the venv
  instead inherits the system's already-working PyGObject rather than
  trying to rebuild it. `README.md`'s install section documents this.
  **New feature**: new `backend/refpolicy_build.py` + new
  `pages/refpolicy_build.py`, for a refpolicy fork/source tree the user
  maintains themselves (their `atropa-refpolicy`, with Arch-specific
  paths/contexts already fixed upstream refpolicy doesn't ship) - not for
  installing a prebuilt AUR package, which stays the existing "install it
  yourself first" posture used everywhere else in Atropa for AUR-only
  tooling (see the AIDE Phase 3 write-up above for the precedent this
  follows). Confirmed the exact make targets by reading
  `doc/BUILD_INSTALL.md` from the user's own source tree rather than
  guessing, and confirmed via their `build.conf` (`MONOLITHIC = n`) that
  the *modular* target set applies (`conf`/`all`/`install`), not the
  monolithic one (`policy`/`install`/`relabel`) - a source tree with
  `MONOLITHIC = y` isn't detected or handled by this module.
  Three genuinely different risk tiers, kept as three separate
  functions/UI actions with separate confirmations rather than one
  "build my policy" button:
  1. `build()` - `make conf all`, entirely **unprivileged** - compiles
     into the source tree's own build artifacts only, zero effect
     anywhere else on the system. Required adding a genuinely missing
     primitive to `privilege.py`: `run_unprivileged_streaming()` - there
     was `run_unprivileged()` (blocking) and `run_privileged`/
     `run_privileged_streaming()`, but nothing for a long-running
     *unprivileged* operation (a full modular refpolicy build can take
     several minutes). Refactored `run_privileged_streaming()`'s Popen/
     line-streaming logic into a shared private `_run_streaming()` rather
     than duplicating it, so both public functions share one
     implementation and only differ in whether a pkexec prefix gets
     prepended before it's called.
  2. `install()` - `make install`, privileged (writes under
     `/etc/selinux/NAME` and `/usr/share/selinux/NAME`), but does **not**
     touch `/etc/selinux/config` or load anything into the running kernel
     policy - the system keeps running whatever it was running before
     this step. (Corrected later: in a modular build `make install` alone
     never builds the compiled policy or the policy store, so Activate
     pointed `SELINUXTYPE` at a policy with nothing to load. It is `make
     install load` now, and Activate checks, validates and orders its steps
     differently - see the second bug-fix batch at the end of this section.)
  3. `activate()` - the consequential one, and the one that took the most
     care. Sets `SELINUXTYPE=` in `/etc/selinux/config` (backed up first,
     same `backup_file()` + `sed -i -E` pattern `set_mode()` already uses
     for `SELINUX=`), maps the `__default__` login to a given SELinux
     user (`unconfined_u` by default) via `semanage login`, and schedules
     a relabel by reusing `selinux.relabel_filesystem()` rather than
     duplicating it. The login-mapping step is there specifically per the
     user's own instruction: a targeted-style policy's whole design
     assumes interactive logins land in `unconfined_t` - a policy that
     built and installed *correctly* would still put a real login into
     the wrong (likely far more restrictive) domain without this step,
     silently breaking the desktop session rather than erroring
     anywhere obviously. `semanage login -a` (add) is tried first, and
     only falls back to `-m` (modify) if `-a` fails because a mapping
     already exists - most systems ship *some* default mapping already,
     so treating "already defined" as a hard failure would make this
     step fail on the common case. Returns one `CommandResult` per step
     (config edit, login mapping, relabel) rather than one opaque
     pass/fail, and stops immediately if any step fails rather than
     proceeding to schedule a relabel on top of a login mapping that
     never actually got set.
  **What this explicitly does NOT do, per the user's own instruction**:
  no kernel boot parameter or bootloader config is ever touched by any of
  this, and nothing here triggers a reboot - the policy switch and
  relabel only take effect after one, and that's the user's call to make
  on their own schedule, not Atropa's to force. A dedicated regression
  test (`test_activate_never_touches_kernel_or_bootloader_config`) greps
  every call `activate()` makes for bootloader/kernel-related substrings
  and fails loudly if any future change to this function ever
  reintroduces one.
  **Also explicitly out of scope, and said so directly rather than
  silently ignored**: the user separately shared a
  `selinux-enforce-after-drivers-nvidia-workaround.service` unit (a
  personal diagnostic tool for bisecting an nvidia+SELinux boot-order
  issue, flipping enforcement mid-boot via a non-standard path
  specifically to avoid a kernel param) - not built into a feature, since
  it's a one-off debugging hack for one specific issue rather than a
  generalizable capability, and "flip your MAC framework's enforcement
  through an unconventional boot-time path" isn't a precedent worth
  setting as a first-class button regardless.
  14 new tests for `refpolicy_build.py`, 5 new tests for
  `run_unprivileged_streaming()` in `test_privilege.py` (mirroring the
  existing `run_privileged_streaming()` test suite's exact structure).
  One real test-authoring mistake caught and fixed while writing these:
  an early draft used the `fake_run` fixture (which patches
  `subprocess.run`) for `build()`/`install()`'s streaming calls, which go
  through `subprocess.Popen` directly and are never touched by that
  fixture at all - the tests passed for the wrong reason (never actually
  exercising the code path) until run, at which point they failed loudly
  with a `PrivilegeError` rather than silently passing; fixed by
  reusing `test_aide.py`'s existing `subprocess.Popen`-mocking pattern
  instead.
- ✅ **Batch `.te` import**, same session as the two entries above.
  `import_te_files(paths)` in `selinux.py` + an "Import .te files…"
  button on the Load Policy page, for compiling a whole pre-written
  collection of `.te` files at once (the motivating case: the user's own
  `atropa-refpolicy-addon` bundle) rather than pasting/loading them one
  at a time through the existing single-file flow. Lands in the same
  Pending queue `build_policy_review` already uses, and deliberately
  does **not** install any of them directly - the single-file
  paste/load-then-Compile-&-Load flow gets to assume "the person
  clicking Compile just read this file"; a multi-file batch pulled from
  disk doesn't get that assumption, so it always stops at Pending for
  individual review same as everything else does. Per file: compiles via
  the same unprivileged `checkmodule`/`semodule_package` pipeline as the
  rest of the SELinux module; a bad file (unreadable, unparseable/invalid
  module name, fails to compile) is recorded with its own error and
  skipped, rather than aborting the whole batch over one bad input.
  Module name resolution prefers the file's own `module <name>
  <version>;` declaration line (matching `audit2allow`'s own output
  format, which is what these files typically already are) and only
  falls back to the filename stem if that line isn't present.

- 🐛 **Bug-fix batch from a full-repo audit** - six fixes, each with
  regression tests verified to fail against the previous code. The common
  thread: the old tests passed because their fixtures shared the code's own
  assumptions (a `system-login` that names `pam_faillock` directly, a
  `visudo` that succeeds unprivileged, an AIDE "Summary" block on a clean
  run) - fixtures for parsed output should come from real Arch systems or
  upstream sources, not from what the code expects.
  1. **Tests wrote into the real home dir** - see section 4:
     `privilege_paths` is now autouse and the action-log handler resolves
     `LOG_PATH` per record.
  2. **Quick Setup could enable the firewall without the SSH rule** -
     `_apply_firewall()` ignored `firewall_allow_port()`'s result, so a
     dismissed prompt or a ufw error still led to deny-by-default with no
     SSH rule (the remote lockout the allow-first ordering exists to
     prevent). It now stops. firewalld ports go through
     `firewall-offline-cmd` while the daemon is stopped (otherwise that check
     would have failed the step for every firewalld user), and a failed
     `--reload` is reported.
  3. **Profile import turned "unknown" into "no"** - a profile exported
     from a stock `sshd_config` records `unknown` (OpenSSH defaults apply),
     and import mapped anything but `yes` to `no`: password login got
     disabled on the importing machine. Unknown/invalid values are now
     skipped; see the Security Profiles summary in section 2 for the rest
     (exact `PermitRootLogin`, explicit-only port, AppArmor 4 modes,
     non-boolean SELinux values, section isolation).
  4. **Four checks reported the wrong result** - faillock "not wired" on
     every stock Arch install (only `system-login` was read; pambase puts
     it in `system-auth`), sudoers always "Permission denied" (unprivileged
     visudo), a failed `arch-audit` scored as "no known vulnerabilities",
     and a clean AIDE check showed "no summary could be parsed". All four
     fixed; the Compliance sudoers row is now `fail` on a real visudo
     error and unscored `info` when authentication is dismissed.
  5. **Setup Mode's time window** - journalctl read the stored UTC time
     as local time (5h late in US Eastern), and ausearch rejected its
     single "date time" `-ts` argument as an invalid time, which went
     unnoticed, so Setup Mode reviews got nothing from the audit log.
     Now `--since @<epoch>` and epoch filtering of audit records; ausearch
     also gets `--input-logs` (with a piped stdin it otherwise reads
     records from stdin).
  6. **Wi-Fi password on the command line** - visible via `ps` and stored
     in plain text in `actions.log` (and the Activity page). Now
     `nmcli --ask` with the password on stdin. Logs written before this
     fix may still contain `wifi connect <ssid> password <pw>` lines.

- 🐛 **Second bug-fix batch from the same audit** (PRs #3, #4 and #6,
  fourteen commits). The thread through most of them: Atropa reported or
  changed something other than what the system actually uses - a config
  value the daemon doesn't read, a file that exists but isn't in effect, a
  switch showing a state that was never applied. The detail for each is in
  section 2 under its module; this is the list.
  1. **`sshd_config` is read and edited the way sshd reads it** - first
     value wins, `Include` and `Match` honoured. Drop-ins and `Match` blocks
     could make Atropa report settings sshd wasn't using, and the audit
     passed them; the old `sed` rewrote lines inside `Match` blocks and
     appended new keys into whatever block came last. Edits are now a
     read-modify-write of the global section, with the original written
     back if `sshd -t` rejects the result.
  2. **Risky one-click changes ask first, and switches stay truthful** -
     `BasePage.apply_switch()` and `run_action()` (section 3), lock and
     delete guards on Users, stop/disable confirmations on Services, a
     root-login choice that no longer passes through "yes".
  3. **No partial upgrades from the Packages page** - "Refresh database"
     (`pacman -Sy`) and "Update only this" are gone, "Check for updates"
     uses `checkupdates`, and `install()` refuses while the database is
     ahead. AUR search results no longer get an Install button that could
     only fail.
  4. **Four checks report what's in effect** - sysctl hardening reads live
     values and leaves stricter ones alone, AppArmor asks the kernel's LSM
     list, the compliance total counts every check, and the root `PATH`
     check survives a missing dotfile.
  5. **AppArmor edits roll back when the parser rejects them**, and both
     denial pages can read the audit log, where denials go while auditd
     runs. The SELinux docstring that claimed AVCs reach the kernel log
     regardless was wrong.
  6. **Review modules are `atropa_<program>_<domain>`**, grouped by domain
     as well as program - a generated `ssh.pp` replaced the policy's own
     `ssh` module when installed.
  7. **refpolicy Install produces a bootable policy** (`make install load`)
     **and Activate is safe**: plain name only, compiled policy required,
     login mapping in the new store first, config put back if the relabel
     can't be scheduled.
  8. **USBGuard generation can't leave an empty policy** (which blocks
     every device, keyboards included), **systemd-boot is found wherever
     the ESP is mounted**, and timeout edits work on a commented-out line.
     (Corrected later: the new detection matched every UEFI machine, the
     ones that boot GRUB included - see the bootloader entry below.)
  9. **Timeouts hold** (section 1), **root-only directories don't crash**
     (`privilege.path_exists()`), and **the progress dialog can be hidden**.
  10. **One command where one will do** - one `auditctl -l` for all audit
      rule sets (five prompts on opening the Hardening page before), one
      `systemctl show` for every service's enabled state, one `setsebool`
      for a profile's booleans.
  11. **SELinux package names and install guidance corrected** - the tools
      are AUR-only and several aren't in the package their name suggests;
      a SELinux that is disabled in the kernel counts as unavailable.
  12. **Tests don't depend on the host's kernel** - the autouse
      `kernel_state` fixture (section 4). One test had failed in CI since
      the initial commit because GitHub's runners have AppArmor on.
  13. **No root shell is left** - the last two `bash -c "echo ... >> file"`
      appends became `tee -a` with the line on stdin.

- ✅ **App icon, icon names and one more test leak** (PRs #9-#11). The logo
  is the app icon - window, launcher and README (layout in section 1,
  `tests/test_resources.py` in section 4). Three icon names that the stock
  Adwaita theme doesn't have rendered blank and were replaced (the note in
  section 7). `test_apply_sysctl_hardening_requires_selection` ran real
  `sysctl` until it was given `fake_run` (section 4).

- 🐛 **GRUB on a UEFI machine was reported as systemd-boot.** Since the
  second batch, `bootloader.detect()` said systemd-boot whenever `bootctl`
  was installed and either the `LoaderInfo` EFI variable existed or an ESP
  was found. Both are true of a UEFI machine that boots GRUB: every UEFI
  machine has an ESP, `bootctl` comes with systemd, and GRUB has set
  `LoaderInfo` itself since 2.12. There the Bootloader page named the wrong
  bootloader, "Apply" wrote the timeout to `loader/loader.conf` on the ESP
  instead of `/etc/default/grub`, and "Regenerate" ran `bootctl update`.
  Detection now reads what `LoaderInfo` says, and without it goes by what's
  installed, GRUB first (the Bootloader summary in section 2). Found by
  reading the code against this document and shown with simulated setups;
  not yet checked on real GRUB/UEFI hardware. The tests had missed it
  because none of them had `bootctl` and GRUB installed together, which is
  every real GRUB machine.

**Still open:**
- `su` restriction to the wheel group (CIS 6.1.x) - deferred from Phase 2
  since it requires the same kind of live PAM edit (`/etc/pam.d/su`) that
  Phase 1 already declined to automate; a natural pairing for whenever
  real PAM-wiring automation (below) gets built, since at that point
  there'd already be a safe, tested pattern to extend rather than a new
  one-off risk
- Bootloader/AppArmor kernel-param and PAM-wiring automation, **now that a
  backup mechanism exists** to lean on — could pair with e.g. keeping the
  previous kernel cmdline as a separate boot entry so a bad boot just picks
  the old one instead of needing a recovery shell
- Disk/partition management (explicitly out of scope at project start)
- Btrfs snapshots / Timeshift integration ("snapshot before this risky op" is
  a very YaST-shaped feature, pairs with the backup mechanism)
- Journal/log viewer (already shell out to `journalctl` in several places,
  never surfaced as its own page)
- Kernel management (multiple kernels, `mkinitcpio`, headers)

**Still open from the full-repo audit** (rough priority order):
- Check bootloader detection on a real UEFI machine that boots GRUB: the
  fix above rests on GRUB 2.12 writing "GRUB ..." to `LoaderInfo` and on
  `bootctl --print-esp-path` answering there, neither of which could be
  run where it was written
- UI for what the README promises but no page offers yet: setting a user's
  password, managing groups, a service's journal, cleaning up orphan
  packages (`pacman.list_orphans()` exists, nothing calls it), and
  disabling USBGuard
- CI: a GTK smoke test that builds every page under Xvfb (the backend
  suite never imports GTK), Python 3.13/3.14 in the matrix next to
  3.11/3.12, and tests that run the parsers against real config files
  rather than hand-written snippets
- Packaging: `install.sh` doesn't install `pacman-contrib` or `fakeroot`,
  so "Check for updates" falls back to `pacman -Qu` until they're installed
  from the Dependencies page. `atropa.desktop` lists two main categories
  (`Settings;System;`), which `desktop-file-validate` flags because the app
  may show up twice in menus
- Quick Setup's status summary fails as a whole when one item's check
  raises: with SELinux in the kernel but no `sestatus` installed, the page
  shows a "Couldn't check current status" toast instead of the other
  items' status
- The single privileged helper (see Architecture): one root helper per
  operation instead of one pkexec prompt per command. Its design gets
  agreed before any code. It is also where backups should move to
  root-owned storage: `restore_file()` only writes to the files Atropa
  backs up, but anything running as the user can still change a backup's
  contents in `~/.local/share/atropa/backups`

---

## 7. Practical notes for continuing this project

- **Dev setup**: the backend and tests need no GTK. In a virtualenv:
  `pip install pytest ruff` (or `pip install -e '.[dev]' ruff` if PyGObject
  is available). Avoid `--break-system-packages` on Arch.
- **Compile check** (same command CI runs):
  `python3 -m py_compile atropa/*.py atropa/ui/*.py atropa/ui/pages/*.py atropa/backend/*.py tests/*.py`
- **Run the test suite**: `python3 -m pytest -q` from the project root.
  Lint with `ruff check .` (config in `pyproject.toml`, `E9`/`F`/`W` only).
  All three run in CI on push/PR to `main`.
- **After any edit near an existing function**: `grep -n "^def <name>"
  <file>` to confirm you didn't just create a duplicate
- **Icon names**: use only names the stock Adwaita theme ships (list them
  with `ls /usr/share/icons/Adwaita/symbolic/*/`). A name the theme lacks
  renders as a blank space with no error - `emblem-ok-symbolic`,
  `shield-symbolic` and `puzzle-piece-symbolic` all did.
- Real install on the user's Arch machine: `./install.sh`, or for
  fast iteration, straight from source: `python3 -m atropa.main`
  (requires `python-gobject gtk4 libadwaita polkit` from pacman)
- The user's actual test system runs **SELinux via `refpolicy-arch`** (an AUR
  policy), not AppArmor — verified `sestatus` parsing against their real
  output (mode `enforcing` — `sestatus` prints it lowercase, see the
  eighth/ninth bug entry — policy `refpolicy-arch`, MLS `disabled`)
