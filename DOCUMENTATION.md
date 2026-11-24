# Atropa — Technical Documentation

The technical reference for Atropa: how it is put together, what each
module does and why, and what to know before changing it. `README.md` is
the user-facing introduction and [`TODO.md`](TODO.md) lists what is still
open. The project's working history - phase write-ups, bug-fix entries and
design specs, kept for the reasoning behind decisions - is in
[`docs/HISTORY.md`](docs/HISTORY.md); it isn't kept up to date with the
code, this file is.

Size: **about 24,500 lines of Python - 41 backend modules, 33 pages plus
the plugin page, and the root helper - and a 1,634-test pytest suite
(about 15,400 lines).**

**Contents:** 1. Architecture · 2. Module reference (2a Core, 2b Security,
2c Maintenance) · 3. UI conventions · 4. Testing · 5. Known limitations ·
6. Working on Atropa

---

## 1. Architecture

```
atropa/
  main.py                     Adw.Application entry point (app ID org.atropa.Atropa)
  helper.py                   the root helper, installed twice (atropa-helper and
                              atropa-helper-ask in /usr/lib/atropa/): what pkexec runs
  ui/
    main_window.py            sidebar (Adw.NavigationSplitView) + Gtk.Stack of pages;
                              MODULES = Module(key, title, icon, page, tagline, section);
                              pages are built the first time they're opened
    theme.py                  loads resources/style.css
    selinux_lint.py           lint badge, findings text and the acknowledge-to-install dialog
    selinux_module_view.py    the module view shared by SELinux: Denials and Modules
    pages/
      __init__.py             BasePage (shared scaffolding) + esc() markup helper
      <one file per sidebar entry>, plugin_page.py (a page built from a plugin manifest)
  backend/                    no GTK anywhere; every module wraps commands through privilege.py
    privilege.py              run_(un)privileged[_streaming], helper routing, backups, action log
    pacman.py news.py system_health.py rollback.py snapshots.py pacnew.py mirrors.py
    system_config.py network.py users.py services.py bootloader.py kernel_params.py kernels.py
    security.py hardening.py audit_rules.py boot_security.py compliance.py inventory.py
    account_hygiene.py aide.py quicksetup.py profiles.py apparmor.py
    selinux.py denial_advice.py te_lint.py selinux_programs.py refpolicy_build.py
    boot_report.py disk_health.py firmware.py power.py sleep.py flatpak.py
    dependencies.py plugins.py plugin_registry.py migration.py
  resources/
    atropa.desktop            launcher
    style.css                 visual layer (Adwaita named colours only)
    icons/hicolor/<N>x<N>/apps/org.atropa.Atropa.png
    org.atropa.pkexec.policy  two polkit actions: atropa-helper with auth_admin_keep,
                              atropa-helper-ask with auth_admin
tests/                        pytest: test_<module>.py per backend module, the helper,
                              stock config files and real SELinux drafts as fixtures,
                              and a GTK smoke test
packaging/arch/PKGBUILD       atropa-git (main); packaging/arch/atropa/PKGBUILD: tagged release
install.sh                    installer for a source checkout (deps, helpers, policy, pipx)
examples/plugins/             annotated plugin manifest (parsed by a test)
.github/workflows/ci.yml      ruff + pytest on Python 3.11-3.14, GTK smoke test under Xvfb
```

The sidebar (`MODULES` in `main_window.py`), by section:

- **Core**: Package Management, System, Network, Services, Bootloader,
  Kernels, Users & Groups
- **Security**: Security Quick Setup, Security Profiles, Security,
  Hardening, Encryption & Secure Boot, Compliance Report, Inventory &
  Hygiene, File Integrity, AppArmor, SELinux, SELinux: Modules, SELinux:
  Denials, SELinux: Build Policy
- **Maintenance**: Config Changes, Package History, Snapshots, Boot Report,
  Disk Health, Firmware, Mirrors, Power, Flatpak, Dependencies, Add-ons,
  Activity & Backups
- **Extensions**: one entry per enabled plugin

### Why the backend/ui split exists
`backend/*.py` has **zero GTK imports**. Every function is a plain Python
wrapper around a `subprocess` call (via `privilege.py`), returning either a
`CommandResult` dataclass or a typed dataclass of parsed data. This means:
- Every backend function is independently testable by faking the one
  function that starts commands (`privilege._subprocess_run`) — no display
  server, no GTK, no root needed.
- `ui/pages/*.py` never runs a command directly; it only calls into `backend/`.

### Privilege model

The app runs as a normal user, never as root. `backend/privilege.py` is the
**only** place that escalates:

```python
run_unprivileged(argv, input_text=None, timeout=120)   # current user
run_privileged(argv, input_text=None, timeout=600)     # through pkexec (sudo -A if there's no pkexec)
```

Commands are argument lists, never a shell, so nothing in a package name,
username or URL can become a second command. `tests/test_privilege.py`
enforces that by walking the AST of every module.

**The helper.** pkexec picks a polkit action from the program it runs, so
running tools directly (`pkexec tee`, `pkexec systemctl`, ...) hit the
generic `org.freedesktop.policykit.exec` action, which asks every time.
Instead every privileged call goes through `atropa/helper.py`, installed
root-owned at `/usr/lib/atropa/atropa-helper`. The shipped policy
annotates that path with its own action and `auth_admin_keep`, so one
password covers polkit's keep window (five minutes by default) and a
multi-step change asks once. Without the helper - a source checkout - calls
fall back to direct pkexec and ask per command; nothing breaks.

Caching authorization makes the helper's reach what a process running as
the user gets for free during the keep window, so it is kept narrow:

- **A validator per program.** `COMMANDS` maps every program Atropa runs as
  root to a validator that accepts exactly the argument shapes the backend
  sends (`systemctl VERB UNIT` with a unit *name*, `pacman` repository
  operations by package name, `nmcli` with the properties Atropa sets,
  `sbctl sign -s` only under `/boot` or `/efi`, ...). Anything else is
  refused - including what someone reusing a cached authorization would
  want: `pacman -U` outside the package cache, `--config`/`--hookdir`,
  `systemctl link`, `sysctl -w`, `make` targets other than `install load`,
  `grep -r` over `/etc`. Programs resolve through a fixed `PATH`.
- **File writes are done by the helper**, not by exec'ing a tool: `tee`,
  `tee -a`, `install -m MODE /dev/stdin FILE` and `replace-in-file PATH
  PATTERN REPLACEMENT` (in place of `sed -i`; `sed` is refused, since a sed
  script can write any file). The destination must be in `WRITE_FILES` or
  under `WRITE_DIRS`, or one of a few exact patterns (systemd-boot's
  `loader.conf` and `loader/entries/*.conf` under `/boot` or `/efi`, a
  battery's `charge_control_end_threshold`); relative paths, `..` and
  symlinked targets are refused. `cp`, `mkdir`, `touch`, `rm` and `chown`
  validate their paths first. `tests/test_helper.py` fails when a path the
  backend writes is missing from the policy.
- **Operations instead of programs** where a program would be too broad:
  `shadow-status` (which accounts have empty/locked/set passwords - never
  the hashes; `cat /etc/shadow` is refused), `pacnew-apply`/`pacnew-remove`
  (only a regular `*.pacnew`/`*.pacsave` under `/etc`, never the account
  databases), `backup-show`/`backup-restore`, `modules-leftover-remove`,
  `grub-keep-previous`, `loader-entry-remove`.
- **Two tiers.** Some of Atropa's own operations are root-equivalent
  whatever their arguments: a password for root, a member for wheel, an
  SELinux module or mode, the policy build (`make install load` runs the
  tree's Makefile), package downgrades (`pacman -U` from the cache), and
  writes to files whose content can run code as root (`pacman.conf`,
  `sshd_config`, `/etc/default/grub` and boot entries, the PAM files,
  `/etc/selinux/config`, the sysctl and fail2ban files, AppArmor profiles,
  snapper's configs). Those are tier ASK: the keep helper refuses them, and
  `privilege.py` (asking `helper.needs_fresh_auth()`) sends them to a second
  copy, `atropa-helper-ask`, whose action is plain `auth_admin` - it asks
  every time. The helper knows which copy it is from the path the kernel
  exec'd. `privilege.authenticate()`, used to unlock controls, is ASK too.

What a cached authorization can still do is Atropa's keep-tier work: stop
or disable any unit; start, restart or enable only `MANAGED_UNITS`
(starting an arbitrary unit isn't safe: `debug-shell.service` is a root
shell on tty9); install or remove a repository package; change hostname,
time, keymap, firewall ports, booleans, AppArmor modes; write the managed
files that aren't root-equivalent. Admin power, but no code an attacker
controls runs as root. `tests/test_helper_shapes.py` runs the backend
functions that build argv at runtime and checks each against the helper in
its expected tier, plus a list of attack shapes that must be refused.

**Timeouts hold, even for a root child.** Commands start in
`privilege._subprocess_run()` (`subprocess.run()`'s interface over
`Popen`). `subprocess.run()` waits without a limit after killing a timed-out
child, and a child of pkexec runs as root, so the kill raises
`PermissionError` and the wait never returned. Such a child is now left
running and reported: `PrivilegeError` names its PID. The streaming runners
read output on a separate thread so their timeout counts while the command
runs.

**Commands print the same on every system.** Every command runs with
`LC_ALL=C.UTF-8` and without `LANGUAGE` (`privilege._command_env()`),
because Atropa parses output that tools translate (`pacman -Ss` translates
its `[installed]` marker). pkexec and sudo pass these on.

**Every command is logged**, privileged or not, to
`~/.local/share/atropa/actions.log` (`RUN: <argv>`, `FAILED (<rc>): ...`,
backup and restore events), browsable on Activity & Backups.

### Backups, and putting things back

The helper backs a file up itself, as root, right before it overwrites it:
`tee`, `install`, `replace-in-file` (when it changes something) and
`pacnew-apply` first copy any existing regular file under `/etc` (and
systemd-boot's `loader.conf`), up to 1 MiB, into `/var/lib/atropa/backups`
(`helper.backup_before_write`). A symlink is never followed into the store.

- The directory and `manifest.jsonl` are `0755`/`0644` root - names and
  paths only, so the app lists backups without a password; each
  `<name>.<timestamp>.bak` is `0600` root.
- One backup per operation: a write within 60 seconds of the last backup of
  the same file belongs to the same operation, so a multi-step edit leaves
  its starting state. The newest 30 backups of each file are kept.
- A failed backup (a full disk) is reported on stderr and doesn't stop the
  write.
- `backup-show NAME` prints a backup only of a file `cat` may read.
  `backup-restore NAME PATH` writes it back: `PATH` must be the one the
  manifest recorded and pass the write policy, its tier is that of writing
  `PATH`, and the file being replaced is backed up first so a restore can
  be undone. The content never passes through the app.

Without the helper, `privilege.backup_file(path)` copies into
`~/.local/share/atropa/backups` as before. Backups there can be changed by
anything running as the user, so with the helper installed they are shown
("kept in your home folder") but not restored. `list_backups()` merges both
stores; `restore_file()` only writes paths `restorable()` accepts.

**Edits that can leave a broken system behind check and put things back.**
`_set_sshd_option` runs `sshd -t` before reloading, and writes the original
text (held in memory) back if validation fails - sshd is never reloaded
with a bad config. The same write-back covers an AppArmor profile
`apparmor_parser -r` rejects, a GRUB change after which `grub-mkconfig`
fails, a `pacman.conf` that `pacman-conf` can't read back, and a refpolicy
activation whose relabel can't be scheduled. Each says plainly when the
write-back failed too. Kernel parameters go further and keep a bootable
entry with the old ones (see Kernel parameters).

### Markup escaping
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

## 2. Module reference

### `privilege.py` (foundation, not a sidebar page)
```python
CommandResult(returncode, stdout, stderr)          # .ok property = returncode == 0
run_unprivileged(argv, input_text=None, timeout=120) -> CommandResult
run_privileged(argv, input_text=None, timeout=600)   -> CommandResult   # via pkexec, else sudo -A, else PrivilegeError
authenticate() -> CommandResult                      # asks for the admin password, changes nothing (runs `true` as root)
run_privileged_streaming(argv, on_line, input_text=None, timeout=1800)   -> CommandResult   # live line-by-line output
run_unprivileged_streaming(argv, on_line, input_text=None, timeout=1800) -> CommandResult   # same, no escalation
path_exists(path) -> bool | None                     # None = can't tell
backup_file(path) -> str | None                      # None with the helper (it backs up on write)
restorable(path) -> bool                             # one of the files Atropa backs up?
restore_file(backup_file_name, original_path, stored="home") -> CommandResult   # PrivilegeError unless restorable()
read_backup(backup_file_name, stored="home") -> str  # a "system" one through the helper's backup-show
list_backups(limit=200) -> list[dict]                # both stores, most-recent-first, "stored" + "restorable"
get_recent_actions(limit=200) -> list[str]           # most-recent-first tail of actions.log
```
A timeout raises `PrivilegeError` (see "Timeouts hold" in section 1); the
streaming runners return everything in `.stdout`, with `.stderr` always empty.
`path_exists()` is there because `Path.exists()` raises `PermissionError` on
Python 3.11-3.13 when a directory on the way isn't searchable - a root-only
ESP, a 0700 `/var/lib/aide`. `backup_file()` treats "can't tell" as "try the
privileged read" rather than crashing.

When the installed helper exists (`HELPER_PATH =
/usr/lib/atropa/atropa-helper`), both privileged runners prepend it to the
pkexec/sudo prefix; that is what makes polkit's keep authorization apply (see
Privilege model). Operations `helper.needs_fresh_auth()` marks as root-equivalent
get `ASK_HELPER_PATH` (`atropa-helper-ask`, asked every time) instead, and a
PrivilegeError when only the keep helper is installed. `helper_available()`
is the check, and a missing or non-executable helper silently restores the
old per-command behavior.

## 2a. Core

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
- `remove(names, purge_config=False)`, `clean_cache`,
  `list_explicit`, `list_orphans` — straightforward pacman
  wraps. The page lists `list_orphans()` under "Orphaned Packages", with a
  remove button per package and "Remove all", which passes exactly the
  names shown to `remove()`
- **The SELinux package repository.** `enable_selinux_repo()` appends the
  archlinuxhardened project's `[selinux]` repository to `/etc/pacman.conf`,
  exactly as their README gives it, `SigLevel = Never` included: neither
  the repository nor its packages are signed, so pacman can only use it
  with verification off. That is the whole trade-off - pacman then installs
  whatever that URL serves, as root, unverified - and why Quick Setup keeps
  it behind a lock (below). The section goes at the end of the file, so the
  official repositories keep precedence for any package both have.
  `pacman.conf` is backed up first, and if `pacman-conf` can't read the new
  file back the previous content is restored: a `pacman.conf` that doesn't
  parse stops every install and upgrade. Nothing is synced or installed by
  it. `disable_selinux_repo()` takes the section out again (packages already
  installed from it stay). `configured_repos()` asks `pacman-conf
  --repo-list`, which follows `Include`, and falls back to the section
  names in the file; `selinux_repo_enabled()` goes by that.
  Enabling the repository replaces nothing by itself. The tools Atropa runs
  (`policycoreutils`, `checkpolicy`, `semodule-utils`, `selinux-python` and
  their libraries) are plain additions; the SELinux builds of core packages
  (`coreutils-selinux`, `pam-selinux`, `systemd-selinux`, `sudo-selinux`,
  ... or `base-selinux` for all of them) conflict with the official ones
  and only go in when someone installs them by name.

- **Arch news before upgrading.** The Packages page's "Before Upgrading"
  group calls `news.check()`: fetch `https://archlinux.org/feeds/news/`,
  keep items published after the last `starting full system upgrade` line
  in `/var/log/pacman.log`, and list up to ten with dates and an Open
  button. User-triggered (no network when the page opens), read-only, no
  root. Failures land in `NewsReport.error` and are shown as one line
  instead of a blank section; the feed parser is tested with an injected
  `fetch`, so CI never touches the network.

- **After upgrading** (`system_health.py`, read-only): failed units
  (`systemctl --failed`), whether the running kernel's package now installs
  a different kernel (found through `pacman -Qo`/`-Ql`, so a deliberately
  installed fallback kernel doesn't leave a permanent "reboot needed"), and
  whether the CPU's microcode package (`intel-ucode`/`amd-ucode`) is
  installed. `check_all()` isolates the three, so one missing tool blanks
  only its own row.

### System (`system_config.py` / `pages/system_config.py`)
Built on `hostnamectl` / `timedatectl` / `localectl`:
`get_hostname_status`/`set_hostname`, `get_time_status`/`list_timezones`/
`set_timezone`/`set_ntp`, `get_locale_status`/`list_generated_locales`/
`set_locale`, `list_locale_gen_entries`/`set_locale_gen_enabled(locale,
charmap, enabled)` (the one raw-file edit: `cat` → edit in Python → `tee`,
backed up, then `locale-gen`), `list_keymaps`/`set_keymap`,
`list_x11_layouts`/`set_x11_layout`. Filter lists render at most 40 matches
(`_MAX_RENDERED_MATCHES`). The page shows the loaded NTP state with its
signals suppressed and sends a click through `apply_switch()`: setting the
switch to the loaded state used to count as a toggle, so opening the page
with NTP on ran `timedatectl set-ntp true` behind a password prompt.

### Network (`network.py` / `pages/network.py`)
NetworkManager (`nmcli`) only — systemd-networkd is detected
(`backend_available()` returns `"networkmanager" | "networkd" | "none"`) but
**read-only**, no write support yet (noted as a known limitation).
- `list_devices`, `list_wifi(rescan=False)`, `connect_wifi(ssid, password=None)`
  (the password goes to `nmcli --ask` on **stdin**, never argv, so it
  never shows in `ps` or the action log),
  `disconnect`, `set_static_ip(connection_name, ip_cidr, gateway, dns)`,
  `set_dhcp`

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
confirmation it asks before stop, restart and disable (for a restart, as
what applies until the unit is back - or for good if it fails to start).
Each row also has a journal button: the last `JOURNAL_LINES = 100` lines in
a dialog. `journal_tail()` reads as the current user and keeps journalctl's
stderr, so its hint about who may read system messages is shown instead of
a bare "No entries". The page renders at most
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
is read with one privileged `grep -rH` instead of crashing. GRUB's entries
are the top-level `menuentry` lines of `/boot/grub/grub.cfg`, which
`grub-mkconfig` writes with umask 077: when it can't be read directly it is
read with one privileged `grep` - a grep, so password hashes from a
`01_users` section stay in the file. Titles are unquoted the way GRUB's
shell-like syntax reads them (`shlex`): grub-mkconfig single-quotes them,
Grub Customizer double-quotes them, and a hand-written entry may have no
space before its `{`. A failed read leaves `entries` empty with the reason
in `entries_error`, and the rest of the page stands. `GRUB_TIMEOUT="5"`
reads as `5`. `get_info()` returns a
`BootloaderInfo(kind, entries, default_timeout, entries_error)`.

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

### Kernel parameters (`kernel_params.py`, on `pages/bootloader.py`)

Configured parameters come from GRUB's `GRUB_CMDLINE_LINUX_DEFAULT` and
`GRUB_CMDLINE_LINUX`, or the `options` line of the systemd-boot entry that
boots the running kernel; /proc/cmdline is shown next to them. The page
has switches for the AppArmor and SELinux `lsm=` lists (one replaces the
other: `with_changes()` replaces a parameter of the same name), hardening
parameters (`slab_nomerge`, `init_on_alloc=1`, `init_on_free=1`,
`page_alloc.shuffle=1`, `randomize_kstack_offset=on`, `vsyscall=none`,
`debugfs=off`), `quiet`, and free-form parameters (one plain word each).

`apply()` keeps the current boot entry before changing anything:

- GRUB: the helper's `grub-keep-previous DATE KERNEL` copies the grub.cfg
  menuentry that boots the running kernel (not a fallback-initramfs one)
  into `/boot/grub/custom.cfg`, retitled "... (kernel parameters before
  DATE)" with its own id. GRUB's stock 41_custom sources that file at boot,
  so it survives grub-mkconfig, and it is GRUB configuration rather than a
  script grub-mkconfig would run as root. A custom.cfg Atropa didn't write
  is never touched. Then /etc/default/grub is edited (removals from either
  variable, additions to `_DEFAULT`) and grub.cfg regenerated; a failed
  regeneration writes the old file back.
- systemd-boot: the entry is copied to `atropa-previous-<entry>.conf`, then
  its options line rewritten. The helper lets Atropa edit existing
  `loader/entries/*.conf` under /boot or /efi but only create
  `atropa-*.conf` ones, and `loader-entry-remove` only deletes those.

All of it asks for the password every time (`ASK_OPERATIONS`, ask-tier
loader entries and /etc/default/grub). Unified kernel images, whose
parameters live in /etc/kernel/cmdline, aren't handled. Verified in the VM
on GRUB: after adding `slab_nomerge` the next boot had it, and
`grub-reboot` into the kept entry booted without it.

### Kernels (`kernels.py` / `pages/kernels.py`)

Kernel packages are found by the `pkgbase` file each one installs in
`/usr/lib/modules/<release>/`, so an AUR kernel counts like a repo one. Per
kernel: pacman version, running (`uname -r` is its directory name),
`-headers` installed (only flagged when a `*-dkms` package is installed,
since DKMS builds against them), and a boot entry:

- GRUB: the `vmlinuz-*` names in `grub.cfg`. grub-mkconfig writes it 0600,
  so when it isn't readable the page offers "Check", which runs the helper's
  `grep -oE 'vmlinuz-[A-Za-z0-9._+-]+' /boot/grub/grub.cfg` - kernel file
  names only, never the command lines.
- systemd-boot: `linux /vmlinuz-*` in the loader entries, plus unified
  kernel images in `EFI/Linux/`.

`warnings()` names, most important first: a single kernel (no fallback),
missing headers with DKMS, a kernel without a boot entry.

- `install(pkgbase, upgrade=False)` - only the Arch kernels in `OFFERED`
  (`linux`, `linux-lts`, `linux-zen`, `linux-hardened`), with headers when
  DKMS is in use, then `grub-mkconfig` on GRUB. `pacman.install`'s
  partial-upgrade refusal passes through; the page then offers
  `upgrade=True` (`pacman -Syu --needed <kernel>`).
- `remove(pkgbase)` - `pacman -Rns` with its headers, then `grub-mkconfig`;
  refused for the running kernel and for the last one.
- `entry_for()` / `add_boot_entry()` - systemd-boot only: a copy of the
  running kernel's entry with the kernel and initramfs names swapped,
  written as `loader/entries/atropa-<pkgbase>.conf`. The helper allows
  only `atropa-*.conf` there, under `/boot` or `/efi`, and writing one asks
  every time (an entry carries the kernel command line).
- Leftover module folders: DKMS builds into `updates/dkms` of every kernel
  release, and pacman doesn't remove that when the kernel goes, so every
  old release's folder stays (about 14 MB each with nvidia). The helper's
  `modules-leftover-remove RELEASE` deletes one only when it isn't the
  running kernel, is a real directory, has no `pkgbase` and no `kernel/`
  tree (so a kernel installed by hand is left alone), and `pacman -Qqo`
  finds no owner.

### Users & Groups (`users.py` / `pages/users.py`)
Reads `/etc/passwd`/`/etc/group` directly via `pwd`/`grp` modules (unprivileged,
always accurate); writes via `useradd`/`usermod`/`userdel`/`groupadd`/`groupdel`.
Regular accounts are the ones in `DEFAULT_MIN_UID`..`DEFAULT_MAX_UID`
(1000-60000, the login.defs defaults); the rest are filtered out by default.
Without the upper bound, `nobody` (65534) was listed as a regular user and
group, delete button included.
- `list_users(include_system=False)` / `list_groups(include_system=False)`
  (root/UID 0 is always included), `create_user`, `modify_user` (full name,
  shell, extra groups, lock/unlock), `delete_user(remove_home=False)`,
  `create_group`, `delete_group`
- `set_password` pipes `user:pass` to `chpasswd` via **stdin**, never argv
  (argv would leak into `ps` output). chpasswd reads one entry per line, so
  a line break in either part is refused (a pasted two-line password would
  have set a second account's password), as are a `:` in the username and
  an empty password
- `supplementary_groups(username)` and `set_groups(username, groups)`
  (`usermod -G`: exactly these groups, next to the primary one).
  `groups_warning()` says when that takes the account out of `ADMIN_GROUP`;
  `group_delete_refusal(name)` refuses the root group, `ADMIN_GROUP` and
  any account's primary group
- The page: each user row has set password (typed twice; the button stays
  off until both match), change groups, lock, unlock and delete. The Groups
  list has a "New group name" row and a delete button per group
- Guards for the one-click changes that can't be undone from Atropa:
  `lock_refusal(username)` refuses the account you're signed in with, and
  root when nobody is in `ADMIN_GROUP` (`wheel` - polkit then asks for
  root's password); `lock_warning(username)` says what else locking breaks
  (the only wheel member, an administrator); `delete_refusal(username)`
  refuses your own account and root. The page asks before locking, has an
  unlock button, disables what's refused, and its delete dialog offers
  "Delete" or "Delete with home folder".

## 2b. Security

### Security Quick Setup (`quicksetup.py` / `pages/quicksetup.py`)
`CATALOG` of `SetupItem(key, title, description, default_selected, risk_note,
locked)` for firewall, fail2ban, sysctl, faillock, AppArmor, auditd, USBGuard
(`default_selected=False`), the SELinux package repository (`locked`) and
SELinux (permissive only). `status_summary()`, `apply_single(key, on_line,
unlocked=())`, `apply_items(keys, on_line, unlocked=()) -> dict[str,
CommandResult]` — checklist and wizard share these. The firewall step
allows every port sshd listens on (`SshStatus.ports` - `Port` lines
accumulate and `ListenAddress` can name its own) before enabling
deny-by-default, and doesn't enable the firewall at all if an allow fails.
`apply_items()` records a step that raises - a `PartialUpgradeError` from
`pacman.install()`, say - as that step's failure and carries on with the
next one instead of aborting the batch. The AppArmor step points at its
`lsm=` kernel parameter, which Bootloader > Kernel parameters can add. The SELinux
step installs `audit`. SELinux's own tools aren't in the official
repositories, so without the SELinux repository it points at the packages
in `selinux.SELINUX_TOOL_PACKAGES` instead of running a `pacman -S` that
could only fail. With the repository enabled it installs them with
`pacman.upgrade_and_install_streaming()` - a full upgrade, because that is
the only supported way for pacman to read a repository it hasn't synced
yet. A SELinux that's disabled in the kernel is reported as a manual step:
the SELinux builds of the base packages, a policy (the Build Policy page
can fetch Atropa's own), the kernel parameter (Bootloader > Kernel
parameters) and the reboot stay with the user.

**The locked item.** "SELinux package repository" adds the unsigned
`[selinux]` repository (see Packages) and is the one item that isn't part
of the baseline. It is locked three ways:
- On the page its checkbox can't be ticked until the lock button next to it
  has been opened, and that takes the administrator password
  (`privilege.authenticate()`). A dismissed prompt leaves it locked. The
  confirmation before applying repeats its risk note, and every lock closes
  again when a batch or the wizard finishes. A "Remove" button appears
  while the repository is enabled and works only while unlocked.
- In the backend `apply_items()` and `apply_single()` refuse a locked key
  that isn't also in `unlocked` - being in the list of keys isn't enough.
- Profile import never passes `unlocked`, and filters locked keys out
  itself with a line saying so: a profile is a file, hand-edited or someone
  else's, and mustn't be a way past the lock. Locked items aren't exported.

`status_summary()` works out each line on its own (`_STATUS_LINES`): a
check that fails says "Couldn't check: ..." in its own line. One missing
tool used to raise out of the whole function and leave the page with an
error toast and no statuses at all.

**Desktop mode.** With no sshd, the server-shaped steps don't fit, so
`_apply_firewall()` stops opening port 22 - it used to do that
unconditionally, which put a listening hole on every laptop - and
`_apply_fail2ban()` skips with an explanation (there is no remote login to
protect). `desktop_baseline()` then returns a read-only
`DesktopBaseline(applies, sshd_installed, checks)` covering firewall
state, LUKS, Secure Boot and "no SSH server to harden"; the page renders
it as its own group, leaves fail2ban visible-but-insensitive, and the
Security page disables its SSH controls for the same reason. Nothing in
the baseline is applied: it states what is already true.

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
and one policy rebuild, not one of each per boolean. A locked Quick Setup
item is never applied from a profile (see Security Quick Setup).

### Security (`security.py` / `pages/security.py`)
Firewall abstraction over `ufw` **or** `firewalld` (whichever is installed;
`firewall_backend()` returns `"ufw" | "firewalld" | "none"`). SSH hardening
(`set_ssh_permit_root_login`, `set_ssh_password_auth`,
`set_ssh_port`, plus the CIS settings `set_ssh_log_level` (INFO/VERBOSE
only), `set_ssh_x11_forwarding`, `set_ssh_max_auth_tries`,
`set_ssh_ignore_rhosts`, `set_ssh_hostbased_authentication`,
`set_ssh_permit_empty_passwords`, `set_ssh_permit_user_environment` — all
route through `_set_sshd_option`, which has the backup, `sshd -t` validation
and write-back logic in section 1).

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

When OpenSSH isn't installed, the Security page disables every SSH
control and says why: a desktop with no SSH server has nothing to harden,
and leaving the switches live only produced failed edits. The firewall,
rules and sudoers check stay usable.

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
  the Arch wiki recommends. The page points at that parameter
  (`APPARMOR_KERNEL_PARAMETER`), which Bootloader > Kernel parameters adds
  - keeping a boot entry with the old parameters in case it doesn't boot
- USBGuard — `usbguard_generate_and_enable()` **always generates a policy from
  currently-plugged-in devices before enabling enforcement**; enabling blind
  would block the next USB replug including your own keyboard. The policy is
  generated first and written only if it has rules (the old
  `generate-policy > rules.conf` emptied the file before generating, so a
  failure left a policy that blocks every device). The previous file is
  backed up, the new one is installed with mode 0600 (`usbguard-daemon`
  refuses any other), and a daemon that was already running is restarted so
  it loads it. `usbguard_status().extra["has_policy"]` is `None` when
  `/etc/usbguard` can't be looked into; the page's "Turn off" button
  (`usbguard_disable()`, shown while the daemon is active or enabled) asks
  first and leaves the policy file where it is
- CIS audit rule sets (`audit_rules.py`): `active_rule_set_keys()` reads the
  loaded rules with **one** privileged `auditctl -l` for every set - the
  page used to run one per set, five password prompts on opening it - and
  matches keys as whole tokens. `apply_all_rule_sets()` does one `mkdir -p`
  and one `augenrules --load`
- auditd, `vulnerability_scan()` (via `arch-audit`), login lockout
  (`faillock_status`/`set_faillock_policy`, which edit
  `/etc/security/faillock.conf`; pambase already wires `pam_faillock` into
  `system-auth`, so Atropa doesn't touch the PAM stack for it). `faillock_wired_into_pam()` /
  `pwquality_wired_into_pam()` follow `include`/`substack`/`@include` and ignore
  comments - on Arch, `system-login` only includes `system-auth`, which is
  where pambase wires faillock in; pwquality also checks the `passwd` service.
  A key that isn't in `faillock.conf`/`pwquality.conf` yet is appended with
  `tee -a` and the line on stdin (`_append_line()`), not a root shell.
  `vulnerability_scan()` raises when `arch-audit` itself fails (e.g. offline)
  rather than returning an empty "nothing vulnerable" list.
- **pam_pwquality** (`wire_pwquality`/`unwire_pwquality`): Arch doesn't
  load it, and stock `/etc/pam.d/passwd` only includes `system-auth`, so it
  goes into `system-auth`'s password section - above the
  `pam_systemd_home` line, whose `[success=1]` skips the next line (placed
  after it, homed users would skip the check), with `use_authtok` on
  pam_unix. Only pambase's stock layout is edited; a hand-edited file is
  refused. Unwiring removes exactly those lines. Verified in a VM: `passwd`
  refuses a short password and accepts a strong one, `su` still
  authenticates, and unwiring restores the stock file byte for byte.
- **su restricted to wheel** (`su_restriction_status`, `restrict_su_to_wheel`,
  `allow_su_for_everyone`). Arch's util-linux
  ships `/etc/pam.d/su` and `su-l` with `auth required pam_wheel.so use_uid`
  commented out, and Atropa uncomments exactly that line (and comments it
  back), nothing else. Each file is `restricted`, `open` (the stock
  commented line) or `custom` (edited by hand - refused, with the line to
  add yourself). Restricting is refused when you aren't in wheel, since it
  would lock you out of su. A pam_wheel `trust` line (wheel uses su with no
  password) is reported as a warning. Both files are ask-tier writes in the
  helper, backed up by it first, and restorable from Activity. The
  compliance report scores it as "su restricted to wheel". Verified in the
  VM: a user outside wheel gets `su: Permission denied`, a wheel member
  still switches users, and reverting restores the stock files.
- `run_audit() -> list[AuditCheck]` — rollup pass/warn/fail/info across all of
  the above plus firewall/SSH from `security.py` plus SELinux status; powers
  the "Security Audit" score section

### Encryption & Secure Boot (`boot_security.py` / `pages/boot_security.py`)

Whether `/` sits above a LUKS device (`findmnt` plus the `lsblk -s` stack,
with `/etc/crypttab` as a fallback when lsblk can't answer - "can't tell"
stays distinct from "unencrypted"), the firmware's Secure Boot state via
bootctl then mokutil, and sbctl's own view. sbctl's three actions run in
the order create keys, sign, enroll, each pkexec'd and confirmed: signing
lists unsigned EFI files with `sbctl verify --json` and signs and saves each
(`sign -s`) - `sign-all` alone only re-signs files already in sbctl's
database, which is empty after `create-keys` - and `enroll-keys --microsoft`
refuses while anything is still unsigned, because many firmwares enforce as
soon as keys are enrolled. Enrollment still requires the firmware in setup
mode, which Atropa cannot do and says so. The encryption and Secure Boot checks feed the
compliance report's "Boot & Disk Security" category and the exposure summary.

### Compliance Report (`compliance.py` / `pages/compliance.py`)
Categorized, scored security-posture report built **on top of**
`hardening.run_audit()` plus extra checks (login lockout, sudoers, su restricted to wheel,
custom SELinux modules) -
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

The score is deliberately framed as **exposure**, not an enterprise audit:
`Exposure`/`ExposureSignal` derive a plain-language level (low / moderate /
high) from facts the report already computed - firewall, whether an SSH
server is reachable, non-loopback listening sockets (read from
`/proc/net/tcp`, so no `ss` dependency), LUKS, Secure Boot - and the page
leads with that before the CIS-style categories. `EXPOSURE_NOTE` states on
the page and in every export that 100% means "nothing Atropa checked is
exposing this machine", not a certification. Loopback-only listeners are
excluded: a local helper isn't network exposure, and counting it made every
ordinary desktop read "moderate".

### Service Inventory & Account Hygiene (`inventory.py` + `account_hygiene.py` / `pages/inventory_hygiene.py`)
CIS DIL Phase 2 - see its write-up in `docs/HISTORY.md` for the full
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

### File Integrity / AIDE (`aide.py` / `pages/aide_page.py`)
CIS DIL Phase 3 - see its write-up in `docs/HISTORY.md` for the full
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
- `parse_check_entries(output)` - the added/removed/changed *paths* from
  AIDE's report, not just the counts. Section-aware (blank line or the
  next header ends a list), so the summary's "Added entries:" counts and
  the "Detailed information about changes" attribute block are never
  mistaken for paths; each entry keeps AIDE's marker column
  (`f++++++++++++++++`) as detail.
- `build_check_record()` / `save_check_record()` / `load_check_record()` /
  `clear_check_record()` - the last check (timestamp, summary, paths) is
  saved to `~/.local/share/atropa/aide_last_check.json`, so "what changed?"
  survives closing the streaming dialog or the app. Writes are atomic
  (temp file + replace), a corrupt/missing file is just "no record", and
  unknown entry kinds are dropped rather than crashing the page.
  Re-baselining clears it, because those changes are now the new normal.
- `check_config()` - `aide --config-check` through pkexec: validates
  `/etc/aide.conf` and every Include without walking the filesystem.
- `timer_details(unit)` - `systemctl show --property=NextElapseUSecRealtime,
  LastTriggerUSec,Result`, parsed as key=value rather than
  `list-timers`' moving columns; empty values mean "not scheduled", never a
  fabricated date.
- The page grew a "Last check" group (saved summary + up to 60 changed
  paths with ADDED/REMOVED/CHANGED labels, then "… and N more"), a
  "Configuration" validate action, and the timer row's next/last run.
- UI's "Update baseline" action requires an explicit `self.confirm()`
  with copy stating it accepts everything currently reported as normal -
  deliberate friction, not an oversight.

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

### SELinux (`selinux.py`, `denial_advice.py`, `te_lint.py`, `selinux_programs.py`)

Three pages plus Build Policy (below):

- **SELinux** (`pages/selinux.py`) - configuration only: status, enforcing mode (lock + confirm),
  relabel, restorecon, booleans, and a row that opens Denials.
- **SELinux: Denials** (`pages/selinux_review.py`) - an `Adw.NavigationSplitView`.
  The sidebar has Setup Mode, "Review now" (kernel log or audit.log), filter
  chips (Needs action / Noise / Done / All, with counts) and the programs:
  one row per SELinux source domain with one badge for its best next step
  (`selinux_programs.overview()`: Dangerous, Review, Relabel, Boolean,
  Module, Policy gap, Noise, Done - most urgent first). "Review now" runs
  `review_all_denials()` and then `build_policy_review()` for the same
  window, so drafts exist as soon as the list does; nothing is installed.
  The program page has the recommended route first - boolean (with how
  many of its denials it covers and how many rules it switches), restorecon
  for paths a label probably explains, installing the dontaudit module for
  known noise, the undefined-class Help - then the draft module, then each
  denial as an expander (sample line, path, hint, matched module) and the
  audit2why text.
- **SELinux: Modules** (`pages/selinux_load.py`) - installed by Atropa (active or
  not, with lint badge and category; Open, Remove, Reinstall, Reinstall all
  inactive), Pending (Open, Install, Discard), New / Load a .te / Import
  several, and everything loaded in the policy.

Drafts, pending, installed and hand-loaded modules all open in the same
`ModuleView` (`ui/selinux_module_view.py`): the category toggle buttons
with the detected reason, the findings (badge, line, why, and a one-click
"Drop it" / "Use dontaudit" / "Turn on <boolean>" where the fix is
mechanical; clicking one jumps to its line), the source - editable,
flagged lines tinted by severity, re-linted 600 ms after typing stops -
and Discard / Save for later / Install. Install goes through
`selinux_lint.install()`, the same acknowledge-each-dangerous-finding
dialog as everywhere else, and the backend gate behind it.

#### Backend (`selinux.py`)

- `get_status()` parses `sestatus` (checked against real output from Arch
  systems on a reference policy - `refpolicy-arch` from the AUR, and
  Atropa's own `atropa-refpolicy`; their boolean lists are much sparser
  than Fedora/RHEL's targeted policy). Installed tools aren't an enabled SELinux: when
  `sestatus` says "disabled", the result is `available=False` with mode
  `"disabled"`, which is what every caller already took "available" to
  mean - it used to come back available with mode "unknown", and Quick
  Setup then ran `setenforce` on a disabled SELinux. The page says the
  tools are installed but SELinux is off.
- `SELINUX_TOOL_PACKAGES` names the package behind each tool Atropa runs -
  none of them in Arch's official repositories (they come from the AUR, or
  from the unsigned repository `pacman.enable_selinux_repo()` adds): `checkmodule` is in `checkpolicy`,
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
  attempt rather than trusting its own last-dragged position (a
  cancelled change used to leave the switch showing a mode never applied).
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
- **Classifying denials**: `list_all_denials(since=None, source="both")`
  → `group_denials()` → `classify_denials()` (`new` / `already_allowed` /
  `undefined_in_policy`), wrapped by `review_all_denials(source="both",
  since_setup_mode=True) -> ExtensiveDenialReview` which also diffs against
  `last_review.json` to produce `resolved`. Time
  scoping uses absolute instants: journalctl gets `--since @<epoch>`, and
  audit-log records are filtered on their own `msg=audit(<epoch>)` stamps
  rather than via ausearch's locale-dependent `-ts`; a failed audit-log read
  raises when the audit log is the requested source.
- `list_semodules()` — `semodule -l`, **privileged** (unprivileged it
  silently returns nothing)
- `compile_and_load_te(te_content, module_name, acknowledged=())` —
  compile unprivileged, then `semodule -i`; gated by the linter (below).
  `save_draft()`/`discard_draft()` put a module into Pending or delete it
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
  user-supplied shell script. Groups denials by **source domain** (known
  noise separately, drafted as dontaudit), skips kernel noise (exact names: `systemd` (PID 1), `kernel`,
  `kworker/*`, `swapper/*` - a prefix match used to hide systemd-tmpfiles,
  systemd-coredump, auditd and the like),
  and for each group: generates a `.te`, an `audit2why` explanation, and
  compiles (but does **not** install) a `.pp`. Rationale for grouping:
  `audit2allow` produces a much better policy seeing all of a program's
  related denials together vs. one denial at a time. `comm=` alone isn't
  enough - it's whatever name a process gives itself, so one name running
  in two domains used to become one module granting both domains' rules.
  Modules are named `atropa_<program>_<domain>` (`_review_module_name()`):
  named after the program alone, a denial from `ssh`, `mount` or `sudo`
  produced `ssh.pp`, `mount.pp` or `sudo.pp`, and installing one replaced
  the policy's own module of that name.
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
  uses — deliberately does **not** install any of them, since a batch of
  files that may never have been individually opened doesn't get the
  "the person clicking Install just read this" assumption a single
  opened module does. One
  bad file (unreadable, invalid/unparseable module name, fails to
  compile) is recorded and skipped rather than aborting the whole batch.
  Module name comes from the file's own `module <name> <version>;`
  declaration line if present (matches `audit2allow`'s own output format,
  which is what these files typically already are), falling back to the
  filename stem.

#### Judging denials (`denial_advice.py`)

audit2allow turns every denial into an allow rule; Atropa judges first. `advise_denials()` runs after `classify_denials()`:

- **Loaded policy** (`PolicyChecker`, setools' Python API - optional, the
  review says when it couldn't check): a still-"new" denial whose
  permissions are all granted by unconditional rules, or by conditional ones
  whose booleans are on now (runtime values from getsebool, not the compiled
  defaults), goes to *already allowed* ("the loaded policy"). One only rules
  behind an off boolean would grant goes to *a boolean would allow this*,
  with each boolean's rule count (`boolean_rule_count`) and a Turn on
  button. Capped at 200 lookups (~0.25 s each).
- **Known noise** (`NOISE`): process siginh/rlimitinh/noatsecure,
  capability net_admin on its own, sock_file access to the homed/userdb/
  nsresourced sockets. Its own group; Generate drafts a separate
  `atropa_<domain>_dontaudit` module with `audit2allow -D` instead of
  allowing it.
- **Label hints** (`label_hint`): unlabeled_t/file_t/default_t targets,
  `execute_no_trans` on lib_t/usr_t (Arch's /usr/lib vs /usr/libexec), and
  a system path carrying a home-directory type. Shown with ⚠ and a
  restorecon button.
- **Drafts**: one module per SELinux domain, `atropa_<domain>` (comm= is cut
  at 15 characters and one domain's programs belong together), real gaps
  before noise. `te_warnings` flags `sock_file write` without
  `unix_stream_socket connectto`; `te_booleans` lifts audit2allow's
  "#!!!! ... boolean" comments into the draft's row.

Tests never load the host's policy: `no_host_policy` (conftest) replaces
`_policy_checker`, and the checker takes an injected setools module.

`selinux_programs.overview()` joins the classified denials and the drafts
per source domain into the Denials page's programs, each with its best next
step: dangerous or review (the draft's lint verdict), relabel (a label hint,
or a denial the policy already allows that keeps happening), boolean,
module, policy gap (a class or permission the compiled policy doesn't
define), noise, done.

#### The module linter (`te_lint.py`)

Drafted, imported and hand-written modules are linted before they're
installed. The parser fails closed, since the linter is an install gate:
statements are split on `;`, `require` blocks skipped with balanced braces,
`if`/`else`/`optional` blocks read, `{ }` sets expanded on source and target
(a complement or an exclusion counts as every type), and anything it can't
read - a macro, an unknown construct, a typo - is a dangerous "couldn't read"
finding rather than a skipped rule. `permissive`, privileged
`typeattribute`s and rules on broad attributes (`domain`, `file_type`, ...)
are dangerous too. `lint(te, category)` checks each rule against a table:

- dangerous: SELinux enforcement (`security` setenforce/load_policy/
  setbool), writing SELinux's own config, `shadow_t`, writing
  passwd/sudo/`etc_t`/PAM, writing `bin_t`/`lib_t`/`boot_t`/`*_exec_t`,
  `/dev/mem` or raw disk writes, `module_load`, `mmap_zero`, dynamic
  transitions, `ptrace` on another domain, transitions to
  `unconfined_t`, writing `auditd_log_t`, `sys_module`/`sys_rawio`/
  `mac_admin`/`mac_override`, anything widening a guest or sandbox domain;
- review: generic targets (`default_t`, `file_t`, `unlabeled_t`, `var_t`,
  `tmp_t`, `usr_t` - usually a label problem), wildcards, full manage sets
  on shared types, write-then-execute, broad port types, raw sockets,
  netlink writes, broad capabilities, signals to other domains, execmem,
  widening `user_t`/`staff_t`, more than 25 rules or types;
- note: `dac_override`/`dac_read_search`, booleans audit2allow named, known
  noise (`noise_reason`), sock_file write without connectto.

Categories (System service, Boot, User service, D-Bus service, Desktop app,
Not sure) adjust that: Boot lowers module loading to review, a Desktop app
makes any capability dangerous, and each adds "out of place for a ..."
findings. The hard dangerous list is never lowered. `detect_category()`
reads the denying process's cgroup (system unit, user manager unit, app
scope) while it runs, else a short list of known domains, else Not sure.
The category and the acknowledged findings live in
`<module>.atropa.json` next to the module and move to approved/ with it.

The gate is in the backend: `compile_and_load_te()`, `install_pp_file()`
(when the .te is next to the .pp) and `reinstall_all_approved_modules()`
raise `LintRefused` - or, for reinstall, hold the module back - while a
dangerous finding isn't acknowledged. The compliance report's "Custom
SELinux modules" warns about installed modules with dangerous findings,
acknowledged or not. Calibrated on 36 real drafts from an enforcing
desktop: none comes out dangerous under its detected category
(`tests/fixtures/te`).

### Custom Reference Policy build (`refpolicy_build.py` / `pages/refpolicy_build.py`)
Builds/installs/activates a user-maintained refpolicy fork (e.g. Arch-
specific paths/contexts fixed upstream) - never an AUR package build,
that stays the existing "install it yourself first" posture. Only
handles `MONOLITHIC = n` (modular) source trees - detected from the
target set used, not auto-sensed from `build.conf`.
- `fetch_atropa_policy(on_line)` - gets Atropa's own reference policy for
  Arch (`ATROPA_POLICY_URL`, a complete modular tree whose `build.conf` says
  `NAME = atropa-refpolicy`) into `ATROPA_POLICY_DIR`
  (`~/.local/share/atropa/refpolicy-atropa`) with git: a shallow clone, or
  `git pull --ff-only` on the checkout already there, so local changes are
  never merged over. Unprivileged; nothing is built or installed. The
  page's "Get or update" button runs it and makes the result the source
  directory. It is still a tree whose Makefile Install runs as root - the
  same trust Install already asks for, now placed in that repository.
  Its `build.conf` says `TYPE = standard` only because refpolicy has no
  "targeted" type (standard/mcs/mls are the valid ones). In practice it is
  a targeted-style policy - `modules.conf` has the `unconfined` module on -
  so interactive logins have to be mapped to `unconfined_u` to run in
  `unconfined_t`. That is `activate()`'s default; the page refuses a type
  or role (`..._t`, `..._r`) typed into the login field, which takes the
  SELinux user.
- `policy_name_of(source_dir)` - `NAME` from the tree's `build.conf`. The
  page fills the policy-name field from it when a source directory is
  chosen, since Activate needs that name exactly.
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

## 2c. Maintenance

### Config Changes (`pacnew.py` / `pages/pacnew.py`)

- `scan() -> list[PacnewEntry]` walks `/etc` for `*.pacnew`/`*.pacsave`,
  derives the live path, and records whether the live side still exists.
  Unreadable subdirectories are skipped (one root-only corner must not hide
  every other pending config); an unreadable `/etc` itself raises.
- `diff_text(entry)` is a unified diff of live vs candidate via `difflib` -
  no shelling out, and a missing live file diffs as empty so a `.pacsave`
  reads as "all new".
- `apply_new(entry)` refuses the account databases (`is_account_file()`:
  passwd, group, shadow, gshadow - merge those by hand), otherwise calls
  the helper's `pacnew-apply`, which backs the live file up before
  replacing it; `discard(entry)` calls `pacnew-remove`. The helper only
  touches a regular, non-symlinked `*.pacnew`/`*.pacsave` under `/etc`,
  which an unprivileged user cannot create.
- The page lists each candidate with **Show diff** (monospaced dialog),
  **Use new version** / **Restore saved config**, and **Keep current**
  (delete the candidate). Replacing asks first and says the backup is made.
  Merging is deliberately manual: Atropa shows the two versions and lets
  you edit, rather than pretending a three-way merge is safe to automate.

### Package History (`rollback.py` / `pages/rollback.py`)

Undoes a recent pacman transaction on any filesystem. `parse_log()` reads
`/var/log/pacman.log` into completed transactions (the command from the
preceding `[PACMAN] Running` line, then every `upgraded`, `downgraded`,
`installed`, `removed`, `reinstalled` line up to `transaction completed`;
failed and interrupted transactions are dropped). `plan()` turns one into
the `pacman -U` file list that reinstalls the versions it replaced, from
`/var/cache/pacman/pkg` (exact `name-version-arch.pkg.tar.{zst,xz}`, arch
from `uname` or `any`), and refuses rather than half-does it:

- a package now at a different version than the transaction left it is
  **stale** - the plan would describe a state the system isn't in;
- a version missing from the cache blocks the rollback: half a rollback is
  a partial upgrade. Packages that came with the install image were never
  downloaded, so the first big upgrade usually can't be rolled back;
- packages the transaction *installed* stay (something may depend on them
  by now), and packages removed since are skipped, not counted as stale.

`apply()` runs one `pacman -U --noconfirm FILES...`. The helper accepts `-U`
only for regular files directly in the root-owned cache (no symlinks, no
`.sig`, no `download-*` temp dirs) and puts it in the ASK tier: installing
older versions is a downgrade and never happens on a remembered
authorization.

`pacman.clean_cache()` used to run `pacman -Sc`, which deletes every old
version and with it any chance of a rollback. With pacman-contrib it now
runs `paccache -r -k2` (installed and previous version) and
`paccache -r -u -k0` (uninstalled packages); without it, `pacman -Sc` with a
note in the result that recent upgrades can't be rolled back.

### Snapshots (`snapshots.py` / `pages/snapshots.py`)

snapper for the root config only, with snap-pac for a pre/post pair around
every pacman transaction (Atropa's upgrades included). `layout()` decides
what a whole-system rollback can mean, from `findmnt /`, `/etc/fstab` and
the kernel command line:

- **top-level**: `/` is subvolid 5 (Arch's VM images). Snapshots work; the
  running root can't be swapped for one.
- **subvolume**: `/` is a subvolume pinned by `subvol=` in fstab or
  `rootflags=` (archinstall's `@`). archinstall also mounts `@.snapshots`
  on `/.snapshots`, which `snapper create-config` refuses, so `setup()`
  writes `/etc/snapper/configs/root` from snapper's own template and adds
  `root` to `SNAPPER_CONFIGS` in `/etc/conf.d/snapper` instead.
- **default-subvolume**: `/` is a subvolume nothing pins (openSUSE-style),
  the one layout where `snapper rollback` works. The page explains it;
  Atropa doesn't run it.

Atropa never swaps the root subvolume of a running system. Recovery is
restoring files (`snapper undochange N..0 PATH`) from the Changes dialog,
or booting a snapshot read-only from GRUB via grub-btrfs (`grub-btrfsd`
keeps the submenu current). `setup()` refuses a non-Btrfs root and a
`/.snapshots` that exists but isn't a mounted subvolume.

Helper tiers: `snapper --jsonout -c root list`, `status N..0` and `create`
are keep-tier; `create-config`, `undochange` (writes anything as root),
`delete` (removes a way back) and both config files (`ALLOW_USERS` makes
snapper user-driven) are ask-tier. Only the `root` config is accepted;
`rollback` and `set-config` are refused. `snapper-cleanup.timer` and
`grub-btrfsd.service` are in `MANAGED_UNITS`.

### Boot Report (`boot_report.py` / `pages/boot_report.py`)

"What went wrong this boot" as a page instead of a journal tail:
`journalctl -b -p err` (parsed into program + message; the identifier must end
in `:` so `-- No entries --` is skipped, not parsed as a program), failed
units (reusing `system_health.failed_units()`'s `systemctl --failed` parser -
no second copy), and `coredumpctl --since @<boot>` crashes, each with its own
error row. The `--since` matters: coredumps persist across reboots, and
without it three-week-old dumps filled a page whose whole premise is "this
boot". The boot timestamp comes from `/proc/uptime`; if that can't be read,
the filter is dropped rather than hiding crashes. Crash rows are parsed by
column after `SIG` (`COREFILE`, then `EXE`, with the trailing `SIZE` column
ignored) - reading "the last field" as the program named every crash `-`.
`collect()` isolates the three sources, so a missing coredumpctl or an
unreadable journal blanks only that group. Read-only, no root, no writes.

### Disk Health (`disk_health.py` / `pages/disk_health.py`)

SMART per whole disk (`lsblk` -> `smartctl -H`), `df` usage per mount,
`fstrim.timer` state and enable, and the three cleanups that aren't pacman's
cache: `journalctl --vacuum-size`, `~/.cache` (user-owned; symlinks are
unlinked, never followed into whatever they point at) and `systemd-tmpfiles
--clean` for coredumps.

Unprivileged `smartctl -H` runs first, so opening the page never prompts.
On most NVMe/ATA drives the kernel refuses it; those rows say UNKNOWN with
smartctl's *actual* reason (its open error is printed on stdout, which used
to be mistaken for the version banner) and the page offers one explicit
"Read SMART as administrator" action. That action calls
`smart_status_privileged()`, which runs `smartctl -H --json` through pkexec
and reads `smart_status.passed`; a failed open's reason lives in
`smartctl.messages` there. One password covers every disk, since polkit
keeps the authorization.

The SMART verdict only comes from the verdict line; a whole-output substring
check turned smartctl's own probe error ("failed: No such device") into a
dying disk. Exit bits 3/4 (disk failing / pre-fail attribute below threshold)
still force a failure, and "smartctl printed no verdict" stays unknown rather
than healthy. One unreadable disk never blanks the others.

### Firmware (`firmware.py` / `pages/firmware.py`)

fwupd devices and updates. Listing uses `fwupdmgr ... --json` and accepts both
the `Devices`/`devices` key and a bare list, because the JSON shape has varied
across fwupd releases; an unparseable device list is an error, never "no
devices". An update's available version is the first release fwupd lists, with
the device's own Version as fallback; equal versions are skipped, and "No
updates" in any of fwupd's forms is an empty list rather than a toast on every
page open. `refresh()` and the streaming `update -y` go through pkexec; the
page confirms first and says that firmware updates can reboot the machine.

### Mirrors (`mirrors.py` / `pages/mirrors.py`)

`reflector` ranking plus mirrorlist writing. `rank_mirrors()` runs reflector
with `--score 20 --latest 30 --sort rate --print` and parses the `Server =`
lines (also accepting bare URLs, which older reflector versions print),
de-duplicating while keeping reflector's order; a missing reflector is a clear
"pacman -S reflector" error. `write_mirrorlist()` refuses an empty list or any
non-`http(s)` URL rather than writing a mirrorlist pacman cannot use, backs up
`/etc/pacman.d/mirrorlist` through the standard mechanism, and writes the new
file with one pkexec `tee`. The page shows the active list, ranks behind a
spinner, and asks before replacing: a bad mirrorlist is only recoverable via
the backup (Activity & Backups).

### Power (`power.py` / `pages/power.py`)

power-profiles-daemon profiles (set unprivileged: the daemon does its own
polkit authentication), TLP detection, battery capacity/status/charge limit
from sysfs (the limit is written through pkexec and only offered where
`charge_control_end_threshold` exists), zram devices, swap and hibernation
feasibility, and enabling zram swap by writing
`/etc/systemd/zram-generator.conf` (backed up first) and starting the setup
unit. Every read degrades to empty/None instead of raising: a desktop has no
battery and a machine without power-profiles-daemon still has a Power page.

**Lid and power button** (`sleep.py`). What closing the lid (on battery and
plugged in) and pressing the power button do, and how long
suspend-then-hibernate stays suspended. Atropa writes its own drop-ins,
`/etc/systemd/logind.conf.d/50-atropa.conf` and
`/etc/systemd/sleep.conf.d/50-atropa.conf`, so a hand-edited `logind.conf`
is never rewritten; deleting them goes back to it. Applying reloads
systemd-logind (`systemctl reload`, the one reload the helper allows),
which re-reads the configuration without ending sessions - a restart would
end the graphical session, which is why this used to be a manual edit.
systemd-sleep reads `sleep.conf` at each suspend, so that drop-in needs
nothing.

`read_settings()` follows systemd's precedence (the first main file of
/etc, /run, /usr/local/lib, /usr/lib, then every `*.conf` drop-in in file
name order, a name in /etc hiding the same name below it, last assignment
wins, an empty one resets) and reports each value with the file it came
from, so a later drop-in that overrides Atropa's shows up on the page.
Hibernating actions are only offered when the kernel advertises `disk`;
a value already set is always shown. The lid rows only appear when
`/proc/acpi/button/lid` exists. The delay accepts any one-line systemd time
span, so a hand-set `1h 30min` survives an Apply.

### Flatpak (`flatpak.py` / `pages/flatpak.py`)

Installed apps, pending updates, `update -y` and `uninstall --unused`, both
streamed into the progress dialog. Whether root is needed is decided per
operation with `flatpak list --system` rather than assumed, so per-user
installs don't prompt and system installs do. "No updates" is an empty list,
not an error.

### Dependencies (`dependencies.py` / `pages/dependencies.py`)
A static catalog of `Dependency(name, module, description, package,
required, note)`; `check_all() -> list[DependencyStatus]`,
`missing_required()`. AUR-only tools (paru/yay, aide,
and SELinux's userspace tools - their notes are built from
`selinux.SELINUX_TOOL_PACKAGES` and mention the Quick Setup repository as
the other way to get them) have `package=None` and a note instead of
an Install button that would run `pacman -S` and fail. `checkupdates`
(pacman-contrib) and `fakeroot` are listed for the Packages page's live
update check; the desktop modules added `reflector`, `fwupdmgr`, `smartctl`,
`fstrim`, `du`, `journalctl`, `coredumpctl`, `powerprofilesctl`, `zramctl`,
`flatpak`, `findmnt`, `sbctl` and `mokutil`. `zram-generator` is deliberately
absent: its generator lives under `/usr/lib/systemd/system-generators`, not
on `PATH`, so `check_all()`'s `shutil.which` would report it missing even
when installed - the Power page checks it with `pacman -Q` instead.

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
Lists `list_backups()` - the helper's root-owned store and, if there is
one, the old home store (marked "kept in your home folder", viewable but
restored only without the helper) - with View (a root-owned backup is read
through the helper's `backup-show`) and Restore (confirmed, through
`backup-restore`), and `get_recent_actions()` (read-only tail of the action
log). When old ArchYaST data exists, a migration section appears, backed by
`migration.py`: `detect_legacy_data() -> LegacyDataStatus`,
`migrate_user_data(on_line)` (`~/.local/share/archyast` → `atropa`,
non-destructive, logs prepended), `migrate_plugin_data(on_line)`
(`/etc/archyast` → `/etc/atropa`, privileged, `cp -n`), and separate
confirm-gated `remove_legacy_user_data()` / `remove_legacy_plugin_data()`.

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
self.confirm(heading, body, danger_label, on_confirm, on_cancel=None, destructive=True)
                                                    # markup disabled; destructive=False for a plain confirm
```

A page that needs more than one scrolling column can replace what the toast
overlay shows: SELinux: Denials puts an `Adw.NavigationSplitView` there
(programs on the left, the selected program on the right) and points
`self.preferences_page` at its sidebar, so `add_group()` keeps working.

### Visual language (`main_window.py` + `resources/style.css`)

The chrome is deliberately built from stock libadwaita widgets plus one
stylesheet, not a custom widget toolkit:

- `MODULES` is a list of `Module(key, title, icon, page, tagline, section)`.
  `section` drives the sidebar's **CORE / SECURITY / MAINTENANCE /
  EXTENSIONS** groups; `tagline` is the content header subtitle and is also
  searchable. A plugin becomes a `Module` with `section="extensions"`.
- The sidebar is a brand header (logo + name + "System control center"), a
  module search entry, one `ListBox` with non-selectable section header rows,
  and a footer explaining the polkit model. Search hides non-matching rows and
  empty sections, offers a keyboard-friendly empty state, and `Enter` opens
  the first match. `Ctrl+K` / `Ctrl+F` focus the search; `Esc` clears it.
- The content header carries the active module's icon (accent-tinted tile),
  title and tagline in an `Adw.WindowTitle`, plus a menu with **Refresh
  Page** (`F5`), **Search Modules** and an `Adw.AboutDialog`. The OS window
  title tracks the active module too.
- In the collapsed one-pane layout the sidebar header needs the window
  controls back (there is no content header on screen); `_sync_sidebar_window_controls()`
  follows `NavigationSplitView:collapsed`.
- `theme.py` loads `resources/style.css` at `STYLE_PROVIDER_PRIORITY_APPLICATION`
  on startup. The stylesheet uses **only Adwaita named colours**
  (`@accent_bg_color`, `@window_fg_color`, `@borders`, ...), so light mode,
  dark mode and the desktop's accent colour all keep working. It styles the
  sidebar, header tiles, group cards, buttons, switches and scrollbars; no
  page logic depends on it. A missing stylesheet is non-fatal at runtime, but
  `tests/test_resources.py` checks that it is shipped in the wheel.
- `BasePage` adds the `atropa-page` class to its `Adw.PreferencesPage`, which
  is the hook for the card/typography refinements. New pages get the same
  look for free by going through `add_group()` as usual.

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

**Two controls are locked on top of that.** The SELinux enforcing switch
has a click-to-arm lock - no password, it stops a stray click or drag.
Quick Setup's locked item takes the administrator password to unlock
(`privilege.authenticate()`), locks again after every run, and is refused
by the backend for any caller that doesn't say it was unlocked (see
Security Quick Setup in section 2).

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

**Shared SELinux widgets.** `ui/selinux_module_view.py` (`ModuleView`) is
the one module view, used by SELinux: Denials for a program's draft and by
SELinux: Modules (in an `Adw.Dialog`) for pending, installed and loaded
modules. `ui/selinux_lint.py` has the badge text, the findings as text and
`install()`, the acknowledge-each-dangerous-finding dialog every install
path goes through.

**Cross-page links.** The SELinux page's "Open Denials" calls the window's
`_activate_module("selinux_review")`.

**Lazy construction, no auto-refresh on navigation**: a page is only
constructed (and its initial `refresh()` run) the first time its sidebar
entry is clicked; `_on_row_activated` deliberately does **not** call
`refresh()` again on later visits, so privileged reads don't re-prompt for
authentication on every click (each one used to prompt again).
Pages that need fresh data have their own Refresh/Re-scan button.

---

## 4. Testing

**The suite**: `tests/`, 1,634 tests in 52 files - one `test_<module>.py`
per backend module plus the helper (`test_helper.py`,
`test_helper_backups.py`, `test_helper_shapes.py`), `test_resources.py`,
`test_stock_configs.py`, `test_te_lint.py` and the GTK smoke test - run with
`python3 -m pytest` (config in `pyproject.toml`). CI
(`.github/workflows/ci.yml`) runs `py_compile`, `ruff check` and the suite
on Python 3.11-3.14, and a second job runs `tests/test_ui_smoke.py` under
`xvfb-run` with the distro's PyGObject.

**Fixtures** (`tests/conftest.py`):

- `fake_run` - replaces `privilege._subprocess_run` (where every command
  starts) and `subprocess.run`, with a prefix-matching response registry;
  `.calls` and `.inputs` record what ran. **Not** autouse: a test that
  doesn't ask for it runs real commands, so give it to every test that
  reaches a backend call.
- `fake_which` - which CLI tools "exist"; `pkexec_on_path` for tests that
  need pkexec found.
- `privilege_paths` (autouse) - points `HOME`, the action log, both backup
  stores, the helper's backup store, the SELinux review folders, the
  downloaded policy, the legacy ArchYaST folder and the su PAM files into
  `tmp_path`. It used to be opt-in, and one test run wrote over a thousand
  fake log lines and several "backups" into the developer's real
  `~/.local/share/atropa`.
- `no_host_helper` (autouse) - `HELPER_PATH`/`ASK_HELPER_PATH` point at
  paths that don't exist, so the suite behaves the same whether or not
  Atropa is installed (makepkg's `check()` runs after a previous install).
- `kernel_state` (autouse) - the live LSM list and AppArmor flags read
  from files under `tmp_path` (GitHub's runners have AppArmor on).
- `no_host_policy` - the SELinux policy checker never loads the host's
  policy; `module_dirs` - SELinux review folders for tests that need them.

**Real data as fixtures.** `tests/fixtures/stock/` holds unmodified config
files from Arch's packages (pacman.conf, sshd_config, /etc/default/grub,
loader.conf, logind.conf, sleep.conf, faillock.conf, pwquality.conf, the su
and system-auth PAM files, locale.gen, mirrorlist, snapper's template;
versions in its README), and `test_stock_configs.py` checks every parser
reads them and every edit changes exactly the line it should.
`tests/fixtures/te/` has real audit2allow drafts from an enforcing desktop,
which the linter must not call dangerous. Running parsers against real
output found bugs hand-written fixtures couldn't (the fixtures shared the
parser's assumptions): smartctl's probe error read as a failing disk,
coredumpctl's SIZE column read as the program name.

**The smoke test** sets `ATROPA_UI_SMOKE=1`, which makes
`BasePage.run_async()` a no-op, and builds every page plus the SELinux
module view - widget construction, not backend behaviour. It skips itself
without a display.

**Guards**: `test_privilege.py` AST-walks every module for `shell=True`,
`os.system` and `os.popen`; `test_helper.py` checks every path the backend
writes is in the helper's policy; `test_helper_shapes.py` checks every
privileged argv against the helper and its tier; `test_resources.py` checks
the icon name agrees between `main.py`, the launcher and the icon files.

**Lessons worth keeping:**

- Patch the one boundary every path goes through, not a name imported into
  one module. A test that mocked `security.run_privileged` passed for the
  wrong reason: `backup_file` calls `run_privileged` through
  `privilege.py`'s own reference (`from x import y` copies a reference),
  and the "expected" error was a real `PrivilegeError` caught by the same
  `except RuntimeError`.
- After editing near an existing function, `grep -n "^def <name>"` to
  check there's still one definition: duplicate `install_pp_file` and
  `check_updates` definitions once silently shadowed the real ones.
- Check a test's assumptions against the real format, not just that it
  passes: an AppArmor rule test passed with an invented `protocol=` field
  while real denials carry `sock_type=`.
- The linter is an install gate, so its tests include constructs that must
  come out dangerous because the parser can't vouch for them - three
  bypasses were found by an automated security review before that rule.

---

## 5. Known limitations (intentional, not oversights)

- **systemd-networkd**: detected, read-only.
- **GRUB reinstall**: not automated (picking the wrong disk is destructive).
- **Unified kernel images**: their parameters live in `/etc/kernel/cmdline`;
  Kernel parameters doesn't edit them. Editing `mkinitcpio.conf` is out of
  scope too.
- **systemd-boot**: kernel parameters, kept entries and copied kernel
  entries are covered by unit tests only; the test VM boots GRUB.
- **Partial upgrades**: no `pacman -Sy` and no single-package update; the
  only ways to change packages are a full upgrade, an install that refuses
  while the database is ahead, and "Upgrade and install".
- **PAM**: Atropa edits only stock lines - `pam_wheel` in su/su-l and
  pam_pwquality in pambase's `system-auth` - and refuses hand-edited files.
  pam_faillock needs no wiring on Arch.
- **AUR-only tools** (AIDE, paru/yay, SELinux userspace without the
  unsigned repository): detected and used once installed, never built by
  Atropa; AUR builds through paru/yay get no PKGBUILD review or sandbox.
- **Turning SELinux on**: Atropa installs its tools (behind the Quick Setup
  lock), fetches, builds, installs and activates a policy, and can add the
  kernel parameter. Swapping the base packages for their SELinux builds and
  the reboot stay manual.
- **SELinux category detection** reads the denying process's cgroup while
  it runs; it hasn't been checked against a live enforcing desktop's
  denials yet. The Build Policy page's own modules aren't linted.
- **Plugins**: declarative TOML only, limited to `plugin_registry.REGISTRY`;
  enabling or disabling takes effect on next launch.
- **Smartctl needs root on most machines**: Disk Health reads unprivileged
  first and offers one privileged read; opening the page never prompts.
- **Hardware the test VM doesn't have**: fwupd devices, battery charge
  thresholds, Secure Boot firmware and laptop lids have only been tested
  against documented output shapes.
- **Secure Boot enrollment** still needs the firmware in setup mode, which
  Atropa can't switch; it says so before enrolling.
- **zram swap** needs `zram-generator` and CONFIG_ZRAM; the Power page
  checks the package with `pacman -Q` (its generator isn't on PATH).
- **Disk and partition management**: out of scope. Timeshift isn't
  integrated; Snapper covers the same need.
- No i18n/l10n.

---

## 6. Working on Atropa

- **Dev setup**: the backend and tests need no GTK. In a virtualenv:
  `pip install pytest ruff`. Avoid `--break-system-packages` on Arch.
- **Checks** (what CI runs):
  `python3 -m py_compile atropa/*.py atropa/ui/*.py atropa/ui/pages/*.py atropa/backend/*.py tests/*.py`,
  `ruff check .` (`E9`/`F`/`W`, config in `pyproject.toml`) and
  `python3 -m pytest -q`. The smoke test needs a display:
  `xvfb-run -a python3 -m pytest tests/test_ui_smoke.py`.
- **Run from source**: `python3 -m atropa.main` (needs `python-gobject gtk4
  libadwaita polkit`). Without the installed helper every privileged call
  asks for the password.
- **Package it**: `cd packaging/arch && makepkg -C -si`. `-C` matters when
  `makepkg.conf` sets `BUILDDIR`: a build folder left from an earlier build
  keeps pointing at that build's clone, and makepkg quietly builds the old
  version.
- **Adding a privileged action**: give the program a validator in
  `helper.COMMANDS` (or a file path in `WRITE_FILES`/`WRITE_DIRS`), decide
  its tier, and let `test_helper.py`/`test_helper_shapes.py` tell you what
  you missed. A file whose content can run code as root belongs in
  `ASK_WRITE_FILES`.
- **Icon names**: only names GTK can load from the installed theme (check
  with `Gtk.IconTheme.has_icon()`, not just the file - the Firmware page's
  `application-x-firmware-symbolic` existed as a file and still rendered as
  the missing-image placeholder).
- **SELinux on the developer's machine**: the system Atropa is developed on
  runs SELinux enforcing with a reference policy, which is where the
  SELinux pages were calibrated; AppArmor is tested in a VM.
