# Atropa - development history

This is the project's working history, kept for the reasoning behind
decisions: phase write-ups, bug-fix entries, the brainstormed roadmap and
the design specs written before features were built. It was written as the
work happened and is **not** updated as the code changes, so parts of it
describe code that has since been rewritten, renamed or removed.

For how Atropa works now, read [`DOCUMENTATION.md`](../DOCUMENTATION.md);
for what's still open, [`TODO.md`](../TODO.md).

---

## Roadmap, phase write-ups and bug-fix log

(Formerly section 6 of DOCUMENTATION.md.)

**Done since the brainstorm:**
- ✅ Config backup + restore mechanism (Activity & Backups page)
- ✅ SSH validate-before-reload with auto-rollback
- ✅ AppArmor parity with SELinux (profile toggles, denial review)
- ✅ Package management visibility (real pending-updates list, not just a count; gated single-package update -
  removed again later, see the second bug-fix batch at the end of this section)
- ✅ A real pytest suite (1159 tests as of the latest pass, across all 31 `backend/` modules, one
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
  module invokes (pkexec/sudo, pacman/AUR helpers, systemd,
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

- ✅ **File Integrity page expanded past counts.** The page used to say
  "3 changed" and forget which files as soon as the streaming dialog
  closed. Now `aide.parse_check_entries()` reads the report's
  added/removed/changed sections into paths (with AIDE's marker column),
  `build/save/load/clear_check_record()` persists the last check to
  `~/.local/share/atropa/aide_last_check.json`, and the page shows a
  "Last check" group that survives restarts - up to 60 paths labelled
  ADDED/REMOVED/CHANGED, then "… and N more". Re-baselining clears it,
  since those changes are accepted as the new normal. Also added
  `aide --config-check` behind a Validate button (fast, pkexec) and
  `timer_details()` (systemctl show properties) so the timer row says when
  the next check runs instead of only active/inactive.

- ✅ **`makepkg` check() is host-independent now.** The suite had a fresh
  failure mode only after installation: with `/usr/lib/atropa/atropa-helper`
  present, `privilege._resolve_privileged_prefix()` correctly prepends it,
  so every test asserting `["pkexec", "systemctl", ...]` failed - and
  `makepkg`'s check() runs *after* the package may already be installed.
  A `no_host_helper` autouse fixture now points `HELPER_PATH` at a
  nonexistent `tmp_path` file (tests that exercise the helper set it
  themselves), making `makepkg`, CI and a developer machine agree.
  Verified by running the whole suite with a simulated installed helper
  (`/usr/bin/true` as its path): 1036 tests pass either way.

- ✅ **pkexec remembers now: one helper, one password, five minutes.**
  The documented polkit bug is fixed. `atropa/helper.py` is installed
  root-owned at `/usr/lib/atropa/atropa-helper`; the shipped policy
  annotates that exact path and sets `allow_active=auth_admin_keep`, so
  polkit keeps the authorization for its window instead of asking on every
  `tee`/`sed`/`systemctl`. The helper validates a bare-name allowlist
  (no shell, no paths), and `tests/test_helper.py` walks the backend's
  privileged call sites so a newly added command can't silently stop
  working. `install.sh` and the PKGBUILD install the helper and policy;
  without them the app falls back to the old per-command prompting.
  Still open: the operation-level helper API and root-owned backups.

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
    2) was **not implemented** at the time (it is now: see Hardening) - editing `/etc/pam.d/su` carries the exact
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

- ✅ **SELinux from inside Atropa: the tools and the policy.** Two things
  that used to be "do it yourself first":
  1. **The tools.** SELinux's userspace isn't in Arch's official
     repositories. The archlinuxhardened project publishes a binary
     repository, and Quick Setup can now add it to `pacman.conf` so the
     SELinux step installs the tools with pacman. It is unsigned
     (`SigLevel = Never`, as its own README says it has to be), so pacman
     installs from it unverified, as root. Hence the lock: the item can't
     be ticked without the administrator password, the confirmation
     repeats what it does, the backend refuses it for any caller that
     doesn't pass it as unlocked, and profile import never does - before
     that last part, a hand-edited profile containing its key would have
     switched the repository on with no lock at all.
  2. **The policy.** The Build Policy page can fetch Atropa's own
     reference policy and fills in its name. It is targeted-style despite
     `TYPE = standard` in its `build.conf`, so Activate's default login
     mapping to `unconfined_u` is the one it needs.

  Still manual: swapping the base packages for their SELinux builds, the
  kernel parameter, and the reboot. Quick Setup's status lines became
  independent of each other in the same change.

  How far this was checked: against real pacman, the repository was
  accepted, synced, and the five tool packages resolved from it; removing
  it left `pacman.conf` byte-identical. The packages are x86_64-only and
  the machine this was written on isn't, so Quick Setup's install step and
  building the policy with the installed tools were not run. The
  repository itself is in use on the maintainer's x86_64 machine.

- ✅ **What the README listed but no page offered** - six things, each
  with its backend function already written and tested:
  1. **Set a user's password** - typed twice in a dialog.
  2. **Groups** - create and delete in the Groups list, a user's
     memberships from their row.
  3. **Restart a service** and 4. **its journal**, on each Services row.
  5. **Orphaned packages** on the Packages page, removable one by one or
     all together.
  6. **Turn USBGuard off**, next to the button that turns it on.

  The guards and refusals are in section 2 under each module. Found on the
  way: `nobody` was listed as a regular user and group. The same change
  closed the two packaging items (`install.sh` installs `pacman-contrib`
  and `fakeroot`; the launcher has one main category) and gave the README
  screenshots (`docs/screenshots/`; `tests/test_resources.py` checks that
  every image the README shows exists).

  How far this was checked: users, passwords, groups and the orphan list
  ran for real against useradd, chpasswd, usermod, groupadd and pacman.
  Restart, the journal and USBGuard need systemd, which wasn't available
  where this was written: there the dialogs and the commands sent were
  checked, not their effect.

- ✅ **Seven desktop modules and an exposure-framed audit.** The earlier
  passes were server-shaped: firewall, SSH, fail2ban, SELinux, CIS categories.
  This pass added the things that actually go wrong or matter on a
  single-user Arch laptop, each as backend module + page + tests, and wired
  into the sidebar and the Dependencies catalog:
  - **Mirrors** (`mirrors.py`) - reflector ranking, backup-first mirrorlist
    replacement.
  - **Boot Report** (`boot_report.py`) - this boot's journal errors, failed
    units (reusing `system_health`'s parser) and coredumpctl crashes, each
    isolated so one missing tool doesn't blank the page.
  - **Firmware** (`firmware.py`) - fwupd device/update listing with a tolerant
    JSON parser, pkexec'd metadata refresh and streamed `update -y`.
  - **Disk Health** (`disk_health.py`) - SMART (with smartctl's exit-bit
    semantics), df usage, fstrim.timer, and journal/cache/coredump cleanup.
  - **Power** (`power.py`) - power-profiles-daemon, battery charge limits,
    zram and hibernation feasibility, zram-generator config writing.
  - **Flatpak** (`flatpak.py`) - app/update listing, streamed update and
    unused-runtime removal, with per-user vs system-wide privilege decided
    from `flatpak list --system` instead of guessed.
  - **Encryption & Secure Boot** (`boot_security.py`) - LUKS detection
    through findmnt/lsblk with a crypttab fallback, bootctl/mokutil Secure
    Boot state, and sbctl create/enroll/sign behind pkexec.
  Two of these are also the first checks that ask "is the *disk* safe", not
  just "is the *service* configured", so they were fed into the audit:
  `compliance.py` gained a "Boot & Disk Security" category and an `Exposure`
  summary (low/moderate/high) built from firewall, reachable SSH,
  non-loopback listening sockets, LUKS and Secure Boot, with the percentage
  re-framed as "share of checks holding" rather than a CIS score. Quick Setup
  grew a desktop mode: with no sshd it no longer opens port 22 (it used to,
  on every machine, server-shaped default included), skips fail2ban, and
  shows a read-only desktop baseline (firewall, encryption, Secure Boot)
  instead of pretending the server checklist fits.
  Every new backend module has its own pytest file (347 new tests); the
  environment couldn't run any of the tools for real (no fwupd, no battery,
  no Secure Boot on the sandbox), so command parsing is tested against
  documented output shapes and the pages are deliberately conservative about
  actions.

- ✅ **`.pacnew`/`.pacsave` handling** (new `backend/pacnew.py` + the
  Config Changes page) - the top item on the single-user desktop TODO.
  `scan()` walks `/etc`, `diff_text()` builds a unified diff with difflib
  (no shell, missing live side reads as all-new), and applying a candidate
  backs up the live file and goes through the helper's bounded
  `pacnew-apply` operation. The page offers Show diff, Use new version /
  Restore saved config, and Keep current; merging stays a manual edit
  rather than an unsafe automated three-way merge. The helper operations
  only accept an existing regular `*.pacnew`/`*.pacsave` under `/etc`,
  which an unprivileged user cannot create, so this does not reopen the
  "write any /etc file" hole phase 1 closed.

- ✅ **Arch news before upgrading** (new `backend/news.py`, the Packages
  page's "Before Upgrading" group) - fetches the Arch news RSS, keeps items
  published after the last `starting full system upgrade` line in
  `/var/log/pacman.log`, and lists them with dates and an Open link. Never
  fetched when the page opens, never raises (failures become one line), and
  the parser tests inject the feed so CI stays offline. Completes the
  "Before: recent Arch news" upgrade check.

- ✅ **CI can see the UI now.** A separate `gtk-smoke` job installs the
  distro PyGObject + Xvfb and constructs every one of the 30 pages under
  `xvfb-run`; `ATROPA_UI_SMOKE=1` turns `BasePage.run_async()` into a no-op
  so building a page never shells out on a runner. The backend matrix also
  grew 3.13/3.14. This is the CI item that the repo audit asked for - and
  it would have caught the GTK-API mistakes previously found by eye.

- ✅ **Version 0.2.0** - first tagged release after the desktop-module,
  helper and exposure work, with a stable `atropa` PKGBUILD that builds
  from the release tarball instead of the git head.

**Still open:**
- Bootloader/AppArmor kernel-param and PAM-wiring automation, **now that a
  backup mechanism exists** to lean on — could pair with e.g. keeping the
  previous kernel cmdline as a separate boot entry so a bad boot just picks
  the old one instead of needing a recovery shell
- Disk/partition management (explicitly out of scope at project start)
- Btrfs snapshots / Timeshift integration ("snapshot before this risky op" is
  a very YaST-shaped feature, pairs with the backup mechanism)
- Journal/log viewer (already runs `journalctl` in several places,
  never surfaced as its own page)
- Kernel management (multiple kernels, `mkinitcpio`, headers) - built: see
  Kernels; `mkinitcpio.conf` editing stays out

**Still open from the full-repo audit** (rough priority order):
- Run the SELinux path once on x86_64 through Atropa: Quick Setup's SELinux
  step through to installed tools (the repository itself is known to
  work), then Get, Build and Install on the Build Policy page
- Check Restart, the journal dialog and USBGuard's "Turn off" on a machine
  with systemd (see the entry above)
- Check bootloader detection on a real UEFI machine that boots GRUB: the
  fix above rests on GRUB 2.12 writing "GRUB ..." to `LoaderInfo` and on
  `bootctl --print-esp-path` answering there, neither of which could be
  run where it was written
- CI: a GTK smoke test that builds every page under Xvfb (the backend
  suite never imports GTK), Python 3.13/3.14 in the matrix next to
  3.11/3.12, and tests that run the parsers against real config files
  rather than hand-written snippets
- The privileged helper is still a *command* allowlist (validated per
  program and argument shape, in two tiers) rather than one entry point
  per operation


---

## Design specs written before building

(Formerly in TODO.md. Both were built as specified, with the decisions
noted; DOCUMENTATION.md describes the result.)

### Over-permissive module warnings

Warn when a drafted (or hand-edited) module grants more than the program
should need, judged against what kind of program it is. Builds on what's
already there: `te_warnings()`, `PolicyChecker`, `noise_reason()`,
`label_hint()`, `te_booleans()`.

- [x] **Parser** - new `backend/te_lint.py` turns a `.te` into rules
      (kind, source, target, class, perms, line) plus its `require` block;
      handles hand edits (braces, `~`, `*`, attributes). With setools,
      attribute targets expand, so `file_type:file write` counts as
      touching thousands of types.
- [x] **Base rules** - a data table: id, severity, match, why, fix.
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
- [x] **Program categories** - linked toggle buttons per pending module:
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
- [x] **UI** - badge per module (Looks fine / Review / Dangerous); each
      finding shows the highlighted line, why, and a one-click safer option
      where it's mechanical (switch to `dontaudit`, enable boolean X,
      relabel with `restorecon`/`semanage fcontext`, drop these perms, split
      the module). Live re-lint of hand edits. Install: fine -> as today;
      Review -> confirm listing findings; Dangerous -> disabled until each
      dangerous finding is acknowledged.
- [x] **Backend gate** - `compile_and_load_te()` lints itself and refuses
      unacknowledged Dangerous findings (`acknowledged={rule ids}`,
      recorded with the category), so "reinstall all approved" and future
      callers can't skip it. On top of the ask-tier `semodule -i`, not
      instead of it.
- [x] **Installed modules** - lint approved/installed Atropa modules on page
      load; compliance report gains "Custom SELinux modules" (warn per
      module with Dangerous findings).
- [x] **Tests** - a should/shouldn't-flag `.te` fixture per rule and per
      category; detection tests from captured AVCs plus unit files; real
      drafts (host pending modules incl. Brave/flatpak, the VM's) as a
      calibration corpus; the backend refusing unacknowledged rules.
- [x] **Open decisions** - decided: acknowledge-to-install; Build Policy not
      linted yet; 25 kept (the real drafts top out at 7 rules). Was: hard block vs loud warning for Dangerous (design
      assumes acknowledge-to-proceed); also lint the Build Policy page's
      modules?; tune the ~25-rule threshold on real modules.

### SELinux pages redesign

Today denials and modules are spread over four sidebar entries, and the
same job lives in three places: the SELinux status page has its own denial
list with "Generate .te" and Install, Denial Review has drafts with View
and Install, and Load Policy has Pending/Approved plus an editor. Denial
Review itself is one long scroll of eight groups sorted by classification,
while modules (and now program categories) are per program, and a draft
opens as plain text in a popup with nowhere to show lint findings.

- [x] **Three entries instead of four**:
  - *SELinux* - configuration only: mode, Setup Mode, relabel, booleans.
    Its own denial list and review buttons go; one row says "N programs
    need attention" and opens Denials.
  - *SELinux: Denials* - replaces Denial Review (below).
  - *SELinux: Modules* - replaces Load Policy: installed Atropa modules
    (with lint badges, so old approvals get checked), pending, approved but
    inactive, "Load .te from disk". Opening any module uses the same
    detail view as Denials, so a hand-loaded `.te` is linted too.
  - *SELinux: Build Policy* stays as it is.
- [x] **Denials: a list of programs, not of classifications** -
      `Adw.NavigationSplitView`: programs (SELinux domain + executable) on
      the left, the selected program on the right (pushed as a page on a
      narrow window).
  - Top of the list: "Review now" with the source (kernel log / audit.log,
    the latter asking for the password) and filter chips with counts:
    Needs action, Noise, Done.
  - Each row: program name, category, denial count, and one badge for the
    best next step: Dangerous / Review / Boolean / Relabel / Noise / Done.
    Sorted by that badge, then count - impact first.
- [x] **Program page**, top to bottom:
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
- [x] **Keep what works** - Setup Mode, the restorecon button, boolean
      "Turn on" with its rule count, the Undefined-class Help dialog and
      the per-domain module naming all move into the new views unchanged.
- [x] **Smoke test and screenshots** - every new view built under Xvfb in
      `tests/test_ui_smoke.py`, and rendered in the VM against real denials
      before merging.
