# Stock configuration files

Unmodified copies of the files Atropa parses and edits, as Arch's packages
ship them, so the parser tests run against real files rather than
hand-written snippets. Refresh them from newer packages when they change:

```bash
bsdtar -xf <package>.pkg.tar.zst -C <dir> etc/...
```

| File | Package | Path |
|---|---|---|
| `pacman.conf` | pacman 7.1.0.r9.g54d9411-4 | `/etc/pacman.conf` |
| `mirrorlist` | pacman-mirrorlist 20260610-1 | `/etc/pacman.d/mirrorlist` |
| `sshd_config` | openssh 10.6p2-1 | `/etc/ssh/sshd_config` |
| `default-grub` | grub 2:2.16-1 | `/etc/default/grub` |
| `loader.conf` | systemd 262.2-1 | `/usr/share/systemd/bootctl/loader.conf` (what `bootctl install` writes) |
| `logind.conf`, `sleep.conf` | systemd 262.2-1 | `/etc/systemd/` |
| `faillock.conf` | pam 1.7.3-1 | `/etc/security/faillock.conf` |
| `pwquality.conf` | libpwquality 1.4.5-7 | `/etc/security/pwquality.conf` |
| `pam.d-su`, `pam.d-su-l` | util-linux 2.42.4-1 | `/etc/pam.d/su`, `/etc/pam.d/su-l` |
| `locale.gen` | glibc 2.44+r78 | `/etc/locale.gen` |
| `snapper-config-template` | snapper 0.13.2-2 | `/usr/share/snapper/config-templates/default` |
