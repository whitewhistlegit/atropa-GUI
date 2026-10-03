#!/usr/bin/env bash
# Installs Atropa system-wide on an Arch Linux machine.
set -euo pipefail

if [[ ! -f /etc/arch-release ]] && ! command -v pacman &>/dev/null; then
    echo "This installer expects an Arch Linux system (pacman not found)." >&2
    exit 1
fi

echo "==> Installing system dependencies (requires sudo)..."
sudo pacman -S --needed --noconfirm \
    python python-pip python-pipx python-gobject gtk4 libadwaita polkit \
    networkmanager

echo "==> Optional hardening tools (skip any that fail, they're not required to run Atropa)..."
sudo pacman -S --needed --noconfirm arch-audit || true
echo "    fail2ban, apparmor, usbguard, and audit are also supported if you install them:"
echo "      sudo pacman -S fail2ban apparmor usbguard audit"
echo "    SELinux denial review (Why?/Generate .te) and policy loading need:"
echo "      pacman -S audit policycoreutils"

echo "==> Installing Atropa via pipx (an isolated venv, not the system Python)..."
# `pip install --user --break-system-packages` used to be here - it works,
# but it's the wrong tool for this: it overrides Arch's PEP 668 protection
# and installs straight into ~/.local's *user* site-packages, a namespace
# shared with anything else that's ever used --user or --break-system-
# packages, with no isolation and no clean uninstall path. pipx gives
# Atropa its own dedicated venv (installed by pacman above, no
# --break-system-packages needed for pipx itself either, since it's a
# proper Arch package) and a single, clean `pipx uninstall atropa` to
# remove it later. --system-site-packages is what actually matters for a
# GTK app specifically: Atropa's one real dependency, PyGObject, needs to
# match the system's own GTK4/libadwaita libraries (installed via pacman
# above) - it can't be pip-installed fresh into an isolated venv without
# the matching system dev headers, so the venv instead inherits the
# system's already-working PyGObject rather than trying to rebuild it.
# --force lets re-running this installer cleanly upgrade an existing
# install rather than erroring that it's already there.
pipx install --system-site-packages --force .
pipx ensurepath --force >/dev/null 2>&1 || true

echo "==> Installing desktop launcher..."
mkdir -p "$HOME/.local/share/applications"
cp atropa/resources/atropa.desktop "$HOME/.local/share/applications/"

echo "==> Installing polkit policy for smoother authentication prompts..."
sudo cp atropa/resources/org.atropa.pkexec.policy /usr/share/polkit-1/actions/

echo "==> Done. Launch Atropa from your app menu, or run: atropa"
echo "    (if 'atropa' isn't found in this same terminal, open a new one or"
echo "    run 'source ~/.bashrc' / restart your shell so pipx's PATH change"
echo "    from 'pipx ensurepath' above takes effect)"
