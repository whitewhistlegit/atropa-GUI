"""
atropa.backend.inventory
------------------------------
CIS-DIL-inspired special-purpose service inventory (CIS 2.2 "Services") -
an itemized "should this be installed and running on a workstation?"
checklist, read-only (no auto-remove/disable actions - deciding a real
server role isn't wanted is a human judgment call, not something to batch
away).

Arch-specific note: CIS's own 2.2/server vs 2.3/client split assumes a
distro (RHEL/Debian-family) that ships client and server tools in separate
packages. Arch frequently doesn't - `inetutils` bundles the legacy
telnet/rsh/talk *clients* together with their matching listening sockets
in one package, and `openldap`/`nfs-utils` similarly bundle client and
server pieces. Rather than force an artificial client/server split that
doesn't match how Arch actually packages things, every entry here just
reports what's real: whether the package is installed, and - if it has
one - whether its service is actually active and listening. A package
installed but inactive is a much smaller finding (leftover client tools)
than one installed AND active (an actual exposed service), so status
reflects that distinction directly instead of forcing a category label
that wouldn't be accurate here.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .privilege import run_unprivileged


@dataclass
class ServiceEntry:
    key: str
    title: str
    description: str
    packages: list[str]  # any one being installed counts as "installed"
    units: list[str] = field(default_factory=list)  # any one active counts as "active"; empty = client-only, no listener


CATALOG: list[ServiceEntry] = [
    ServiceEntry(
        "avahi", "Avahi (mDNS/DNS-SD)",
        "Zeroconf network discovery - convenient on a LAN, an unnecessary broadcast surface on anything else.",
        ["avahi"], ["avahi-daemon"],
    ),
    ServiceEntry(
        "cups", "CUPS (print server)",
        "Print spooling. Needed if this machine handles printing (including sharing a printer), otherwise unused surface.",
        ["cups"], ["cups"],
    ),
    ServiceEntry(
        "dhcp-server", "DHCP server",
        "Hands out IP leases to other hosts. A workstation almost never needs to run this itself.",
        ["dhcp"], ["dhcpd4", "dhcpd6"],
    ),
    ServiceEntry(
        "openldap", "OpenLDAP (server + client tools)",
        "Directory service. The same package provides ldapsearch/ldapmodify client tools and the slapd server - "
        "\"installed\" alone just means the client tools are present; \"active\" means slapd is actually serving.",
        ["openldap"], ["slapd"],
    ),
    ServiceEntry(
        "nfs-server", "NFS server",
        "Exports filesystems to the network. nfs-utils also provides the NFS *client* (mount.nfs), so installed-but-"
        "inactive here just means client mounting capability is present, not that anything is being shared.",
        ["nfs-utils"], ["nfs-server"],
    ),
    ServiceEntry(
        "bind", "BIND (DNS server)",
        "Authoritative/recursive DNS server. Running one on a general-purpose machine is unusual.",
        ["bind"], ["named"],
    ),
    ServiceEntry(
        "vsftpd", "vsftpd (FTP server)",
        "Plaintext-by-default file transfer server - CIS flags FTP servers generally as legacy/insecure.",
        ["vsftpd"], ["vsftpd"],
    ),
    ServiceEntry(
        "httpd", "Apache HTTP Server",
        "General-purpose web server daemon.",
        ["apache"], ["httpd"],
    ),
    ServiceEntry(
        "nginx", "nginx",
        "General-purpose web server / reverse proxy daemon.",
        ["nginx"], ["nginx"],
    ),
    ServiceEntry(
        "dovecot", "Dovecot (IMAP/POP3 server)",
        "Mail retrieval server.",
        ["dovecot"], ["dovecot"],
    ),
    ServiceEntry(
        "samba", "Samba (SMB/CIFS file+print sharing)",
        "Windows-compatible file/print sharing. Package unit was renamed smbd->smb in samba 4.8+.",
        ["samba"], ["smb"],
    ),
    ServiceEntry(
        "squid", "Squid (HTTP proxy)",
        "Caching HTTP proxy server.",
        ["squid"], ["squid"],
    ),
    ServiceEntry(
        "snmpd", "net-snmp (SNMP agent)",
        "Exposes system info/metrics over SNMP - old SNMP versions (v1/v2c) transmit the community string in "
        "plaintext, so CIS treats an unneeded SNMP agent as real exposure, not just noise.",
        ["net-snmp"], ["snmpd"],
    ),
    ServiceEntry(
        "rsyncd", "rsync daemon mode",
        "The rsync package itself is a normal, widely-needed client tool - this only flags rsyncd, the standalone "
        "daemon (unauthenticated-by-default rsync:// listener), not rsync usage over SSH.",
        ["rsync"], ["rsyncd"],
    ),
    ServiceEntry(
        "xinetd", "xinetd (super-server)",
        "Legacy on-demand service dispatcher. Its presence at all is the finding here - it exists specifically to "
        "launch other legacy network services (telnet/tftp/etc) on demand.",
        ["xinetd"], ["xinetd"],
    ),
    ServiceEntry(
        "legacy-inetutils", "Legacy plaintext network services (telnet/rsh/talk)",
        "inetutils bundles the telnet/rsh/talk *client* binaries together with their matching plaintext listening "
        "sockets in one package - installed-but-inactive just means the old client tools are present (fine); "
        "active means this machine is actually listening for inbound telnet/rsh/talk connections (CIS-flagged, "
        "all three predate any transport encryption).",
        ["inetutils"], ["telnet.socket", "rsh.socket", "talk.socket"],
    ),
]

_CATALOG_BY_KEY = {e.key: e for e in CATALOG}


@dataclass
class ServiceFinding:
    key: str
    title: str
    status: str  # "pass" (not installed) | "warn" (installed, inactive) | "fail" (installed and active)
    detail: str


def _is_package_installed(package: str) -> bool:
    return run_unprivileged(["pacman", "-Q", package]).ok


def _is_any_unit_active(units: list[str]) -> bool:
    for unit in units:
        if run_unprivileged(["systemctl", "is-active", unit]).stdout.strip() == "active":
            return True
    return False


def scan_entry(entry: ServiceEntry) -> ServiceFinding:
    installed_pkgs = [p for p in entry.packages if _is_package_installed(p)]
    if not installed_pkgs:
        return ServiceFinding(entry.key, entry.title, "pass", "Not installed")

    if entry.units and _is_any_unit_active(entry.units):
        return ServiceFinding(
            entry.key, entry.title, "fail",
            f"Installed ({', '.join(installed_pkgs)}) and active - a listening service is actually exposed",
        )

    if entry.units:
        return ServiceFinding(
            entry.key, entry.title, "warn",
            f"Installed ({', '.join(installed_pkgs)}) but not active - present, not currently exposed",
        )

    return ServiceFinding(entry.key, entry.title, "warn", f"Installed ({', '.join(installed_pkgs)})")


def scan_all() -> list[ServiceFinding]:
    return [scan_entry(entry) for entry in CATALOG]
