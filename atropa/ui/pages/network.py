"""atropa.ui.pages.network - Network module (NetworkManager)."""

from __future__ import annotations

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")

from gi.repository import Adw, Gtk  # noqa: E402

from atropa.backend import network
from atropa.ui.pages import BasePage, esc


class NetworkPage(BasePage):
    def __init__(self) -> None:
        super().__init__()

        self.status_group = self.add_group("Status")
        self.status_row = Adw.ActionRow(title="Detecting network backend…")
        self.status_group.add(self.status_row)

        devices_group = self.add_group("Devices")
        self.devices_group = devices_group

        wifi_group = self.add_group("Wi-Fi Networks")
        rescan_btn = Gtk.Button(label="Scan", valign=Gtk.Align.CENTER)
        rescan_btn.connect("clicked", lambda _b: self._load_wifi(rescan=True))
        wifi_header_row = Adw.ActionRow(title="Available networks")
        wifi_header_row.add_suffix(rescan_btn)
        wifi_group.add(wifi_header_row)
        self.wifi_group = wifi_group

        static_group = self.add_group(
            "Static IP", "Set a fixed IP for a connection instead of DHCP"
        )
        self.conn_name_row = Adw.EntryRow(title="Connection name (e.g. 'Wired connection 1')")
        static_group.add(self.conn_name_row)
        self.ip_row = Adw.EntryRow(title="IP address / CIDR (e.g. 192.168.1.50/24)")
        static_group.add(self.ip_row)
        self.gateway_row = Adw.EntryRow(title="Gateway")
        static_group.add(self.gateway_row)
        self.dns_row = Adw.EntryRow(title="DNS servers, comma separated")
        static_group.add(self.dns_row)

        apply_btn = Gtk.Button(label="Apply static IP")
        apply_btn.add_css_class("suggested-action")
        apply_btn.set_margin_top(8)
        apply_btn.connect("clicked", self._on_apply_static)
        dhcp_btn = Gtk.Button(label="Use DHCP instead")
        dhcp_btn.set_margin_top(8)
        dhcp_btn.connect("clicked", self._on_use_dhcp)

        btn_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        btn_row.append(apply_btn)
        btn_row.append(dhcp_btn)
        static_group.add(btn_row)

        self.refresh()

    def refresh(self) -> None:
        self.run_async(network.backend_available, self._on_backend_loaded)
        self.clear_rows(self.devices_group, getattr(self, "_device_rows", []))
        self._device_rows = [self.start_loading(self.devices_group, "Loading devices…")]
        self.run_async(network.list_devices, self._on_devices_loaded)
        self._load_wifi(rescan=False)

    def _on_backend_loaded(self, result, error) -> bool:
        if error:
            self.status_row.set_title("Could not detect network backend")
            self.status_row.set_subtitle(esc(error))
        else:
            labels = {
                "networkmanager": "NetworkManager is active",
                "networkd": "systemd-networkd is active",
                "none": "No active network backend detected",
            }
            self.status_row.set_title(labels.get(result, esc(result)))
        return False

    def _on_devices_loaded(self, result, error) -> bool:
        for row in list(getattr(self, "_device_rows", [])):
            self.devices_group.remove(row)
        self._device_rows = []

        if error:
            self.notify(f"Failed to list devices: {error}", is_error=True)
            return False

        for dev in result:
            row = Adw.ActionRow(
                title=esc(dev.name),
                subtitle=esc(f"{dev.dev_type} · {dev.state} · {dev.connection or 'not connected'}"),
            )
            if dev.state == "connected":
                disc_btn = Gtk.Button(label="Disconnect", valign=Gtk.Align.CENTER)
                disc_btn.connect("clicked", self._on_disconnect, dev.name)
                row.add_suffix(disc_btn)
            self.devices_group.add(row)
            self._device_rows.append(row)
        return False

    def _load_wifi(self, rescan: bool) -> None:
        self.clear_rows(self.wifi_group, getattr(self, "_wifi_rows", []))
        self._wifi_rows = [
            self.start_loading(self.wifi_group, "Scanning for Wi-Fi networks…" if rescan else "Loading Wi-Fi networks…")
        ]
        self.run_async(lambda: network.list_wifi(rescan=rescan), self._on_wifi_loaded)

    def _on_wifi_loaded(self, result, error) -> bool:
        for row in list(getattr(self, "_wifi_rows", [])):
            self.wifi_group.remove(row)
        self._wifi_rows = []

        if error:
            self.notify(f"Wi-Fi scan failed: {error}", is_error=True)
            return False

        seen = set()
        for net in sorted(result, key=lambda n: -n.signal):
            if not net.ssid or net.ssid in seen:
                continue
            seen.add(net.ssid)
            subtitle = f"Signal {net.signal}% · {net.security}"
            row = Adw.ActionRow(title=esc(net.ssid), subtitle=esc(subtitle))
            if net.in_use:
                row.add_suffix(Gtk.Label(label="connected", css_classes=["dim-label"]))
            else:
                connect_btn = Gtk.Button(label="Connect", valign=Gtk.Align.CENTER)
                connect_btn.connect("clicked", self._on_wifi_connect, net.ssid, net.security != "Open")
                row.add_suffix(connect_btn)
            self.wifi_group.add(row)
            self._wifi_rows.append(row)
        return False

    def _on_wifi_connect(self, _btn: Gtk.Button, ssid: str, needs_password: bool) -> None:
        if not needs_password:
            self.notify(f"Connecting to {ssid}…")
            self.run_async(lambda: network.connect_wifi(ssid), self.handle_command_result)
            return

        dialog = Adw.AlertDialog(heading=f"Connect to {ssid}", body="Enter the network password")
        dialog.set_heading_use_markup(False)
        entry = Gtk.PasswordEntry()
        entry.set_show_peek_icon(True)
        dialog.set_extra_child(entry)
        dialog.add_response("cancel", "Cancel")
        dialog.add_response("connect", "Connect")
        dialog.set_response_appearance("connect", Adw.ResponseAppearance.SUGGESTED)

        def on_response(_dlg, response: str) -> None:
            if response == "connect":
                password = entry.get_text()
                self.notify(f"Connecting to {ssid}…")
                self.run_async(lambda: network.connect_wifi(ssid, password), self.handle_command_result)

        dialog.connect("response", on_response)
        dialog.present(self.get_root())

    def _on_disconnect(self, _btn: Gtk.Button, device_name: str) -> None:
        self.run_async(lambda: network.disconnect(device_name), self.handle_command_result)

    def _on_apply_static(self, _btn: Gtk.Button) -> None:
        conn = self.conn_name_row.get_text().strip()
        ip_cidr = self.ip_row.get_text().strip()
        gateway = self.gateway_row.get_text().strip()
        dns = [d.strip() for d in self.dns_row.get_text().split(",") if d.strip()]
        if not (conn and ip_cidr and gateway):
            self.notify("Connection name, IP/CIDR, and gateway are required")
            return
        self.run_async(lambda: network.set_static_ip(conn, ip_cidr, gateway, dns), self.handle_command_result)

    def _on_use_dhcp(self, _btn: Gtk.Button) -> None:
        conn = self.conn_name_row.get_text().strip()
        if not conn:
            self.notify("Enter the connection name first")
            return
        self.run_async(lambda: network.set_dhcp(conn), self.handle_command_result)
