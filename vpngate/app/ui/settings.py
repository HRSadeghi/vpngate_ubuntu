"""Settings window (port of SettingsView.swift): General, Proxy, Routing, Advanced tabs."""

from __future__ import annotations

import gi
gi.require_version("Gtk", "3.0")
from gi.repository import Gtk  # noqa: E402

from ..keyring import get as keyring_get, set as keyring_set
from ..statistics import VGStatistics
from .routing import RoutingRulesEditor


class SettingsWindow(Gtk.ApplicationWindow):
    def __init__(self, app, model, **kwargs):
        super().__init__(application=app, title="Settings", **kwargs)
        self.app = app
        self.model = model
        self.set_default_size(600, 500)

        notebook = Gtk.Notebook()
        notebook.append_page(self._general_tab(), Gtk.Label(label="General"))
        notebook.append_page(self._proxy_tab(), Gtk.Label(label="Proxy"))
        notebook.append_page(self._routing_tab(), Gtk.Label(label="Routing"))
        notebook.append_page(self._advanced_tab(), Gtk.Label(label="Advanced"))
        self.add(notebook)

    @staticmethod
    def _form() -> tuple[Gtk.Box, Gtk.Grid]:
        grid = Gtk.Grid(column_spacing=12, row_spacing=10, margin_start=16, margin_end=16,
                        margin_top=14, margin_bottom=14)
        scrolled = Gtk.ScrolledWindow()
        scrolled.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
        scrolled.add(grid)
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        box.add(scrolled)
        return box, grid

    def _section(self, grid, row: int, title: str) -> int:
        head = Gtk.Label(xalign=0)
        head.set_markup(f"<b>{title}</b>")
        grid.attach(head, 0, row, 2, 1)
        return row + 1

    @staticmethod
    def _note(grid, row, text):
        note = Gtk.Label(xalign=0)
        note.set_line_wrap(True)
        note.get_style_context().add_class("dim-label")
        note.set_markup(f"<small>{text}</small>")
        grid.attach(note, 0, row, 2, 1)
        return row + 1

    # MARK: General

    def _general_tab(self) -> Gtk.Widget:
        box, grid = self._form()
        prefs = self.model.prefs
        row = self._section(grid, 0, "Connection")

        launch = Gtk.CheckButton(label="Launch at login")
        launch.set_active(bool(prefs.get("launchAtLogin")))
        launch.connect("toggled", self._on_launch_toggled)
        grid.attach(launch, 0, row, 2, 1)
        row += 1

        reconnect = Gtk.CheckButton(label="Reconnect automatically")
        reconnect.set_active(bool(prefs.get("autoReconnect", True)))
        reconnect.connect("toggled", lambda c: prefs.set("autoReconnect", c.get_active()))
        grid.attach(reconnect, 0, row, 2, 1)
        row += 1

        block6 = Gtk.CheckButton(label="Block IPv6 while connected")
        block6.set_active(bool(prefs.get("blockIPv6", True)))
        block6.connect("toggled", lambda c: prefs.set("blockIPv6", c.get_active()))
        grid.attach(block6, 0, row, 2, 1)
        row += 1
        row = self._note(grid, row, "On: IPv6 is captured and dropped, which prevents IPv6 leaks; "
                                    "dual-stack sites fall back to IPv4 through the VPN. Off: IPv6 "
                                    "only works if the VPN network provides it. Otherwise IPv6 is "
                                    "still captured and dropped, so nothing leaks.")

        row = self._section(grid, row, "VPN connections")
        open_btn = Gtk.Button(label="Open VPN Connection Settings…")
        open_btn.connect("clicked", lambda _b: self.app.open_accounts())
        grid.attach(open_btn, 0, row, 2, 1)
        row += 1
        row = self._note(grid, row, "Manage your own SoftEther servers and accounts in a separate "
                                    "window.")

        row = self._section(grid, row, "VPN component")
        status = "Running" if self.model.helper_is_running else (
            "Installed, not running" if self.model.helper_is_installed else "Not installed")
        status_label = Gtk.Label(xalign=0)
        status_label.set_text(f"Status: {status}")
        grid.attach(status_label, 0, row, 2, 1)
        row += 1
        buttons = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        reinstall = Gtk.Button(label="Install…" if not self.model.helper_is_installed else "Reinstall…")
        reinstall.connect("clicked", lambda _b: self.model.begin_setup())
        uninstall = Gtk.Button(label="Uninstall…")
        uninstall.set_sensitive(self.model.helper_is_installed)
        uninstall.connect("clicked", lambda _b: self.model.uninstall_helper())
        buttons.pack_start(reinstall, False, False, 0)
        buttons.pack_start(uninstall, False, False, 0)
        grid.attach(buttons, 0, row, 2, 1)
        row += 1
        row = self._note(grid, row, "It runs as root to create the VPN interface, routes and DNS. "
                                    "The installer asks for your password once.")
        return box

    def _on_launch_toggled(self, check) -> None:
        from ..helperinstaller import register_login_item, unregister_login_item
        prefs = self.model.prefs
        if check.get_active():
            try:
                register_login_item("vpngate")
                prefs.set("launchAtLogin", True)
            except OSError as e:
                check.set_active(False)
                self.model.notice = f"Launch at login could not be enabled: {e}"
                self.model.append_log(str(e))
        else:
            try:
                unregister_login_item()
                prefs.set("launchAtLogin", False)
            except OSError as e:
                check.set_active(True)
                self.model.notice = f"Launch at login could not be disabled: {e}"

    # MARK: Proxy

    def _proxy_tab(self) -> Gtk.Widget:
        box, grid = self._form()
        prefs = self.model.prefs
        row = self._section(grid, 0, "Proxy")
        grid.attach(Gtk.Label(label="Connect through", xalign=0), 0, row, 1, 1)
        kind = Gtk.ComboBoxText()
        kind.append("none", "No proxy (direct)")
        kind.append("http", "HTTP proxy (CONNECT)")
        kind.append("socks5", "SOCKS5 proxy")
        kind.set_active_id(prefs.get("proxyKind", "none"))
        grid.attach(kind, 1, row, 1, 1)
        row += 1

        self.proxy_fields = Gtk.Grid(column_spacing=10, row_spacing=8)
        host_entry = Gtk.Entry()
        host_entry.set_text(prefs.get("proxyHost", ""))
        host_entry.set_placeholder_text("Proxy host")
        port_entry = Gtk.Entry()
        port_entry.set_text(str(prefs.get("proxyPort", 0) or ""))
        port_entry.set_placeholder_text("Port")
        user_entry = Gtk.Entry()
        user_entry.set_text(prefs.get("proxyUsername", ""))
        user_entry.set_placeholder_text("Username (optional)")
        pass_entry = Gtk.Entry()
        pass_entry.set_visibility(False)
        pass_entry.set_text(keyring_get("proxy") or "")
        pass_entry.set_placeholder_text("Password")

        def save(*_a):
            prefs.set("proxyHost", host_entry.get_text().strip())
            try:
                prefs.set("proxyPort", int(port_entry.get_text().strip() or "0"))
            except ValueError:
                prefs.set("proxyPort", 0)
            prefs.set("proxyUsername", user_entry.get_text())
            keyring_set("proxy", pass_entry.get_text())
        for _w in (host_entry, port_entry, user_entry, pass_entry):
            _w.connect("changed", save)

        self.proxy_fields.attach(host_entry, 0, 0, 1, 1)
        self.proxy_fields.attach(port_entry, 1, 0, 1, 1)
        self.proxy_fields.attach(user_entry, 0, 1, 1, 1)
        self.proxy_fields.attach(pass_entry, 1, 1, 1, 1)
        grid.attach(self.proxy_fields, 0, row, 2, 1)
        row += 1

        def on_kind(c):
            prefs.set("proxyKind", c.get_active_id() or "none")
            self.proxy_fields.set_sensitive((c.get_active_id() or "none") != "none")
        kind.connect("changed", on_kind)
        self.proxy_fields.set_sensitive((kind.get_active_id() or "none") != "none")

        row = self._note(grid, row, "If you are using a proxy server, you might not be able to "
                                    "use VPN Relay Servers which don't support the TCP port 443 "
                                    "as “SSL-VPN Connection” from such a proxy-mandated network.")
        return box

    # MARK: Routing

    def _routing_tab(self) -> Gtk.Widget:
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        box.set_margin_start(16)
        box.set_margin_end(16)
        box.set_margin_top(14)
        box.set_margin_bottom(14)
        editor = RoutingRulesEditor(self.model.routing_config, self._routing_changed, self)
        box.pack_start(editor, True, True, 0)
        return box

    def _routing_changed(self, config) -> None:
        self.model.set_routing_config(config)

    # MARK: Advanced

    def _advanced_tab(self) -> Gtk.Widget:
        box, grid = self._form()
        prefs = self.model.prefs
        row = self._section(grid, 0, "Server list")
        mirror_entry = Gtk.Entry()
        mirror_entry.set_text(prefs.get("mirrorURL", ""))
        mirror_entry.set_placeholder_text("Mirror URL (optional)")
        mirror_entry.connect("changed", lambda e: prefs.set("mirrorURL", e.get_text().strip()))
        grid.attach(mirror_entry, 0, row, 2, 1)
        row += 1
        row = self._note(grid, row, "Used first when set, e.g. if vpngate.net is blocked.")

        row = self._section(grid, row, "Diagnostics (opt-in)")
        stats = self.model.statistics
        telemetry = Gtk.CheckButton(label="Send anonymous diagnostics every 10 minutes")
        telemetry.set_active(stats.is_enabled)
        telemetry.connect("toggled", lambda c: stats.set_enabled(c.get_active()))
        grid.attach(telemetry, 0, row, 2, 1)
        row += 1
        payload = Gtk.Label(xalign=0)
        payload.set_line_wrap(True)
        payload.set_markup(
            "<small><tt>" + "\n".join(VGStatistics.payload_description()).replace("\n", "\n")
            + "</tt></small>")
        grid.attach(payload, 0, row, 2, 1)
        row += 1
        reset_btn = Gtk.Button(label="Reset ID")
        reset_btn.connect("clicked", lambda _b: stats.reset_host_key())
        grid.attach(reset_btn, 0, row, 1, 1)
        row += 1
        row = self._note(grid, row, "Off by default. The Windows client does not send this for "
                                    "ordinary users; it is specific to this app. No traffic, "
                                    "addresses or personal data are included. HostKey is a random "
                                    "ID (not derived from the machine name).")

        row = self._section(grid, row, "VPN Gate connections")
        row_h = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        row_h.pack_start(Gtk.Label(label="TCP connections per VPN Gate connection:", xalign=0),
                         False, False, 0)
        max_conn = Gtk.SpinButton.new_with_range(1, 32, 1)
        try:
            max_conn.set_value(max(1, min(int(prefs.get("vgateMaxConnections", 1) or 1), 32)))
        except (TypeError, ValueError):
            max_conn.set_value(1)
        max_conn.connect("value-changed", lambda w: prefs.set("vgateMaxConnections", int(w.get_value())))
        row_h.pack_start(max_conn, False, False, 0)
        grid.attach(row_h, 0, row, 2, 1)
        row += 1
        row = self._note(grid, row, "The real client uses 1. Raise to 3–4 when a relay starts "
                                    "throttling your single TLS flow after a while (parallel "
                                    "flows defeat per-connection throttling). The relay still "
                                    "caps it in its welcome packet.")

        row = self._section(grid, row, "Log")
        log_btn = Gtk.Button(label="Show Log…")
        log_btn.connect("clicked", lambda _b: self.app.open_log())
        grid.attach(log_btn, 0, row, 2, 1)
        return box