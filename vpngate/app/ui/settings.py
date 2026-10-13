"""Settings window (port of SettingsView.swift): General, Proxy, Routing, Advanced tabs —
icon switcher on top, macOS-style grouped sections (rounded gray boxes with rows)."""

from __future__ import annotations

import gi
gi.require_version("Gtk", "3.0")
from gi.repository import GLib, Gtk  # noqa: E402

from ..keyring import get as keyring_get, set as keyring_set
from ..statistics import VGStatistics
from .routing import RoutingRulesEditor


def group(title: str | None = None) -> tuple[Gtk.Box, Gtk.ListBox]:
    """A macOS-style group: bold section header + rounded gray box with a row list."""
    box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
    if title:
        head = Gtk.Label(xalign=0)
        head.set_markup(f"<b>{title}</b>")
        box.pack_start(head, False, False, 0)
    frame = Gtk.Frame()
    frame.get_style_context().add_class("vg-group")
    frame.set_shadow_type(Gtk.ShadowType.NONE)
    rows = Gtk.ListBox()
    rows.set_selection_mode(Gtk.SelectionMode.NONE)
    rows.set_activate_on_single_click(False)
    frame.add(rows)
    box.pack_start(frame, False, False, 0)
    return box, rows


def list_row(label: str | None = None, wrap_text: str | None = None) -> Gtk.ListBoxRow:
    row = Gtk.ListBoxRow()
    row.set_activatable(False)
    row.set_selectable(False)
    if label is not None:
        lab = Gtk.Label(label=label, xalign=0)
        lab.set_margin_start(10)
        lab.set_margin_end(10)
        lab.set_margin_top(8)
        lab.set_margin_bottom(8)
        row.add(lab)
    if wrap_text is not None:
        lab = Gtk.Label(xalign=0)
        lab.set_line_wrap(True)
        lab.set_max_width_chars(70)
        lab.get_style_context().add_class("dim-label")
        lab.set_markup(f"<small>{wrap_text}</small>")
        lab.set_margin_start(10)
        lab.set_margin_end(10)
        lab.set_margin_top(4)
        lab.set_margin_bottom(8)
        row.add(lab)
    return row


def two_sided(left: str, right: Gtk.Widget) -> Gtk.ListBoxRow:
    row = Gtk.ListBoxRow()
    row.set_activatable(False)
    row.set_selectable(False)
    box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
    lab = Gtk.Label(label=left, xalign=0)
    lab.set_hexpand(True)
    lab.set_valign(Gtk.Align.CENTER)
    box.pack_start(lab, True, True, 0)
    right.set_valign(Gtk.Align.CENTER)
    box.pack_end(right, False, False, 0)
    box.set_margin_start(10)
    box.set_margin_end(10)
    box.set_margin_top(6)
    box.set_margin_bottom(6)
    row.add(box)
    return row


def note_row(text: str) -> Gtk.ListBoxRow:
    row = Gtk.ListBoxRow()
    row.set_activatable(False)
    row.set_selectable(False)
    lab = Gtk.Label(xalign=0)
    lab.set_line_wrap(True)
    lab.set_max_width_chars(72)
    lab.get_style_context().add_class("dim-label")
    lab.set_markup(f"<small>{text}</small>")
    lab.set_margin_start(10)
    lab.set_margin_end(10)
    lab.set_margin_top(6)
    lab.set_margin_bottom(8)
    row.add(lab)
    return row


class SettingsWindow(Gtk.ApplicationWindow):
    def __init__(self, app, model, **kwargs):
        super().__init__(application=app, title="Settings", **kwargs)
        self.app = app
        self.model = model
        self.set_default_size(600, 560)

        outer = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
        outer.set_margin_top(10)
        self.add(outer)

        stack = Gtk.Stack()
        stack.set_transition_type(Gtk.StackTransitionType.NONE)
        switcher = Gtk.StackSwitcher()
        switcher.set_stack(stack)
        switcher.set_halign(Gtk.Align.CENTER)
        outer.pack_start(switcher, False, False, 0)
        outer.pack_start(stack, True, True, 0)

        for name, icon, builder in (
                ("General", "applications-system-symbolic", self._general_tab),
                ("Proxy", "applications-internet-symbolic", self._proxy_tab),
                ("Routing", "media-playlist-shuffle-symbolic", self._routing_tab),
                ("Advanced", "applications-engineering-symbolic", self._advanced_tab)):
            child = builder()
            stack.add_titled(child, name.lower(), name)
            stack.child_set(child, icon_name=icon)
        stack.connect("notify::visible-child-name",
                      lambda st, _p: self.set_title(st.get_visible_child_name().title()))

    @staticmethod
    def _scrolled(child: Gtk.Widget) -> Gtk.Widget:
        scroller = Gtk.ScrolledWindow()
        scroller.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
        scroller.add(child)
        return scroller

    # MARK: General

    def _general_tab(self) -> Gtk.Widget:
        outer = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=14)
        outer.set_margin_start(16)
        outer.set_margin_end(16)
        outer.set_margin_top(6)
        outer.set_margin_bottom(14)
        prefs = self.model.prefs

        connection, rows = group("Connection")
        launch = Gtk.Switch()
        launch.set_active(bool(prefs.get("launchAtLogin")))
        launch.connect("notify::active", self._on_launch_toggled)
        rows.add(two_sided("Launch at login", launch))
        reconnect = Gtk.Switch()
        reconnect.set_active(bool(prefs.get("autoReconnect", True)))
        reconnect.connect("notify::active", lambda s, _p: prefs.set("autoReconnect", s.get_active()))
        rows.add(two_sided("Reconnect automatically", reconnect))
        block6 = Gtk.Switch()
        block6.set_active(bool(prefs.get("blockIPv6", True)))
        block6.connect("notify::active", lambda s, _p: prefs.set("blockIPv6", s.get_active()))
        rows.add(two_sided("Block IPv6 while connected", block6))
        rows.add(note_row("On: IPv6 is captured and dropped, which prevents IPv6 leaks; "
                          "dual-stack sites fall back to IPv4 through the VPN."))
        outer.pack_start(connection, False, False, 0)

        mode, mrows = group("Mode")
        mode_combo = Gtk.ComboBoxText()
        mode_combo.append("full", "Full tunnel (whole computer)")
        mode_combo.set_active_id("full")
        mrows.add(two_sided("Use the VPN as", mode_combo))
        mrows.add(note_row("All traffic from this computer goes through the VPN (subject to "
                           "your routing rules)."))
        outer.pack_start(mode, False, False, 0)

        connections, crows = group("VPN connections")
        open_btn = Gtk.Button(label="Open VPN Connection Settings…")
        open_btn.set_halign(Gtk.Align.START)
        open_btn.set_margin_start(10)
        open_btn.set_margin_top(6)
        open_btn.set_margin_bottom(6)
        open_btn.connect("clicked", lambda _b: self.app.open_accounts())
        crows.add(open_btn)
        crows.add(note_row("Manage your own SoftEther servers and accounts in a separate window."))
        outer.pack_start(connections, False, False, 0)

        component, vrows = group("VPN component")
        status = "Running" if self.model.helper_is_running else (
            "Installed, not running" if self.model.helper_is_installed else "Not installed")
        status_label = Gtk.Label(label=status, xalign=0)
        status_label.get_style_context().add_class("dim-label")
        vrows.add(two_sided("Status", status_label))
        buttons = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        buttons.set_margin_start(10)
        buttons.set_margin_bottom(6)
        reinstall = Gtk.Button(label="Reinstall…" if self.model.helper_is_installed else "Install…")
        reinstall.connect("clicked", lambda _b: self.model.begin_setup())
        uninstall = Gtk.Button(label="Uninstall…")
        uninstall.set_sensitive(self.model.helper_is_installed)
        uninstall.connect("clicked", lambda _b: self.model.uninstall_helper())
        buttons.pack_start(reinstall, False, False, 0)
        buttons.pack_start(uninstall, False, False, 0)
        vrows.add(buttons)
        vrows.add(note_row("It runs as root to create the VPN interface, routes and DNS. "
                           "The installer asks for your password once."))
        outer.pack_start(component, False, False, 0)
        return self._scrolled(outer)

    def _on_launch_toggled(self, switch, _param) -> None:
        from ..helperinstaller import register_login_item, unregister_login_item
        prefs = self.model.prefs
        if switch.get_active():
            try:
                register_login_item("vpngate")
                prefs.set("launchAtLogin", True)
            except OSError as e:
                switch.set_active(False)
                self.model.notice = f"Launch at login could not be enabled: {e}"
                self.model.append_log(str(e))
        else:
            try:
                unregister_login_item()
                prefs.set("launchAtLogin", False)
            except OSError as e:
                switch.set_active(True)
                self.model.notice = f"Launch at login could not be disabled: {e}"

    # MARK: Proxy

    def _proxy_tab(self) -> Gtk.Widget:
        outer = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=14)
        outer.set_margin_start(16)
        outer.set_margin_end(16)
        outer.set_margin_top(6)
        outer.set_margin_bottom(14)
        prefs = self.model.prefs

        proxy_box, rows = group("Proxy")
        kind = Gtk.ComboBoxText()
        kind.append("none", "No proxy (direct)")
        kind.append("http", "HTTP proxy (CONNECT)")
        kind.append("socks5", "SOCKS5 proxy")
        kind.set_active_id(prefs.get("proxyKind", "none"))
        rows.add(two_sided("Connect through", kind))
        row = Gtk.ListBoxRow()
        row.set_activatable(False)
        row.set_selectable(False)
        fields = Gtk.Grid(column_spacing=10, row_spacing=8)
        fields.set_margin_start(10)
        fields.set_margin_end(10)
        fields.set_margin_top(4)
        fields.set_margin_bottom(8)
        host_entry = Gtk.Entry()
        host_entry.set_text(prefs.get("proxyHost", ""))
        host_entry.set_placeholder_text("Proxy host")
        host_entry.set_hexpand(True)
        port_entry = Gtk.Entry()
        port_entry.set_text(str(prefs.get("proxyPort", 0) or ""))
        port_entry.set_placeholder_text("Port")
        port_entry.set_width_chars(8)
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
        fields.attach(host_entry, 0, 0, 1, 1)
        fields.attach(port_entry, 1, 0, 1, 1)
        fields.attach(user_entry, 0, 1, 1, 1)
        fields.attach(pass_entry, 1, 1, 1, 1)
        row.add(fields)
        rows.add(row)

        def on_kind(c):
            prefs.set("proxyKind", c.get_active_id() or "none")
            fields.set_sensitive((c.get_active_id() or "none") != "none")
        kind.connect("changed", on_kind)
        fields.set_sensitive((kind.get_active_id() or "none") != "none")

        rows.add(note_row("If you are using a proxy server, you might not be able to use VPN "
                          "Relay Servers which don't support the TCP port 443 as “SSL-VPN "
                          "Connection” from such a proxy-mandated network."))
        outer.pack_start(proxy_box, False, False, 0)
        return self._scrolled(outer)

    # MARK: Routing

    def _routing_tab(self) -> Gtk.Widget:
        outer = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
        outer.set_margin_start(16)
        outer.set_margin_end(16)
        outer.set_margin_top(6)
        outer.set_margin_bottom(14)
        editor = RoutingRulesEditor(self.model.routing_config, self._routing_changed, self)
        outer.pack_start(editor, False, False, 0)
        return self._scrolled(outer)

    def _routing_changed(self, config) -> None:
        self.model.set_routing_config(config)

    # MARK: Advanced

    def _advanced_tab(self) -> Gtk.Widget:
        scroller = Gtk.ScrolledWindow()
        scroller.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
        outer = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=14)
        outer.set_margin_start(16)
        outer.set_margin_end(16)
        outer.set_margin_top(6)
        outer.set_margin_bottom(14)
        scroller.add(outer)
        prefs = self.model.prefs

        server_list, srows = group("Server list")
        mirror_row = Gtk.ListBoxRow()
        mirror_row.set_activatable(False)
        mirror_entry = Gtk.Entry()
        mirror_entry.set_text(prefs.get("mirrorURL", ""))
        mirror_entry.set_placeholder_text("Mirror URL (optional)")
        mirror_entry.set_hexpand(True)
        mirror_entry.set_margin_start(10)
        mirror_entry.set_margin_end(10)
        mirror_entry.set_margin_top(8)
        mirror_entry.set_margin_bottom(8)
        mirror_entry.connect("changed", lambda e: prefs.set("mirrorURL", e.get_text().strip()))
        mirror_row.add(mirror_entry)
        srows.add(mirror_row)
        srows.add(note_row("Used first when set, e.g. if vpngate.net is blocked."))
        outer.pack_start(server_list, False, False, 0)

        diag, drows = group("Diagnostics (this computer app only, opt-in)")
        stats = self.model.statistics
        telemetry = Gtk.Switch()
        telemetry.set_active(stats.is_enabled)
        telemetry.connect("notify::active", lambda s, _p: stats.set_enabled(s.get_active()))
        drows.add(two_sided("Send anonymous diagnostics every 10 minutes", telemetry))

        expander = Gtk.Expander(label="Exactly what is sent")
        expander.set_margin_start(10)
        expander.set_margin_end(10)
        expander.set_margin_bottom(6)
        expander.set_expanded(True)
        payload = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
        pl = Gtk.Label(xalign=0)
        payload_text = GLib.markup_escape_text("\n".join(VGStatistics.payload_description()))
        pl.set_markup("<tt>" + payload_text + "</tt>")
        pl.set_selectable(True)
        payload.pack_start(pl, False, False, 0)
        hk = Gtk.Label(xalign=0)
        hk.set_line_wrap(True)
        hk.get_style_context().add_class("dim-label")
        hk.set_markup("<small>HostKey is a random ID created on this computer (not derived "
                      "from its name).</small>")
        payload.pack_start(hk, False, False, 0)
        reset_btn = Gtk.Button(label="Reset ID")
        reset_btn.set_halign(Gtk.Align.CENTER)
        reset_btn.connect("clicked", lambda _b: stats.reset_host_key())
        payload.pack_start(reset_btn, False, False, 0)
        expander.add(payload)
        drows.add(expander)
        drows.add(note_row("Off by default. The Windows client does not send this for ordinary "
                           "users; it is specific to this app. No traffic, addresses or personal "
                           "data are included."))
        outer.pack_start(diag, False, False, 0)

        gate, grows = group("VPN Gate connections")
        spin = Gtk.SpinButton.new_with_range(1, 32, 1)
        try:
            spin.set_value(max(1, min(int(prefs.get("vgateMaxConnections", 1) or 1), 32)))
        except (TypeError, ValueError):
            spin.set_value(1)
        spin.connect("value-changed", lambda w: prefs.set("vgateMaxConnections",
                                                          int(w.get_value())))
        grows.add(two_sided("TCP connections per VPN Gate connection", spin))
        grows.add(note_row("The real client uses 1. Raise to 3–4 when a relay starts throttling "
                           "your single TLS flow after a while (parallel flows defeat "
                           "per-connection throttling). The relay still caps it in its welcome."))
        outer.pack_start(gate, False, False, 0)

        logbox, lrows = group("Log")
        log_btn = Gtk.Button(label="Show Log…")
        log_btn.set_halign(Gtk.Align.START)
        log_btn.set_margin_start(10)
        log_btn.set_margin_top(6)
        log_btn.set_margin_bottom(6)
        log_btn.connect("clicked", lambda _b: self.app.open_log())
        lrows.add(log_btn)
        outer.pack_start(logbox, False, False, 0)
        return scroller


