"""System tray icon (port of the MenuBarExtra) via AppIndicator / AyatanaAppIndicator."""

from __future__ import annotations

import os

import gi
from gi.repository import GLib, Gtk  # noqa: E402

try:
    gi.require_version("AyatanaAppIndicator3", "0.1")
    from gi.repository import AyatanaAppIndicator3 as _AppIndicator  # type: ignore
except (ValueError, ImportError):
    try:
        gi.require_version("AppIndicator3", "0.1")
        from gi.repository import AppIndicator3 as _AppIndicator  # type: ignore
    except (ValueError, ImportError):
        _AppIndicator = None

from ...core.ipcmessages import ConnectionState
from ..formatting import bytes_fmt, state_title

ICONS = {
    ConnectionState.connected: "security-high",
    ConnectionState.disconnected: "security-low",
}
BUSY_ICON = "security-medium"


class TrayIcon:
    def __init__(self, app, model) -> None:
        self.app = app
        self.model = model
        self.indicator = None
        if _AppIndicator is None:
            return
        icon_name = self._icon_path() or "network-vpn"
        self.indicator = _AppIndicator.Indicator.new(
            "vpngate", icon_name, _AppIndicator.IndicatorCategory.APPLICATION_STATUS)
        self.indicator.set_status(_AppIndicator.IndicatorStatus.ACTIVE)
        # One menu for the lifetime of the indicator (it keeps the reference): swapping in
        # a fresh Gtk.Menu every second used to churn widgets faster than GTK could
        # finalize them (gtk_widget_get_scale_factor criticals) and wasted CPU.
        self.menu = Gtk.Menu()
        self.indicator.set_menu(self.menu)
        self._last_sig: tuple | None = None
        self._bytes_item: Gtk.MenuItem | None = None
        self._icon_applied: tuple | None = None
        self._rebuild()
        model.changed.connect(lambda: GLib.idle_add(self._refresh))

    @staticmethod
    def _icon_path() -> str | None:
        here = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(
            os.path.abspath(__file__)))))
        for p in (os.path.join(here, "assets", "AppIcon-256.png"),
                  "/usr/local/share/vpngate/AppIcon-256.png",
                  "/usr/share/icons/vpngate/AppIcon-256.png"):
            if os.path.exists(p):
                return p
        return None

    def _signature(self) -> tuple:
        """What the menu's structure depends on — everything except the ticking byte
        counters, which are updated in place."""
        m = self.model
        return (m.event.state, m.event.server, m.event.virtualIP,
                m.last_server.id if m.last_server is not None else None,
                tuple(sorted(m.favorites)))

    def _refresh(self) -> bool:
        if self.indicator is None:
            return False
        sig = self._signature()
        if sig != self._last_sig:
            self._rebuild()
        elif self._bytes_item is not None and self.model.event.state == ConnectionState.connected:
            e = self.model.event
            self._bytes_item.set_label(
                f"↓ {bytes_fmt(e.bytesIn)}  ↑ {bytes_fmt(e.bytesOut)}")
        return False

    def _rebuild(self) -> bool:
        if self.indicator is None:
            return False
        m = self.model
        state = m.event.state
        self._last_sig = self._signature()
        self._bytes_item = None
        # Clear the existing menu in place: the indicator keeps the same reference.
        for child in self.menu.get_children():
            self.menu.remove(child)
            child.destroy()
        status = Gtk.MenuItem(label=state_title(state))
        status.set_sensitive(False)
        self.menu.append(status)
        if m.event.server:
            server = m.connected_server
            label = f"{server.flag} {server.hostName} ({m.event.server})" if server else m.event.server
            item = Gtk.MenuItem(label=label)
            item.set_sensitive(False)
            self.menu.append(item)
        if m.event.virtualIP:
            item = Gtk.MenuItem(label=f"Virtual IP {m.event.virtualIP}")
            item.set_sensitive(False)
            self.menu.append(item)
        if state == ConnectionState.connected:
            item = Gtk.MenuItem(label=f"↓ {bytes_fmt(m.event.bytesIn)}  ↑ {bytes_fmt(m.event.bytesOut)}")
            item.set_sensitive(False)
            self.menu.append(item)
            self._bytes_item = item
        self.menu.append(Gtk.SeparatorMenuItem())
        if state == ConnectionState.disconnected:
            last = m.last_server or next(
                (s for s in m.servers if s.id in m.favorites), None)
            if last is not None:
                connect = Gtk.MenuItem(label=f"Connect to {last.hostName}")

                def do_connect(_i, s=last):
                    m.connect(s)
                    if m.showing_disclaimer:
                        self.app.open_main()
                connect.connect("activate", do_connect)
                self.menu.append(connect)
        else:
            disconnect = Gtk.MenuItem(label="Disconnect")
            disconnect.connect("activate", lambda _i: m.disconnect())
            self.menu.append(disconnect)
            if m.last_server is not None:
                reconnect = Gtk.MenuItem(label="Reconnect")
                reconnect.connect("activate", lambda _i: m.reconnect())
                self.menu.append(reconnect)
        show = Gtk.MenuItem(label="Show VPN Gate")
        show.connect("activate", lambda _i: self.app.open_main())
        self.menu.append(show)
        accounts = Gtk.MenuItem(label="VPN Connection Settings…")
        accounts.connect("activate", lambda _i: self.app.open_accounts())
        self.menu.append(accounts)
        settings = Gtk.MenuItem(label="Settings…")
        settings.connect("activate", lambda _i: self.app.open_settings())
        self.menu.append(settings)
        self.menu.append(Gtk.SeparatorMenuItem())
        quit_item = Gtk.MenuItem(label="Quit")
        quit_item.connect("activate", lambda _i: self.app.quit())
        self.menu.append(quit_item)
        self.menu.show_all()
        if _AppIndicator is not None:
            name = ICONS.get(state, BUSY_ICON)
            if state not in (ConnectionState.connected, ConnectionState.disconnected):
                name = BUSY_ICON
            path = self._icon_path()
            icon_key = (path if (path and state == ConnectionState.connected) else name,)
            if icon_key != self._icon_applied:
                self._icon_applied = icon_key
                if path and state == ConnectionState.connected:
                    self.indicator.set_icon_full(path, "VPN Gate")
                else:
                    self.indicator.set_icon(name)
        return False
