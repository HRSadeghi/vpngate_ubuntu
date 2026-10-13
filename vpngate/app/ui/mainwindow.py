"""Server list window (port of ServerListView.swift): the Windows client's VPN Gate plug-in
layout — header, connection card, filter bar, the relay table, and the Connect button.

The table never clears its store: rows are added/updated/removed in place (cells read their
values from the store; sorting is GTK-native over hidden numeric columns), so scrolling,
selection and sort order survive every model event."""

from __future__ import annotations

import time

import gi
gi.require_version("Gtk", "3.0")
from gi.repository import Gdk, GLib, Gtk, Pango  # noqa: E402

from ...core.ipcmessages import ConnectionState
from ...core.serverfilter import ServerFilter
from ...core.serverlist import ListFormat, VPNServer
from ...core.serverprobe import ProbeOutcome
from ..formatting import bytes_fmt, duration, speed, state_title

LOG_CHOICES = [("Any logging policy", -1), ("2 weeks or less", 2), ("Up to 1 month", 5), ("No logs only", 0)]

# Store layout: display columns read straight from the store; hidden numeric columns carry the
# GTK-native sort keys. Indices below; C_* are the display columns.
(C_ID, C_IP, C_COUNTRY, C_UPTIME, C_SESSIONS, C_SPEED, C_PING, C_PROBE, C_LOGGING, C_SCORE,
 C_DDNS, C_SSL, C_UDP, C_TRAFFIC, C_USERS, C_OPERATOR, C_MESSAGE) = range(17)
(S_IP, S_COUNTRY, S_UPTIME_MS, S_SESSIONS, S_SPEED, S_PING, S_PROBE_RANK, S_TRAFFIC,
 S_USERS) = range(17, 26)
STORE_TYPES = (
    str,                                  # C_ID
    str, str,                             # C_IP, C_COUNTRY
    str, str, str, str,                   # C_UPTIME, C_SESSIONS, C_SPEED, C_PING
    str,                                  # C_PROBE
    str,                                  # C_LOGGING
    int,                                  # C_SCORE
    str, str, str,                        # C_DDNS, C_SSL, C_UDP
    str, str,                             # C_TRAFFIC, C_USERS
    str, str,                             # C_OPERATOR, C_MESSAGE
    str, str,                             # S_IP, S_COUNTRY
    int, int, int, int, int, int, int,    # S_UPTIME_MS, S_SESSIONS, S_SPEED, S_PING,
)                                         # S_PROBE_RANK, S_TRAFFIC, S_USERS

# (title, display column, sort column, default visible)
COLUMNS = [
    ("IP Address (Hostname)", C_IP, S_IP, True),
    ("Region", C_COUNTRY, S_COUNTRY, True),
    ("Uptime", C_UPTIME, S_UPTIME_MS, True),
    ("VPN Sessions", C_SESSIONS, S_SESSIONS, True),
    ("Line Speed", C_SPEED, S_SPEED, True),
    ("Ping (Google, SE)", C_PING, S_PING, True),
    ("Test from this computer", C_PROBE, S_PROBE_RANK, True),
    ("Logging Policy", C_LOGGING, C_LOGGING, True),
    ("Total Score", C_SCORE, C_SCORE, True),
    ("DDNS Hostname", C_DDNS, C_DDNS, False),
    ("SSL-VPN (TCP)", C_SSL, None, False),
    ("UDP Support", C_UDP, None, False),
    ("Cumulative Transfers", C_TRAFFIC, S_TRAFFIC, False),
    ("Cumulative Users", C_USERS, S_USERS, False),
    ("Operator's Name", C_OPERATOR, C_OPERATOR, False),
    ("Operator's Message", C_MESSAGE, None, False),
]

_I32_MAX = 2147483647


def _i32(v: int) -> int:
    """GObject int store columns are 32-bit; clamp int64 values from the .dat."""
    return max(-_I32_MAX, min(_I32_MAX, int(v)))


CARD_STYLES = {
    ConnectionState.connected: ("vg-card-green", "🔒"),
    ConnectionState.disconnected: ("vg-card-gray", "🔓"),
}


class ServerListWindow(Gtk.ApplicationWindow):
    def __init__(self, app, model, **kwargs):
        super().__init__(application=app, title="VPN Gate Public VPN Relay Servers", **kwargs)
        self.app = app
        self.model = model
        self.search = ""
        self.country = "All"
        self.favorites_only = False
        self._selected_id: str | None = None
        self._updating = False
        self._iters: dict[str, Gtk.TreeIter] = {}
        self._row_cache: dict[str, tuple] = {}
        self._countries_sig = None
        self._servers_by_id: dict[str, VPNServer] = {}

        self.set_default_size(980, 620)
        self._install_css()
        outer = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=0)
        self.add(outer)

        outer.pack_start(self._build_header(), False, False, 0)
        outer.pack_start(Gtk.Separator(), False, False, 0)
        outer.pack_start(self._build_filter_bar(), False, False, 0)
        outer.pack_start(Gtk.Separator(), False, False, 0)
        self.status_label = Gtk.Label(xalign=0)
        self.status_label.set_margin_start(16)
        self.status_label.set_margin_top(6)
        self.status_label.set_margin_bottom(6)
        outer.pack_start(self.status_label, False, False, 0)

        scrolled = Gtk.ScrolledWindow()
        scrolled.set_policy(Gtk.PolicyType.AUTOMATIC, Gtk.PolicyType.AUTOMATIC)
        scrolled.set_vexpand(True)
        outer.pack_start(scrolled, True, True, 0)
        scrolled.add(self._build_table())

        outer.pack_start(Gtk.Separator(), False, False, 0)
        outer.pack_start(self._build_button_row(), False, False, 6)
        footnote = Gtk.Label()
        footnote.set_markup(
            "<small><span foreground='gray'>Academic project at University of Tsukuba, Japan."
            "  ·  A server with a higher Line Speed and a smaller Ping is usually more "
            "comfortable to use.</span></small>")
        footnote.set_xalign(0.5)
        footnote.set_margin_bottom(6)
        outer.pack_start(footnote, False, False, 0)

        self._sync_from_model()
        self._unsubscribe = model.changed.connect(lambda: GLib.idle_add(self._sync_from_model))
        self.connect("destroy", self._on_destroy)

    def _on_destroy(self, *_a):
        self._unsubscribe()

    @staticmethod
    def _install_css() -> None:
        provider = Gtk.CssProvider()
        provider.load_from_data(b"""
            .vg-card { border-radius: 8px; padding: 10px; }
            .vg-card-green { background: rgba(46,194,126,0.14);
                             border: 1px solid rgba(46,194,126,0.45); }
            .vg-card-gray  { background: rgba(127,127,135,0.14);
                             border: 1px solid rgba(127,127,135,0.4); }
            .vg-card-orange { background: rgba(224,125,31,0.14);
                              border: 1px solid rgba(224,125,31,0.45); }
            .vg-card-title { font-weight: bold; font-size: 110%; }
            .vg-card-small { font-size: 90%; }
        """)
        screen = Gdk.Screen.get_default()
        Gtk.StyleContext.add_provider_for_screen(
            screen, provider, Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION)

    # MARK: layout pieces

    def _build_header(self) -> Gtk.Widget:
        box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=16)
        box.set_margin_start(16)
        box.set_margin_end(16)
        box.set_margin_top(12)
        box.set_margin_bottom(12)

        left = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
        title = Gtk.Label(xalign=0)
        title.set_markup("<big><b>VPN Gate Public VPN Relay Servers</b></big>")
        left.pack_start(title, False, False, 0)
        desc = Gtk.Label(xalign=0)
        desc.set_line_wrap(True)
        desc.set_max_width_chars(60)
        desc.get_style_context().add_class("dim-label")
        desc.set_text("Gain freedom access to Internet by using VPN connection via Public VPN "
                      "Servers provided by volunteers around the world. Bypass your local "
                      "malfunctioning firewall's packet blocking, and hide your IP address safely.")
        left.pack_start(desc, False, False, 0)
        box.pack_start(left, True, True, 0)

        self.card = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        # Fixed height: the card's text changes every second while connected, and a height
        # change here would re-fit the window and shift the list (the macOS card is likewise
        # a fixed-size panel).
        self.card.set_size_request(280, 104)
        self.card.get_style_context().add_class("vg-card")
        self._card_style_class = "vg-card-gray"
        self.card_icon = Gtk.Label()
        self.card_icon.set_markup('<span size="16000">🔓</span>')
        self.card_icon.set_valign(Gtk.Align.START)
        self.card.pack_start(self.card_icon, False, False, 0)
        card_text = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2)
        self.card_title = Gtk.Label(xalign=0)
        self.card_title.get_style_context().add_class("vg-card-title")
        card_text.pack_start(self.card_title, False, False, 0)
        self.card_line1 = Gtk.Label(xalign=0)
        self.card_line1.set_ellipsize(Pango.EllipsizeMode.END)
        self.card_line1.get_style_context().add_class("vg-card-small")
        card_text.pack_start(self.card_line1, False, False, 0)
        self.card_line2 = Gtk.Label(xalign=0)
        self.card_line2.get_style_context().add_class("vg-card-small")
        card_text.pack_start(self.card_line2, False, False, 0)
        self.card.pack_start(card_text, True, True, 0)
        box.pack_end(self.card, False, False, 0)
        return box

    def _build_filter_bar(self) -> Gtk.Widget:
        bar = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        bar.set_margin_start(16)
        bar.set_margin_end(16)
        bar.set_margin_top(6)
        bar.set_margin_bottom(6)

        self.search_entry = Gtk.SearchEntry()
        self.search_entry.set_placeholder_text("Search host, IP, country, operator")
        self.search_entry.set_size_request(280, -1)
        self.search_entry.connect("search-changed", self._on_search_changed)
        bar.pack_start(self.search_entry, False, False, 0)

        self.country_combo = Gtk.ComboBoxText()
        self.country_combo.connect("changed", self._on_country_changed)
        bar.pack_start(self.country_combo, False, False, 0)

        self.logging_combo = Gtk.ComboBoxText()
        for label, _weeks in LOG_CHOICES:
            self.logging_combo.append_text(label)
        self.logging_combo.set_active(0)
        self.logging_combo.connect("changed", self._on_logging_changed)
        bar.pack_start(self.logging_combo, False, False, 0)

        self.fav_check = Gtk.CheckButton(label="Favorites only")
        self.fav_check.connect("toggled", self._on_favorites_toggled)
        bar.pack_start(self.fav_check, False, False, 0)

        clear_btn = Gtk.Button(label="Clear Filters")
        clear_btn.connect("clicked", self._on_clear_filters)
        bar.pack_end(clear_btn, False, False, 0)

        details_btn = Gtk.Button(label="Details")
        details_btn.connect("clicked", lambda _b: self._show_details())
        bar.pack_end(details_btn, False, False, 0)

        test_btn = Gtk.Button(label="Test Connection")
        test_btn.set_tooltip_text("Try a real VPN handshake with the listed servers and show the "
                                  "connect time from this computer")
        test_btn.connect("clicked", lambda _b: self.model.measure(self._visible_servers()))
        bar.pack_end(test_btn, False, False, 0)

        refresh_btn = Gtk.Button(label="Refresh List")
        refresh_btn.connect("clicked", lambda _b: self.model.refresh())
        bar.pack_end(refresh_btn, False, False, 0)
        return bar

    def _build_table(self) -> Gtk.Widget:
        self.store = Gtk.ListStore(*STORE_TYPES)
        self.tree = Gtk.TreeView(model=self.store)
        self.tree.set_rules_hint(True)
        self.tree.get_selection().connect("changed", self._on_selection_changed)
        self.tree.connect("row-activated", self._on_row_activated)
        self.tree.connect("button-press-event", self._on_button_press)

        for title, display_col, sort_col, visible in COLUMNS:
            cell = Gtk.CellRendererText()
            cell.set_property("ellipsize", Pango.EllipsizeMode.END)
            col = Gtk.TreeViewColumn(title, cell)
            col.set_resizable(True)
            col.set_visible(visible)
            col.set_min_width(70)
            if display_col == C_IP:
                col.add_attribute(cell, "markup", C_IP)
            else:
                col.add_attribute(cell, "text", display_col)
            if display_col == C_SCORE or display_col == C_PROBE:
                cell.set_property("xalign", 0.0)
            if sort_col is not None:
                col.set_sort_column_id(sort_col)
            self.tree.append_column(col)
        # The macOS window sorts by Total Score, newest best first.
        self.store.set_sort_column_id(C_SCORE, Gtk.SortType.DESCENDING)
        return self.tree

    # MARK: row values (all cell text lives in the store)

    def _probe_text_and_rank(self, sid: str) -> tuple[str, int]:
        outcome = self.model.probes.get(sid)
        if outcome is None:
            return "—", _I32_MAX - 1
        if outcome.state == "queued":
            return "Waiting…", _I32_MAX - 1
        if outcome.state == "testing":
            return "Testing…", _I32_MAX - 1
        if outcome.state == "ok":
            # Single line: a height change in a row above the viewport would shift the
            # visible content and read as a scroll jump.
            return (f"✓ {outcome.connectMs} ms (hs {outcome.helloMs} ms, port {outcome.port})",
                    outcome.connectMs)
        return f"✗ {outcome.message}", _I32_MAX

    def _row_values(self, s: VPNServer) -> tuple:
        """Values in exact store column order: display columns 0..16, then sort keys 17..25."""
        probe_text, probe_rank = self._probe_text_and_rank(s.id)
        host_escaped = GLib.markup_escape_text(s.hostName)
        return (
            # display columns
            s.id,
            f"{GLib.markup_escape_text(s.ip)}\n"
            f"<small><span foreground='gray'>{host_escaped}</span></small>",
            f"{s.flag} {s.countryLong}".strip(),
            ListFormat.uptime(s.uptimeMs),
            ListFormat.sessions(s.sessions),
            speed(s.speed),
            ListFormat.pings(s.pingToGoogle, s.ping),
            probe_text,
            ListFormat.logging(s.logType),
            _i32(s.score),
            s.fqdn,
            ", ".join(str(p) for p in s.prioritized_ssl_ports),
            ListFormat.udp(s.udpPort),
            bytes_fmt(s.totalTraffic),
            ListFormat.logins(s.totalUsers),
            s.operatorName or "Anonymous",
            s.message,
            # hidden sort keys
            s.ip,
            s.countryLong,
            _i32(s.uptimeMs),
            _i32(s.sessions),
            _i32(s.speed),
            _i32(s.ping),
            probe_rank,
            _i32(s.totalTraffic),
            _i32(s.totalUsers),
        )

    # MARK: in-place diff update (never clears the store → scroll/selection never jump)

    def _sync_from_model(self) -> bool:
        if self._updating:
            return False
        self._updating = True
        try:
            self._update_card()
            self._update_status()
            self._update_countries()
            self._diff_rows()
            self._update_connect_button()
        finally:
            self._updating = False
        return False

    def _diff_rows(self) -> None:
        visible = self._visible_servers()
        self._servers_by_id = {s.id: s for s in visible}

        # Remove rows that no longer pass the filter / the list.
        it = self.store.get_iter_first()
        while it is not None:
            nxt = self.store.iter_next(it)
            sid = self.store.get_value(it, C_ID)
            if sid not in self._servers_by_id:
                self.store.remove(it)
                self._iters.pop(sid, None)
                self._row_cache.pop(sid, None)
            it = nxt

        # Add new rows and update changed ones in place.
        seen = set()
        for s in visible:
            seen.add(s.id)
            values = self._row_values(s)
            cached = self._row_cache.get(s.id)
            if cached is not None and cached == values:
                continue
            it = self._iters.get(s.id)
            if it is not None and self.store.iter_is_valid(it):
                for i, v in enumerate(values):
                    self.store.set_value(it, i, v)
            else:
                self._iters[s.id] = self.store.append(values)
            self._row_cache[s.id] = values
        for sid in list(self._row_cache):
            if sid not in seen:
                self._row_cache.pop(sid, None)
                self._iters.pop(sid, None)

    def _visible_servers(self) -> list[VPNServer]:
        f = ServerFilter()
        f.search = self.search
        f.country = self.country
        f.favorites_only = self.favorites_only
        f.favorites = self.model.favorites
        max_weeks = int(self.model.prefs.get("maxLogWeeks", -1) or -1)
        f.max_log_weeks = max_weeks if max_weeks >= 0 else None
        return f.apply(self.model.servers)

    def _update_countries(self) -> None:
        countries = ["All"] + sorted({s.countryLong for s in self.model.servers})
        if self._countries_sig == tuple(countries):
            return
        self._countries_sig = tuple(countries)
        current = self.country
        self.country_combo.handler_block_by_func(self._on_country_changed)
        self.country_combo.remove_all()
        for c in countries:
            self.country_combo.append_text("All countries" if c == "All" else c)
        self.country_combo.set_active(countries.index(current) if current in countries else 0)
        self.country_combo.handler_unblock_by_func(self._on_country_changed)

    def _update_card(self) -> None:
        m = self.model
        state = m.event.state
        server = m.connected_server
        style, icon = CARD_STYLES.get(state, ("vg-card-orange", "⇄"))
        if self._card_style_class != style:
            ctx = self.card.get_style_context()
            ctx.remove_class(self._card_style_class)
            ctx.add_class(style)
            self._card_style_class = style
        self.card_icon.set_markup(f'<span size="16000">{icon}</span>')

        title = "Not connected" if state == ConnectionState.disconnected else state_title(state)
        self.card_title.set_text(title)
        if state != ConnectionState.disconnected:
            line1 = (f"{server.flag} {server.hostName}" if server else (m.event.server or ""))
            parts = [line1] if line1 else []
            if m.event.virtualIP:
                parts.append(f"Virtual IP {m.event.virtualIP}")
            self.card_line1.set_text("\n".join(parts))
            if state == ConnectionState.connected:
                self.card_line2.set_markup(
                    f"<tt>{duration(m.connected_at)}  ↓ {bytes_fmt(m.event.bytesIn)}  "
                    f"↑ {bytes_fmt(m.event.bytesOut)}</tt>")
            elif m.event.error:
                self.card_line2.set_markup(
                    f'<span foreground="red">{GLib.markup_escape_text(m.event.error)}</span>')
            else:
                self.card_line2.set_text("")
        elif m.notice:
            self.card_line1.set_text("")
            self.card_line2.set_markup(
                f'<span foreground="red">{GLib.markup_escape_text(m.notice)}</span>')
        else:
            self.card_line1.set_text("Select a server and press Connect.")
            self.card_line2.set_text("")

    def _update_status(self) -> None:
        m = self.model
        visible = self._visible_servers()
        if m.loading:
            self.status_label.set_markup(
                "<span foreground='gray'>"
                + GLib.markup_escape_text(
                    "Refreshing the List… (about 1 MB, can take 10–20 s)"
                    if not m.servers else "Refreshing the List…")
                + "</span>")
            return
        if not m.servers:
            self.status_label.set_markup(
                "<span foreground='gray'>No servers yet. Press Refresh List.</span>")
            return
        stale = (m.list_timestamp is not None and not ListFormat.is_list_ok(m.list_timestamp))
        updated = m.list_fetched_at or m.list_timestamp
        updated_text = ""
        if updated:
            updated_text = (f" (Updated at "
                            f"{time.strftime('%Y-%m-%d %H:%M', time.localtime(updated))})")
        shown = "" if len(visible) == len(m.servers) else f" — showing {len(visible)}"
        text = f"{len(m.servers)} Public VPN Relay Servers on the Earth!{updated_text}{shown}"
        if stale:
            self.status_label.set_markup(
                f"<span foreground='orange'>{GLib.markup_escape_text(text)}  ·  "
                f"The list is old — press Refresh List.</span>")
        else:
            self.status_label.set_markup(f"<span foreground='gray'>"
                                         f"{GLib.markup_escape_text(text)}</span>")

    def _update_connect_button(self) -> None:
        state = self.model.event.state
        if state == ConnectionState.disconnected:
            self.connect_button.set_label("Connect to the VPN Server")
            self.connect_button.get_style_context().add_class("suggested-action")
            self.connect_button.get_style_context().remove_class("destructive-action")
            self.connect_button.set_sensitive(self._selected_id is not None)
        elif state == ConnectionState.connected:
            self.connect_button.set_label("Disconnect")
            self.connect_button.get_style_context().remove_class("suggested-action")
            self.connect_button.get_style_context().add_class("destructive-action")
            self.connect_button.set_sensitive(True)
        else:
            self.connect_button.set_label("Cancel")
            self.connect_button.get_style_context().remove_class("suggested-action")
            self.connect_button.get_style_context().remove_class("destructive-action")
            self.connect_button.set_sensitive(True)

    def _build_button_row(self) -> Gtk.Widget:
        row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL)
        row.set_margin_start(16)
        row.set_margin_end(16)
        row.set_margin_bottom(6)
        self.connect_button = Gtk.Button()
        self.connect_button.set_size_request(220, 34)
        self.connect_button.connect("clicked", self._on_connect_clicked)
        row.pack_end(self.connect_button, False, False, 0)
        return row

    # MARK: events

    def _on_search_changed(self, entry) -> None:
        self.search = entry.get_text()
        self._diff_rows()
        self._update_status()

    def _on_country_changed(self, combo) -> None:
        text = combo.get_active_text()
        self.country = "All" if (text is None or text == "All countries") else text
        self._diff_rows()
        self._update_status()

    def _on_logging_changed(self, combo) -> None:
        idx = combo.get_active()
        if 0 <= idx < len(LOG_CHOICES):
            self.model.prefs.set("maxLogWeeks", LOG_CHOICES[idx][1])
        self._diff_rows()
        self._update_status()

    def _on_favorites_toggled(self, check) -> None:
        self.favorites_only = check.get_active()
        self._diff_rows()
        self._update_status()

    def _on_clear_filters(self, _btn) -> None:
        self.country = "All"
        self.favorites_only = False
        self.fav_check.set_active(False)
        self.model.prefs.set("maxLogWeeks", -1)
        self.logging_combo.set_active(0)
        self.search_entry.set_text("")
        self._diff_rows()
        self._update_status()

    def _selected_server(self) -> VPNServer | None:
        sel = self.tree.get_selection()
        model, iter_ = sel.get_selected()
        if iter_ is None:
            return None
        return self._servers_by_id.get(model[iter_][C_ID])

    def _on_selection_changed(self, sel) -> None:
        s = self._selected_server()
        self._selected_id = s.id if s is not None else None
        self._update_connect_button()

    def _on_row_activated(self, _tree, _path, _column) -> None:
        # Double-click connects only when idle; to switch servers, disconnect first.
        if self.model.event.state == ConnectionState.disconnected:
            s = self._selected_server()
            if s is not None:
                self.model.connect(s)

    def _on_connect_clicked(self, _btn) -> None:
        state = self.model.event.state
        if state == ConnectionState.disconnected:
            s = self._selected_server()
            if s is not None:
                self.model.connect(s)
        else:
            self.model.disconnect()

    def _on_button_press(self, tree, event):
        if event.button != 3:
            return False
        result = tree.get_path_at_pos(int(event.x), int(event.y))
        if result is None:
            return False
        path, _col, _x, _y = result
        tree.get_selection().select_path(path)
        s = self._selected_server()
        if s is None:
            return False
        menu = Gtk.Menu()
        if self.model.event.state == ConnectionState.disconnected:
            item = Gtk.MenuItem(label="Connect to the VPN Server")
            item.connect("activate", lambda _i: self.model.connect(s))
            menu.append(item)
        item = Gtk.MenuItem(label="Server Details…")
        item.connect("activate", lambda _i: self._show_details(s))
        menu.append(item)
        item = Gtk.MenuItem(label="Remove from Favorites" if s.id in self.model.favorites
                            else "Add to Favorites")
        item.connect("activate", lambda _i: self.model.toggle_favorite(s))
        menu.append(item)
        menu.show_all()
        menu.popup_at_pointer(event)
        return True

    def _show_details(self, server: VPNServer | None = None) -> None:
        from .dialogs import show_server_details
        s = server or self._selected_server()
        if s is not None:
            show_server_details(self, s)