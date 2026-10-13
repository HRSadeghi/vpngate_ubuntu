"""Connection history and log windows (ports of HistoryView.swift and LogView.swift)."""

from __future__ import annotations

import time

import gi
gi.require_version("Gtk", "3.0")
from gi.repository import GLib, Gtk  # noqa: E402

from ..formatting import bytes_fmt, duration_seconds


class HistoryWindow(Gtk.ApplicationWindow):
    def __init__(self, app, model, **kwargs):
        super().__init__(application=app, title="Connection History", **kwargs)
        self.model = model
        self.set_default_size(760, 400)

        header = Gtk.HeaderBar()
        header.set_show_close_button(True)
        header.set_has_subtitle(False)
        title = Gtk.Label(xalign=0)
        title.set_markup("<b>Connection history</b>")
        header.set_custom_title(title)
        clear = Gtk.Button(label="Clear")
        clear.connect("clicked", lambda _b: model.connection_log.clear())
        header.pack_end(clear)
        self.set_titlebar(header)

        outer = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=0)
        self.add(outer)

        self.empty = Gtk.Label(label="No connections yet.")
        outer.pack_start(self.empty, True, True, 0)

        self.store = Gtk.ListStore(str, str, str, str, str, str)
        self.tree = Gtk.TreeView(model=self.tree_store())
        self.tree.set_rules_hint(True)
        for title_, i in (("Server", 0), ("Address", 1), ("Connected", 2), ("Duration", 3),
                          ("Traffic", 4), ("Result", 5)):
            if i == 5:  # colored result
                cell = Gtk.CellRendererText()
                col = Gtk.TreeViewColumn(title_, cell)
                col.set_cell_data_func(cell, self._result_data, None)
            else:
                col = Gtk.TreeViewColumn(title_, Gtk.CellRendererText(), text=i)
            col.set_resizable(True)
            self.tree.append_column(col)
        scrolled = Gtk.ScrolledWindow()
        scrolled.set_policy(Gtk.PolicyType.AUTOMATIC, Gtk.PolicyType.AUTOMATIC)
        scrolled.set_vexpand(True)
        scrolled.add(self.tree)
        outer.pack_start(scrolled, True, True, 0)

        self._reload()
        self._unsubscribe = model.connection_log.changed.connect(
            lambda: GLib.idle_add(self._reload))
        self.connect("destroy", self._on_destroy)

    def tree_store(self):
        return self.store

    def _on_destroy(self, *_a):
        self._unsubscribe()

    def _result_data(self, _col, cell, _model, iter_, _data):
        result = self.store[iter_][5]
        if result and result != "ended":
            cell.set_property("markup", f'<span foreground="#c01c28">{result}</span>')
        else:
            cell.set_property("markup", f'<span foreground="gray">{result or "ended"}</span>')

    def _reload(self) -> bool:
        self.store.clear()
        entries = self.model.connection_log.entries
        self.empty.set_visible(not entries)
        for e in entries:
            connected = time.strftime("%b %d at %H:%M", time.localtime(e.connectedAt))
            if e.durationSeconds is not None:
                duration = duration_seconds(e.durationSeconds)
            else:
                duration = "active"
            traffic = f"↓ {bytes_fmt(e.bytesIn)}  ↑ {bytes_fmt(e.bytesOut)}"
            result = e.error or ("" if e.disconnectedAt is None else "ended")
            self.store.append([e.serverName, e.serverIP, connected, duration, traffic, result])
        return False


class LogWindow(Gtk.ApplicationWindow):
    def __init__(self, app, model, **kwargs):
        super().__init__(application=app, title="Connection Log", **kwargs)
        self.model = model
        self.set_default_size(760, 440)

        header = Gtk.HeaderBar()
        header.set_show_close_button(True)
        header.set_has_subtitle(False)
        copy_btn = Gtk.Button()
        copy_btn.set_image(Gtk.Image.new_from_icon_name(
            "edit-copy-symbolic", Gtk.IconSize.BUTTON))
        copy_btn.set_tooltip_text("Copy")
        copy_btn.connect("clicked", self._copy)
        header.pack_end(copy_btn)
        self.set_titlebar(header)

        outer = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=0)
        self.add(outer)

        self.text = Gtk.TextView()
        self.text.set_editable(False)
        self.text.set_monospace(True)
        self.text.set_wrap_mode(Gtk.WrapMode.WORD)
        self.text.get_buffer().create_tag("dim", foreground="gray")
        scrolled = Gtk.ScrolledWindow()
        scrolled.set_policy(Gtk.PolicyType.AUTOMATIC, Gtk.PolicyType.AUTOMATIC)
        scrolled.set_vexpand(True)
        scrolled.add(self.text)
        outer.pack_start(scrolled, True, True, 0)

        self._reload()
        self._unsubscribe = model.changed.connect(lambda: GLib.idle_add(self._reload))
        self.connect("destroy", self._on_destroy)

    def _on_destroy(self, *_a):
        self._unsubscribe()

    def _reload(self) -> bool:
        buffer = self.text.get_buffer()
        text = "\n".join(self.model.log_lines) or "No log yet."
        current = buffer.get_text(buffer.get_start_iter(), buffer.get_end_iter(), False)
        if current == text:
            return False
        # Only follow the tail when the reader is already at the bottom.
        vadj = self.text.get_vadjustment()
        at_bottom = (vadj is None or vadj.get_value() + vadj.get_page_size()
                     >= vadj.get_upper() - 1)
        buffer.set_text(text)
        if at_bottom:
            mark = buffer.create_mark(None, buffer.get_end_iter(), False)
            self.text.scroll_to_mark(mark, 0, False, 0, 0)
        return False

    def _copy(self, _btn) -> None:
        from gi.repository import Gdk
        clipboard = Gtk.Clipboard.get_default(Gdk.Display.get_default())
        clipboard.set_text("\n".join(self.model.log_lines), -1)