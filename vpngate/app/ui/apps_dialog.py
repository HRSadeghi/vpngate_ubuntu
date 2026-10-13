"""Dialog for picking running applications (split tunneling by app).

Searchable list of the running applications: name, executable path and process count.
Double-click or Add appends the selection to the bypass list."""

from __future__ import annotations

import gi
gi.require_version("Gtk", "3.0")
from gi.repository import GLib, Gtk  # noqa: E402

from ...app.apps import list_running_apps, RunningApp


class RunningAppsDialog(Gtk.Dialog):
    def __init__(self, parent) -> None:
        super().__init__(title="Add a running application", transient_for=parent, modal=True)
        self.add_button("_Cancel", Gtk.ResponseType.CANCEL)
        add_btn = self.add_button("_Add", Gtk.ResponseType.OK)
        add_btn.get_style_context().add_class("suggested-action")
        self.set_default_response(Gtk.ResponseType.OK)
        self.set_default_size(620, 560)
        self._add_callback = None
        self._selected: RunningApp | None = None
        self._apps: list[RunningApp] = []

        box = self.get_content_area()
        box.set_spacing(8)
        box.set_margin_top(10)
        box.set_margin_bottom(4)

        self.search = Gtk.SearchEntry()
        self.search.set_placeholder_text("Search running applications…")
        self.search.set_margin_start(12)
        self.search.set_margin_end(12)
        self.search.connect("search-changed", lambda _e: self._reload())
        box.pack_start(self.search, False, False, 0)

        hint = Gtk.Label(xalign=0)
        hint.set_markup("<small><span foreground='gray'>Pick an application — its new "
                        "connections will keep the regular internet instead of the VPN. "
                        "Programs of all users are bypassed by the helper.</span></small>")
        hint.set_margin_start(12)
        hint.set_margin_end(12)
        box.pack_start(hint, False, False, 0)

        self.store = Gtk.ListStore(str, str, str)  # key, name+detail markup, count text
        self.tree = Gtk.TreeView(model=self.store)
        self.tree.set_rules_hint(True)
        col = Gtk.TreeViewColumn("Application", Gtk.CellRendererText(), markup=1)
        col.set_resizable(True)
        col.set_expand(True)
        self.tree.append_column(col)
        col = Gtk.TreeViewColumn("Processes", Gtk.CellRendererText(), text=2)
        self.tree.append_column(col)
        self.tree.get_selection().connect("changed", self._on_selection)
        self.tree.connect("row-activated", lambda _t, _p, _c: self._emit_add())

        scrolled = Gtk.ScrolledWindow()
        scrolled.set_policy(Gtk.PolicyType.AUTOMATIC, Gtk.PolicyType.AUTOMATIC)
        scrolled.set_vexpand(True)
        scrolled.set_margin_start(12)
        scrolled.set_margin_end(12)
        scrolled.add(self.tree)
        box.pack_start(scrolled, True, True, 0)

        self.count_label = Gtk.Label(xalign=0)
        self.count_label.get_style_context().add_class("dim-label")
        self.count_label.set_margin_start(12)
        self.count_label.set_margin_end(12)
        box.pack_start(self.count_label, False, False, 0)

        self._reload()
        self.connect("response", self._on_response)

    def set_add_callback(self, callback) -> None:
        self._add_callback = callback

    def _on_selection(self, sel) -> None:
        model, iter_ = sel.get_selected()
        if iter_ is None:
            self._selected = None
            return
        key = model[iter_][0]
        self._selected = next((a for a in self._apps if a.name.lower() == key), None)

    def _emit_add(self) -> None:
        if self._selected is not None and self._add_callback is not None:
            self._add_callback(self._selected.name)
        self.destroy()

    def _on_response(self, dialog, response) -> None:
        if response == Gtk.ResponseType.OK:
            self._emit_add()
            return
        self.destroy()

    def _reload(self) -> None:
        self._apps = list_running_apps()
        text = self.search.get_text().strip().lower()
        self.store.clear()
        shown = 0
        for app in self._apps:
            if text and text not in app.name.lower() and text not in app.path.lower():
                continue
            shown += 1
            name = GLib.markup_escape_text(app.name)
            detail = GLib.markup_escape_text(app.detail)
            self.store.append([app.name.lower(),
                               f"<b>{name}</b>\n<small><span foreground='gray'>"
                               f"{detail}</span></small>",
                               str(len(app.pids))])
        total = len(self._apps)
        self.count_label.set_text(f"{shown} of {total} running applications shown")
