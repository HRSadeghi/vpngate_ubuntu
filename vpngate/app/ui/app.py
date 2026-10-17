"""Application entry (port of VPNGateApp.swift): windows, menu actions, tray, disclaimer."""

from __future__ import annotations

import webbrowser

import gi
gi.require_version("Gtk", "3.0")
from gi.repository import Gio, GLib, Gtk  # noqa: E402

from ..model import AppModel
from .accounts import AccountsWindow
from .dialogs import show_disclaimer
from .history import HistoryWindow, LogWindow
from .mainwindow import ServerListWindow
from .settings import SettingsWindow
from .tray import TrayIcon

VPNGATE_WEBSITE = "http://www.vpngate.net/"


def _quiet_gtk_scale_noise() -> None:
    """Drop exactly one known-benign GTK 3 critical.

    AyatanaAppIndicator asks its hidden status icon for a scale factor while GTK
    does not consider it a widget yet ("gtk_widget_get_scale_factor: assertion
    'GTK_IS_WIDGET (widget)' failed"). It is non-fatal and comes from inside the
    toolkit, not from a widget of ours. Every other message still prints."""
    def _handler(_domain: str, _level, message: str, _data) -> None:
        if message and "gtk_widget_get_scale_factor" in message:
            return
        GLib.log_default_handler(_domain, _level, message, None)

    try:
        GLib.log_set_handler(
            "Gtk",
            GLib.LogLevelFlags.LEVEL_CRITICAL | GLib.LogLevelFlags.LEVEL_WARNING,
            _handler, None)
    except Exception:
        pass  # older PyGObject: leave the noise rather than fail


class VPNGateApplication(Gtk.Application):
    def __init__(self) -> None:
        super().__init__(application_id="com.yazdanifar.vpngate.linux",
                         flags=Gio.ApplicationFlags.FLAGS_NONE)
        self.model: AppModel | None = None
        self.windows: dict[str, Gtk.Window] = {}
        self.tray: TrayIcon | None = None

    def do_startup(self) -> None:
        _quiet_gtk_scale_noise()
        Gtk.Application.do_startup(self)
        self.model = AppModel()
        self.add_accelerator_actions()

    def do_activate(self) -> None:
        self.open_main()
        if not self.model.has_agreed_to_disclaimer:
            main = self.windows.get("main")
            if main is not None:
                show_disclaimer(main, self.model)
        if self.tray is None:
            try:
                self.tray = TrayIcon(self, self.model)
            except Exception:
                self.tray = None

    # MARK: window management

    def _register(self, key: str, window: Gtk.Window) -> Gtk.Window:
        self.windows[key] = window
        window.connect("destroy", lambda _w, k=key: self.windows.pop(k, None))
        window.show_all()
        return window

    def open_main(self, *_a) -> None:
        w = self.windows.get("main")
        if w is None:
            w = self._register("main", ServerListWindow(self, self.model))
            if not self.model.has_agreed_to_disclaimer:
                show_disclaimer(w, self.model)
        w.present()

    def open_accounts(self, *_a) -> None:
        w = self.windows.get("accounts")
        if w is None:
            w = self._register("accounts", AccountsWindow(self, self.model))
        w.present()

    def open_history(self, *_a) -> None:
        w = self.windows.get("history")
        if w is None:
            w = self._register("history", HistoryWindow(self, self.model))
        w.present()

    def open_log(self, *_a) -> None:
        w = self.windows.get("log")
        if w is None:
            w = self._register("log", LogWindow(self, self.model))
        w.present()

    def open_settings(self, *_a) -> None:
        w = self.windows.get("settings")
        if w is None:
            w = self._register("settings", SettingsWindow(self, self.model))
        w.present()

    def _refresh_windows(self) -> bool:
        # Windows refresh themselves via their own model.on_change hooks; this catches
        # button states that depend on more than one store.
        return False

    # MARK: actions

    def add_accelerator_actions(self) -> None:
        actions = [
            ("refresh", self._action_refresh, "<Primary>r"),
            ("disconnect", self._action_disconnect, "<Primary>d"),
            ("main", self.open_main, "<Primary>1"),
            ("accounts", self.open_accounts, "<Primary><Shift>m"),
            ("history", self.open_history, "<Primary>y"),
            ("log", self.open_log, "<Primary><Shift>l"),
            ("settings", self.open_settings, "<Primary>comma"),
        ]
        for name, callback, accel in actions:
            action = Gio.SimpleAction.new(name, None)
            action.connect("activate", lambda _a, _p, cb=callback: cb())
            self.add_action(action)
            if accel:
                self.set_accels_for_action(f"app.{name}", [accel])
        about = Gio.SimpleAction.new("website", None)
        about.connect("activate", lambda *_a: webbrowser.open(VPNGATE_WEBSITE))
        self.add_action(about)

    def _action_refresh(self, *_a) -> None:
        self.model.refresh()

    def _action_disconnect(self, *_a) -> None:
        self.model.disconnect()