"""Smoke test: every screen must construct without errors.

The GTK "Settings…" bug class: an attribute typo inside one tab builder crashed the window
only when the user opened it (the button handler swallowed the traceback). This test builds
every window and every settings tab up-front. Requires a display; skips cleanly headless."""

import os
import unittest

os.environ.setdefault("VPNGATE_SUPPORT_DIR", "/tmp/opencode/ui-smoke")


def _display_available() -> bool:
    try:
        import gi
        gi.require_version("Gtk", "3.0")
        from gi.repository import Gtk, Gdk
        if Gdk.Screen.get_default() is not None:
            return True
        display = os.environ.get("DISPLAY") or ":0"
        return Gdk.Display.open(display) is not None
    except Exception:
        return False


@unittest.skipUnless(_display_available(), "no GTK display available")
class UIScreenSmokeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import sys
        sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        import gi
        gi.require_version("Gtk", "3.0")
        from gi.repository import Gtk
        cls.Gtk = Gtk

        class _StubApp(Gtk.Application):
            """A real Gtk.Application (windows bind `application=`) with open_* handlers."""

            def __init__(self) -> None:
                super().__init__(application_id="com.yazdanifar.vpngate.smoketest")
                self.opened = []

            def do_activate(self) -> None:
                pass

            def open_main(self, *_a):
                self.opened.append("main")

            def open_accounts(self, *_a):
                self.opened.append("accounts")

            def open_history(self, *_a):
                self.opened.append("history")

            def open_log(self, *_a):
                self.opened.append("log")

            def open_settings(self, *_a):
                self.opened.append("settings")

        from vpngate.app.model import AppModel
        cls.model = AppModel(auto_start=False)
        cls.model.servers = []
        cls.app = _StubApp()

    def test_main_window(self):
        from vpngate.app.ui.mainwindow import ServerListWindow
        win = ServerListWindow(self.app, self.model)
        win.destroy()

    def test_settings_every_tab(self):
        """Constructing the window builds every tab eagerly — an attribute typo in any tab
        builder (the Settings-button crash class) fails here, at test time."""
        from vpngate.app.ui.settings import SettingsWindow
        win = SettingsWindow(self.app, self.model)
        stack = self._find_stack(win)
        self.assertIsNotNone(stack, "settings stack not found")
        self.assertEqual(stack.get_children().__len__(), 4, "expected 4 settings tabs")
        # Touch every page's widget tree so lazy errors surface too.
        for child in stack.get_children():
            stack.set_visible_child(child)
            child.get_allocated_width()
        win.destroy()

    def _find_stack(self, widget):
        if isinstance(widget, self.Gtk.Stack):
            return widget
        if isinstance(widget, self.Gtk.Container):
            for child in widget.get_children():
                found = self._find_stack(child)
                if found is not None:
                    return found
        return None

    def test_accounts_window(self):
        from vpngate.app.ui.accounts import AccountsWindow
        win = AccountsWindow(self.app, self.model)
        win.destroy()

    def test_history_window(self):
        from vpngate.app.ui.history import HistoryWindow
        win = HistoryWindow(self.app, self.model)
        win.destroy()

    def test_log_window(self):
        from vpngate.app.ui.history import LogWindow
        win = LogWindow(self.app, self.model)
        win.destroy()

    def test_routing_editor(self):
        from vpngate.app.ui.routing import RoutingRulesEditor
        editor = RoutingRulesEditor(self.model.routing_config, lambda c: None,
                                    parent_window=None)
        editor.destroy()

    def test_running_apps_dialog(self):
        from vpngate.app.ui.apps_dialog import RunningAppsDialog
        dialog = RunningAppsDialog(None)
        dialog.destroy()





if __name__ == "__main__":
    unittest.main()