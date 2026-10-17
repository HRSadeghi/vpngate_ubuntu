"""Routing rules editor (port of RoutingSettingsView.swift) — shared by the Settings tab and
the per-account override editor. macOS-style groups: defaults, rules, bypass apps, hint."""

from __future__ import annotations

import gi
gi.require_version("Gtk", "3.0")
from gi.repository import GLib, Gtk  # noqa: E402

from ...app.apps import list_running_apps
from ...core.routing import (RoutingAction, RoutingConfig, RoutingRule, RoutingRuleType,
                             routing_rule_validation_error)
from .apps_dialog import RunningAppsDialog

PLACEHOLDERS = {
    RoutingRuleType.domainSuffix: "example.com",
    RoutingRuleType.domainFull: "example.com",
    RoutingRuleType.domainKeyword: "ads",
    RoutingRuleType.domainRegex: "^(.+\\.)?example\\.com$",
    RoutingRuleType.ip: "203.0.113.5",
    RoutingRuleType.cidr: "10.0.0.0/8",
}

ACTION_COLORS = {RoutingAction.proxy: "#3584e4", RoutingAction.direct: "#2ec27e",
                 RoutingAction.block: "#e01b24"}


def _group(title: str) -> tuple[Gtk.Frame, Gtk.Box]:
    head = Gtk.Label(xalign=0)
    head.set_markup(f"<b>{title}</b>")
    frame = Gtk.Frame()
    frame.get_style_context().add_class("vg-group")
    frame.set_shadow_type(Gtk.ShadowType.NONE)
    inner = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
    frame.add(inner)
    return frame, inner


def _pack_group(parent: Gtk.Box, frame: Gtk.Frame, head: Gtk.Label) -> None:
    parent.pack_start(head, False, False, 0)
    parent.pack_start(frame, False, False, 0)


class RoutingRuleSheet(Gtk.Dialog):
    """Add or edit one rule (macOS sheet: Match / value / Action / Enabled + Cancel/Add)."""

    def __init__(self, parent, rule: RoutingRule | None, on_done) -> None:
        self.rule = rule
        self.on_done = on_done
        self.is_new = rule is None
        super().__init__(title="Add Routing Rule" if self.is_new else "Edit Routing Rule",
                         transient_for=parent, modal=True)
        self.add_button("_Cancel", Gtk.ResponseType.CANCEL)
        if not self.is_new:
            self.add_button("_Delete", Gtk.ResponseType.REJECT)
        save_btn = self.add_button(self.is_new and "_Add" or "_Save", Gtk.ResponseType.OK)
        save_btn.get_style_context().add_class("suggested-action")
        self.set_default_response(Gtk.ResponseType.OK)
        self.set_size_request(480, -1)

        grid = Gtk.Grid(column_spacing=12, row_spacing=12, margin_start=16, margin_end=16,
                        margin_top=14, margin_bottom=14)
        grid.attach(Gtk.Label(label="Match", xalign=0), 0, 0, 1, 1)
        self.type_combo = Gtk.ComboBoxText()
        for t in RoutingRuleType:
            self.type_combo.append(t.value, t.label)
        self.type_combo.set_active_id(rule.type.value if rule
                                      else RoutingRuleType.domainSuffix.value)
        self.type_combo.connect("changed", lambda _c: self._update_error())
        grid.attach(self.type_combo, 1, 0, 1, 1)

        grid.attach(Gtk.Label(label="Value", xalign=0), 0, 1, 1, 1)
        self.value_entry = Gtk.Entry()
        self.value_entry.set_text(rule.value if rule else "")
        self.value_entry.set_placeholder_text(self._placeholder())
        self.value_entry.set_hexpand(True)
        self.value_entry.connect("changed", lambda _e: self._update_error())
        grid.attach(self.value_entry, 1, 1, 1, 1)

        self.error_label = Gtk.Label(xalign=0)
        self.error_label.set_markup('<span foreground="red" size="small"></span>')
        grid.attach(self.error_label, 1, 2, 1, 1)

        grid.attach(Gtk.Label(label="Action", xalign=0), 0, 3, 1, 1)
        self.action_combo = Gtk.ComboBoxText()
        for a in RoutingAction:
            self.action_combo.append(a.value, a.label)
        self.action_combo.set_active_id(rule.action.value if rule else RoutingAction.proxy.value)
        grid.attach(self.action_combo, 1, 3, 1, 1)

        self.enabled_check = Gtk.CheckButton(label="Enabled")
        self.enabled_check.set_active(rule.enabled if rule else True)
        grid.attach(self.enabled_check, 1, 4, 1, 1)

        self.get_content_area().add(grid)
        self._update_error()
        self.connect("response", self._on_response)

    def _placeholder(self) -> str:
        try:
            return PLACEHOLDERS[RoutingRuleType(self.type_combo.get_active_id())]
        except (ValueError, KeyError):
            return ""

    def _current_rule(self) -> RoutingRule:
        return RoutingRule(
            id=self.rule.id if self.rule else "",
            type=RoutingRuleType(self.type_combo.get_active_id()),
            value=self.value_entry.get_text(),
            action=RoutingAction(self.action_combo.get_active_id()),
            enabled=self.enabled_check.get_active(),
        )

    def _update_error(self) -> None:
        self.value_entry.set_placeholder_text(self._placeholder())
        error = self._current_rule().validation_error
        value = self.value_entry.get_text().strip()
        self.error_label.set_markup(
            f'<span foreground="red" size="small">{error if (error and value) else ""}</span>')
        self.set_response_sensitive(Gtk.ResponseType.OK, self._current_rule().is_valid)

    def _on_response(self, dialog, response) -> None:
        if response == Gtk.ResponseType.REJECT:
            self.on_done(None)
            self.destroy()
            return
        if response == Gtk.ResponseType.OK:
            rule = self._current_rule()
            if rule.is_valid:
                self.on_done(rule)
                self.destroy()
            return
        self.destroy()


class RoutingRulesEditor(Gtk.Box):
    """Ordered rule list, default-action picker, bypass-private-networks toggle and the
    bypass-apps group (split tunneling by application)."""

    def __init__(self, config: RoutingConfig, on_change, parent_window=None) -> None:
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=10)
        self.config = config
        self.on_change = on_change
        self.parent_window = parent_window

        # MARK: Bypass apps — first, it is the headline feature of this tab
        self._build_bypass_group()

        # MARK: Unmatched traffic
        frame, inner = _group("Unmatched traffic")
        row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8,
                      margin_start=10, margin_end=10, margin_top=8, margin_bottom=8)
        lab = Gtk.Label(label="By default", xalign=0)
        lab.set_hexpand(True)
        row.pack_start(lab, True, True, 0)
        self.default_combo = Gtk.ComboBoxText()
        self.default_combo.append("proxy", "Proxy (through the tunnel)")
        self.default_combo.append("direct", "Direct (bypass the tunnel)")
        self.default_combo.set_active_id(config.default_action.value)
        self.default_combo.connect("changed", self._on_default_changed)
        row.pack_end(self.default_combo, False, False, 0)
        inner.add(row)

        self.bypass_check = Gtk.Switch()
        self.bypass_check.set_active(config.bypass_private_networks)
        self.bypass_check.connect("notify::active", self._on_bypass_toggled)
        inner.add(self._labeled_row("Bypass private networks (LAN, link-local, CGNAT)",
                                    self.bypass_check))
        self.hint = Gtk.Label(xalign=0)
        self.hint.set_line_wrap(True)
        self.hint.set_max_width_chars(70)
        self.hint.get_style_context().add_class("dim-label")
        self._update_hint()
        hint_row = Gtk.ListBoxRow()
        hint_row.set_activatable(False)
        self.hint.set_margin_start(10)
        self.hint.set_margin_end(10)
        self.hint.set_margin_top(2)
        self.hint.set_margin_bottom(8)
        hint_row.add(self.hint)
        inner.add(hint_row)
        unmatched_head = Gtk.Label(xalign=0)
        unmatched_head.set_markup("<b>Unmatched traffic</b>")
        _pack_group(self, frame, unmatched_head)

        # MARK: Rules
        rules_frame, rules_inner = _group("Rules")
        head_label = Gtk.Label(xalign=0)
        head_label.set_markup("<b>Rules</b>")
        self.list_box = Gtk.ListBox()
        self.list_box.set_selection_mode(Gtk.SelectionMode.SINGLE)
        self.list_box.connect("row-activated", self._on_row_activated)
        rules_inner.add(self.list_box)
        add_btn = Gtk.Button(label="Add Rule…")
        add_btn.set_halign(Gtk.Align.START)
        add_btn.set_margin_start(10)
        add_btn.set_margin_top(4)
        add_btn.set_margin_bottom(8)
        add_btn.connect("clicked", lambda _b: self._add_rule())
        rules_inner.add(add_btn)
        _pack_group(self, rules_frame, head_label)

        # MARK: explanation
        exp_frame, exp_inner = _group("")
        exp_lab = Gtk.Label(xalign=0)
        exp_lab.set_line_wrap(True)
        exp_lab.set_max_width_chars(76)
        exp_lab.get_style_context().add_class("dim-label")
        exp_lab.set_markup(
            "<small>Rules are checked in order from top to bottom; the first one that matches "
            "wins. Domain rules need the DNS proxy, which only runs while one is configured. A "
            "domain marked “Direct” is looked up through your regular network connection, never "
            "through the VPN or its DNS — everything else is resolved only through the tunnel."
            "</small>")
        exp_lab.set_margin_start(10)
        exp_lab.set_margin_end(10)
        exp_lab.set_margin_top(8)
        exp_lab.set_margin_bottom(8)
        exp_inner.add(exp_lab)
        self.pack_start(exp_frame, False, False, 0)

        self._reload()

    @staticmethod
    def _labeled_row(label: str, control: Gtk.Widget) -> Gtk.ListBoxRow:
        row = Gtk.ListBoxRow()
        row.set_activatable(False)
        row.set_selectable(False)
        box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8,
                      margin_start=10, margin_end=10, margin_top=8, margin_bottom=8)
        lab = Gtk.Label(label=label, xalign=0)
        lab.set_hexpand(True)
        lab.set_valign(Gtk.Align.CENTER)
        box.pack_start(lab, True, True, 0)
        control.set_valign(Gtk.Align.CENTER)
        box.pack_end(control, False, False, 0)
        row.add(box)
        return row

    # MARK: bypass apps (outside the tunnel)

    def _build_bypass_group(self) -> None:
        self._bypass_rows_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        frame, inner = _group("Bypass apps (outside the tunnel)")

        self.bypass_switch = Gtk.Switch()
        self.bypass_switch.set_active(self.config.bypass_apps_enabled)
        self.bypass_switch.connect("notify::active", self._on_bypass_switch)
        inner.add(self._labeled_row("Enable app bypass", self.bypass_switch))

        add_btn = Gtk.Button(label="Add running app…")
        add_btn.set_halign(Gtk.Align.START)
        add_btn.set_margin_start(10)
        add_btn.set_margin_bottom(8)
        add_btn.set_sensitive(self.config.bypass_apps_enabled)
        add_btn.connect("clicked", lambda _b: self._show_running_apps_dialog())
        self._bypass_add_btn = add_btn
        inner.add(add_btn)
        inner.add(self._bypass_rows_box)
        bypass_head = Gtk.Label(xalign=0)
        bypass_head.set_markup("<b>Bypass apps (outside the tunnel)</b>")
        _pack_group(self, frame, bypass_head)

        hint_frame, hint_inner = _group("")
        hint = Gtk.Label(xalign=0)
        hint.set_line_wrap(True)
        hint.set_max_width_chars(76)
        hint.get_style_context().add_class("dim-label")
        hint.set_markup(
            "<small>Selected applications keep their normal internet connection while the "
            "VPN is connected — useful for banking apps, local services or apps that refuse "
            "proxies. Takes effect for new connections of the app.</small>")
        hint.set_margin_start(10)
        hint.set_margin_end(10)
        hint.set_margin_top(8)
        hint.set_margin_bottom(8)
        hint_inner.add(hint)
        self.pack_start(hint_frame, False, False, 0)
        self._reload_bypass_rows()

    def _reload_bypass_rows(self) -> None:
        for child in self._bypass_rows_box.get_children():
            self._bypass_rows_box.remove(child)
        for app in self.config.bypass_apps:
            row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8,
                          margin_start=10, margin_end=10, margin_top=6, margin_bottom=6)
            row.pack_start(Gtk.Image.new_from_icon_name("application-x-executable-symbolic",
                                                        Gtk.IconSize.BUTTON), False, False, 0)
            lab = Gtk.Label(xalign=0)
            lab.set_markup(f"<b>{GLib.markup_escape_text(app)}</b>")
            lab.set_hexpand(True)
            row.pack_start(lab, True, True, 0)
            remove = Gtk.Button(label="Remove")
            remove.connect("clicked", lambda _b, a=app: self._remove_bypass_app(a))
            row.pack_end(remove, False, False, 0)
            self._bypass_rows_box.add(row)
        self._bypass_rows_box.show_all()
        self._bypass_add_btn.set_sensitive(bool(self.config.bypass_apps_enabled))

    def _on_bypass_switch(self, switch, _param) -> None:
        self.config.bypass_apps_enabled = switch.get_active()
        self._bypass_add_btn.set_sensitive(self.config.bypass_apps_enabled)
        self.on_change(self.config)

    def _remove_bypass_app(self, app: str) -> None:
        if app in self.config.bypass_apps:
            self.config.bypass_apps.remove(app)
            self.on_change(self.config)
            self._reload_bypass_rows()  # rebuild the rows so Remove actually removes the row

    def _show_running_apps_dialog(self) -> None:
        dialog = RunningAppsDialog(self.parent_window)
        dialog.set_add_callback(self._add_bypass_app)
        dialog.show_all()

    def _add_bypass_app(self, app: str) -> None:
        if app and app not in self.config.bypass_apps:
            self.config.bypass_apps.append(app)
            self.on_change(self.config)

    # MARK: rules

    def _update_hint(self) -> None:
        from ...core.routing import RoutingAction
        if self.config.default_action == RoutingAction.proxy:
            self.hint.set_text("Everything goes through the tunnel except what the rules below "
                               "send elsewhere.")
        else:
            extra = ""
            if not any(r.enabled and r.action == RoutingAction.proxy for r in self.config.rules):
                extra = (" ⚠ With no Proxy rule below, NOTHING uses the VPN — sites resolve "
                         "through the tunnel's DNS but connect outside it. For one exception, "
                         "keep the default on Proxy and add that site as a Direct rule.")
            self.hint.set_text("Everything bypasses the tunnel except what the rules below send "
                               "into it. IPv6 keeps being captured and dropped regardless (see "
                               "“Block IPv6” in General)." + extra)

    def _rule_row(self, rule: RoutingRule) -> Gtk.ListBoxRow:
        row = Gtk.ListBoxRow()
        row.set_activatable(True)
        row.rule_id = rule.id  # Python attribute (set_data is unsupported in PyGObject)
        box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8, margin_start=10,
                      margin_end=10, margin_top=8, margin_bottom=8)
        left = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=1)
        value = Gtk.Label(xalign=0)
        value.set_markup(f"<tt>{GLib.markup_escape_text(rule.value)}</tt>")
        left.pack_start(value, False, False, 0)
        kind = Gtk.Label(xalign=0)
        kind.get_style_context().add_class("dim-label")
        kind.set_markup(f'<small>{rule.type.label}</small>')
        left.pack_start(kind, False, False, 0)
        box.pack_start(left, True, True, 0)
        color = ACTION_COLORS.get(rule.action, "#77767b")
        action = Gtk.Label()
        action.set_markup(
            f'<span background="{color}22" foreground="{color}"><b> {rule.action.label} </b>'
            f'</span>')
        action.get_style_context().add_class("vg-pill")
        box.pack_start(action, False, False, 0)
        if not rule.enabled:
            off = Gtk.Label()
            off.set_markup('<span foreground="gray" size="small">Off</span>')
            box.pack_start(off, False, False, 0)
        row.add(box)
        return row

    def _reload(self) -> None:
        for child in self.list_box.get_children():
            self.list_box.remove(child)
        for rule in self.config.rules:
            self.list_box.add(self._rule_row(rule))
        self.list_box.show_all()
        self._update_hint()

    def _selected_rule(self) -> RoutingRule | None:
        row = self.list_box.get_selected_row()
        if row is None:
            return None
        rule_id = getattr(row, "rule_id", None)
        for r in self.config.rules:
            if r.id == rule_id:
                return r
        return None

    def _add_rule(self) -> None:
        self._editing_rule_id = None
        RoutingRuleSheet(self.parent_window, None, self._rule_added).show_all()

    def _rule_added(self, rule: RoutingRule | None) -> None:
        if rule is not None:
            self.config.rules.append(rule)
            self._changed()

    def _edit_selected(self) -> None:
        rule = self._selected_rule()
        if rule is not None:
            self._editing_rule_id = rule.id
            RoutingRuleSheet(self.parent_window, rule, self._rule_edited).show_all()

    def _rule_edited(self, updated: RoutingRule | None) -> None:
        if updated is None:
            # Delete: use the tracked editing rule (selection may have changed)
            rid = getattr(self, "_editing_rule_id", None)
            self.config.rules = [r for r in self.config.rules if r.id != rid]
        else:
            for i, r in enumerate(self.config.rules):
                if r.id == updated.id:
                    self.config.rules[i] = updated
                    break
        self._changed()

    def _on_row_activated(self, _box, _row) -> None:
        self._edit_selected()

    def _on_default_changed(self, combo) -> None:
        from ...core.routing import RoutingAction
        try:
            self.config.default_action = RoutingAction(combo.get_active_id() or "proxy")
        except ValueError:
            pass
        self._changed()

    def _on_bypass_toggled(self, check) -> None:
        self.config.bypass_private_networks = check.get_active()
        self._changed()

    def _changed(self) -> None:
        self._reload()
        self.on_change(self.config)