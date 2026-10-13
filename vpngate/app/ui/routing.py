"""Routing rules editor (port of RoutingSettingsView.swift) — shared by the Settings tab and the
per-account override editor."""

from __future__ import annotations

import gi
gi.require_version("Gtk", "3.0")
from gi.repository import Gtk  # noqa: E402

from ...core.routing import RoutingAction, RoutingConfig, RoutingRule, RoutingRuleType

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


class RoutingRuleSheet(Gtk.Dialog):
    """Add or edit one rule."""

    def __init__(self, parent, rule: RoutingRule | None, on_done) -> None:
        self.rule = rule
        self.on_done = on_done
        self.is_new = rule is None
        super().__init__(title="Add Routing Rule" if self.is_new else "Edit Routing Rule",
                         transient_for=parent, modal=True)
        self.add_button("_Cancel", Gtk.ResponseType.CANCEL)
        if not self.is_new:
            self.add_button("_Delete", Gtk.ResponseType.REJECT)
        self.add_button(self.is_new and "_Add" or "_Save", Gtk.ResponseType.OK)
        self.set_default_response(Gtk.ResponseType.OK)
        self.set_size_request(440, -1)

        grid = Gtk.Grid(column_spacing=10, row_spacing=10, margin_start=14, margin_end=14,
                        margin_top=12, margin_bottom=12)
        grid.attach(Gtk.Label(label="Match", xalign=0), 0, 0, 1, 1)
        self.type_combo = Gtk.ComboBoxText()
        for t in RoutingRuleType:
            self.type_combo.append(t.value, t.label)
        self.type_combo.set_active_id((rule.type.value if rule else RoutingRuleType.domainSuffix.value))
        self.type_combo.connect("changed", lambda _c: self._update_error())
        grid.attach(self.type_combo, 1, 0, 1, 1)

        grid.attach(Gtk.Label(label="Value", xalign=0), 0, 1, 1, 1)
        self.value_entry = Gtk.Entry()
        self.value_entry.set_text(rule.value if rule else "")
        self.value_entry.set_placeholder_text(self._placeholder())
        self.value_entry.connect("changed", lambda _e: self._update_error())
        grid.attach(self.value_entry, 1, 1, 1, 1)

        self.error_label = Gtk.Label(xalign=0)
        self.error_label.set_markup('<span foreground="red" size="small"></span>')
        grid.attach(self.error_label, 1, 2, 1, 1)

        grid.attach(Gtk.Label(label="Action", xalign=0), 0, 3, 1, 1)
        self.action_combo = Gtk.ComboBoxText()
        for a in RoutingAction:
            self.action_combo.append(a.value, a.label)
        self.action_combo.set_active_id((rule.action.value if rule else RoutingAction.proxy.value))
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
        text = error if (error and value) else ""
        self.error_label.set_markup(f'<span foreground="red" size="small">{text}</span>')
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
    """An ordered list of rules, add/remove/reorder, a default-action picker and the
    bypass-private-networks toggle."""

    def __init__(self, config: RoutingConfig, on_change, parent_window=None) -> None:
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        self.config = config
        self.on_change = on_change
        self.parent_window = parent_window

        defaults = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
        row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        row.pack_start(Gtk.Label(label="By default", xalign=0), False, False, 0)
        self.default_combo = Gtk.ComboBoxText()
        self.default_combo.append("proxy", "Proxy (through the tunnel)")
        self.default_combo.append("direct", "Direct (bypass the tunnel)")
        self.default_combo.set_active_id(config.default_action.value)
        self.default_combo.connect("changed", self._on_default_changed)
        row.pack_start(self.default_combo, False, False, 0)
        defaults.pack_start(row, False, False, 0)

        self.bypass_check = Gtk.CheckButton(
            label="Bypass private networks (LAN, link-local, CGNAT)")
        self.bypass_check.set_active(config.bypass_private_networks)
        self.bypass_check.connect("toggled", self._on_bypass_toggled)
        defaults.pack_start(self.bypass_check, False, False, 0)

        self.hint = Gtk.Label(xalign=0)
        self.hint.set_line_wrap(True)
        self.hint.get_style_context().add_class("dim-label")
        self._update_hint()
        defaults.pack_start(self.hint, False, False, 0)
        self.pack_start(defaults, False, False, 0)

        rules_head = Gtk.Label(xalign=0)
        rules_head.set_markup("<b>Rules</b>")
        self.pack_start(rules_head, False, False, 0)

        self.list_box = Gtk.ListBox()
        self.list_box.set_selection_mode(Gtk.SelectionMode.SINGLE)
        self.list_box.connect("row-activated", self._on_row_activated)
        scrolled = Gtk.ScrolledWindow()
        scrolled.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
        scrolled.set_max_content_height(180)
        scrolled.set_propagate_natural_height(True)
        scrolled.add(self.list_box)
        self.pack_start(scrolled, True, True, 0)

        buttons = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
        add_btn = Gtk.Button(label="Add Rule…")
        add_btn.connect("clicked", lambda _b: self._add_rule())
        buttons.pack_start(add_btn, False, False, 0)
        edit_btn = Gtk.Button(label="Edit")
        edit_btn.connect("clicked", lambda _b: self._edit_selected())
        buttons.pack_start(edit_btn, False, False, 0)
        up_btn = Gtk.Button(label="↑")
        up_btn.set_tooltip_text("Move rule up (checked first)")
        up_btn.connect("clicked", lambda _b: self._move(-1))
        buttons.pack_start(up_btn, False, False, 0)
        down_btn = Gtk.Button(label="↓")
        down_btn.set_tooltip_text("Move rule down")
        down_btn.connect("clicked", lambda _b: self._move(1))
        buttons.pack_start(down_btn, False, False, 0)
        self.pack_start(buttons, False, False, 0)

        explanation = Gtk.Label(xalign=0)
        explanation.set_line_wrap(True)
        explanation.get_style_context().add_class("dim-label")
        explanation.set_markup(
            '<small>Rules are checked in order from top to bottom; the first one that matches '
            'wins. Domain rules need the DNS proxy, which only runs while one is configured. A '
            'domain marked “Direct” is looked up through your regular network connection, never '
            'through the VPN or its DNS — everything else is resolved only through the tunnel.'
            '</small>')
        self.pack_start(explanation, False, False, 0)
        self._reload()

    def _update_hint(self) -> None:
        from ...core.routing import RoutingAction
        if self.config.default_action == RoutingAction.proxy:
            self.hint.set_text("Everything goes through the tunnel except what the rules below "
                               "send elsewhere.")
        else:
            self.hint.set_text("Everything bypasses the tunnel except what the rules below send "
                               "into it. IPv6 keeps being captured and dropped regardless (see "
                               "“Block IPv6” in General).")

    def _rule_row(self, rule: RoutingRule) -> Gtk.ListBoxRow:
        row = Gtk.ListBoxRow()
        rule_id = rule.id
        row.set_data("rule-id", rule_id)
        box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8, margin_start=8,
                      margin_end=8, margin_top=4, margin_bottom=4)
        left = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=1)
        value = Gtk.Label(xalign=0)
        value.set_markup(f"<tt>{rule.value}</tt>")
        left.pack_start(value, False, False, 0)
        kind = Gtk.Label(xalign=0)
        kind.get_style_context().add_class("dim-label")
        kind.set_markup(f'<small>{rule.type.label}</small>')
        left.pack_start(kind, False, False, 0)
        box.pack_start(left, True, True, 0)
        action = Gtk.Label()
        color = ACTION_COLORS.get(rule.action, "gray")
        action.set_markup(f'<span foreground="{color}"><b>{rule.action.label}</b></span>')
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
            self.list_box.append(self._rule_row(rule))
        self.list_box.show_all()
        self._update_hint()

    def _selected_rule(self) -> RoutingRule | None:
        row = self.list_box.get_selected_row()
        if row is None:
            return None
        rule_id = row.get_data("rule-id")
        for r in self.config.rules:
            if r.id == rule_id:
                return r
        return None

    def _add_rule(self) -> None:
        RoutingRuleSheet(self.parent_window, None, self._rule_added).show_all()

    def _rule_added(self, rule: RoutingRule | None) -> None:
        if rule is not None:
            self.config.rules.append(rule)
            self._changed()

    def _edit_selected(self) -> None:
        rule = self._selected_rule()
        if rule is not None:
            RoutingRuleSheet(self.parent_window, rule, self._rule_edited).show_all()

    def _rule_edited(self, updated: RoutingRule | None) -> None:
        if updated is None:
            self.config.rules = [r for r in self.config.rules if r.id != (
                self._selected_rule().id if self._selected_rule() else "")]
        else:
            for i, r in enumerate(self.config.rules):
                if r.id == updated.id:
                    self.config.rules[i] = updated
                    break
        self._changed()

    def _on_row_activated(self, _box, _row) -> None:
        self._edit_selected()

    def _move(self, delta: int) -> None:
        rule = self._selected_rule()
        if rule is None:
            return
        idx = self.config.rules.index(rule)
        new = idx + delta
        if 0 <= new < len(self.config.rules):
            self.config.rules[idx], self.config.rules[new] = \
                self.config.rules[new], self.config.rules[idx]
            self._changed()

    def _changed(self) -> None:
        self._reload()
        self.on_change(self.config)