"""VPN Connection Settings window and the account editor (ports of AccountsView.swift,
AccountEditor.swift and AccountEditorState.swift)."""

from __future__ import annotations

import gi
gi.require_version("Gtk", "3.0")
from gi.repository import Gtk  # noqa: E402

from ...core.clientaccount import AccountAuthType, ClientAccount
from ...core.ipcmessages import ConnectionState
from ...core.validation import (is_valid_host, is_valid_identity_field, normalized_fingerprint,
                                parse_mac_address)
from ..certimport import CertImportError, identity as cert_identity, import_pkcs12
from .routing import RoutingRulesEditor


class AccountEditorDialog(Gtk.Dialog):
    """New/Edit VPN Connection Setting."""

    def __init__(self, parent, manager, account: ClientAccount | None, on_saved) -> None:
        self.manager = manager
        self.base = account
        self.on_saved = on_saved
        self.has_stored_identity = account is not None and manager.has_certificate_identity(account)
        self.cert_der: bytes | None = None
        self.private_key_der: bytes | None = None
        self.import_error: str | None = None
        super().__init__(title="Edit VPN Connection Setting" if account else "New VPN Connection Setting",
                         transient_for=parent, modal=True)
        self.add_button("_Cancel", Gtk.ResponseType.CANCEL)
        save_btn = self.add_button("_Save", Gtk.ResponseType.OK)
        save_btn.get_style_context().add_class("suggested-action")
        self.set_default_response(Gtk.ResponseType.OK)
        self.set_size_request(560, 640)

        scrolled = Gtk.ScrolledWindow()
        scrolled.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
        grid = Gtk.Grid(column_spacing=12, row_spacing=8, margin_start=16, margin_end=16,
                        margin_top=14, margin_bottom=14)
        scrolled.add(grid)
        self.get_content_area().pack_start(scrolled, True, True, 0)

        row = self._heading(grid, 0, "General Setting")
        self.name_entry = self._text_row(grid, row, "Setting Name:",
                                         account.name if account else "New Connection")
        self.name_entry.connect("changed", lambda _e: self._update_can_save())
        row += 1

        row = self._heading(grid, row + 1, "Destination VPN Server")
        self.host_entry = self._text_row(grid, row, "Host Name / IP Address:",
                                         account.host if account else "")
        self.host_entry.connect("changed", lambda _e: self._update_can_save())
        row += 1
        ports = ", ".join(str(p) for p in (account.portList if account else [443, 992, 5555, 1194]))
        self.ports_entry = self._text_row(grid, row, "Port Number (comma separated):", ports)
        row += 1
        self.hub_entry = self._text_row(grid, row, "Virtual HUB Name:",
                                        account.hub if account else "DEFAULT")
        self.hub_entry.connect("changed", lambda _e: self._update_can_save())
        row += 1

        row = self._heading(grid, row + 1, "User Authentication Setting")
        grid.attach(Gtk.Label(label="Auth Type:", xalign=0), 0, row, 1, 1)
        self.auth_combo = Gtk.ComboBoxText()
        for t in AccountAuthType.ALL:
            self.auth_combo.append(t, t)
        self.auth_combo.set_active_id(account.authType if account else AccountAuthType.PASSWORD)
        self.auth_combo.connect("changed", lambda _c: self._auth_changed())
        grid.attach(self.auth_combo, 1, row, 1, 1)
        row += 1
        self.user_entry = self._text_row(grid, row, "User Name:", account.username if account else "")
        self.user_entry.connect("changed", lambda _e: self._update_can_save())
        row += 1
        self.pass_entry = Gtk.Entry()
        self.pass_entry.set_visibility(False)
        self.pass_entry.set_placeholder_text("Password:")
        if account:
            self.pass_entry.set_text(manager.password(account) or "")
        grid.attach(Gtk.Label(label="Password:", xalign=0), 0, row, 1, 1)
        grid.attach(self.pass_entry, 1, row, 1, 1)
        self._pass_row = row
        row += 1

        # Certificate section
        self.cert_label = Gtk.Label(xalign=0)
        self.cert_label.set_line_wrap(True)
        self.cert_label.get_style_context().add_class("dim-label")
        self.cert_label.set_markup("<small>No certificate yet. Import a PEM/DER certificate with "
                                   "its RSA key, or a .p12 file.</small>")
        grid.attach(self.cert_label, 0, row, 2, 1)
        self._cert_label_row = row
        row += 1
        buttons = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        pem_btn = Gtk.Button(label="Certificate + Key (PEM/DER)…")
        pem_btn.connect("clicked", self._import_pem)
        p12_btn = Gtk.Button(label="PKCS#12 (.p12)…")
        p12_btn.connect("clicked", self._import_p12)
        buttons.pack_start(pem_btn, False, False, 0)
        buttons.pack_start(p12_btn, False, False, 0)
        grid.attach(buttons, 0, row, 2, 1)
        self._cert_buttons_row = row
        row += 1
        grid.attach(Gtk.Label(label="Passphrase for the .p12 file:", xalign=0), 0, row, 1, 1)
        self.p12_pass_entry = Gtk.Entry()
        self.p12_pass_entry.set_visibility(False)
        grid.attach(self.p12_pass_entry, 1, row, 1, 1)
        row += 1
        self.import_error_label = Gtk.Label(xalign=0)
        self.import_error_label.set_markup('<span foreground="red" size="small"></span>')
        grid.attach(self.import_error_label, 0, row, 2, 1)
        row += 1

        # Advanced options — folded away until asked for (the macOS form's disclosure).
        row = self._heading(grid, row + 1, "Advanced Options")
        self.advanced = Gtk.Grid(column_spacing=12, row_spacing=8)
        self.advanced.set_hexpand(True)
        self.advanced.set_margin_top(4)
        adv_expander = Gtk.Expander(label="Advanced Options")
        adv_expander.add(self.advanced)
        grid.attach(adv_expander, 0, row, 2, 1)
        arow = 0
        max_conn = Gtk.SpinButton.new_with_range(1, 32, 1)
        max_conn.set_value(account.maxConnection if account else 1)
        self.advanced.attach(Gtk.Label(label="Max TCP Connections:", xalign=0), 0, arow, 1, 1)
        self.advanced.attach(max_conn, 1, arow, 1, 1)
        self.max_conn_spin = max_conn
        arow += 1
        self.compression_check = self._advanced_check(arow, "Use Data Compression",
                                                      account.compression if account else False)
        self.advanced.attach(self.compression_check, 0, arow, 2, 1)
        arow += 1
        self.udp_check = self._advanced_check(arow, "Use UDP Acceleration (Fastest)",
                                              account.udpAcceleration if account else True)
        self.advanced.attach(self.udp_check, 0, arow, 2, 1)
        arow += 1
        self.qos_check = self._advanced_check(arow, "Use QoS",
                                              not (account.disableQoS if account else False))
        self.advanced.attach(self.qos_check, 0, arow, 2, 1)
        arow += 1
        self.half_check = self._advanced_check(
            arow, "Use Half Connection (separate send/receive sockets)",
            account.halfConnection if account else False)
        self.advanced.attach(self.half_check, 0, arow, 2, 1)
        arow += 1
        self.mtu_entry = Gtk.Entry()
        self.mtu_entry.set_placeholder_text("blank = automatic (DHCP option 26)")
        self.mtu_entry.set_text(str(account.mtu) if (account and account.mtu) else "")
        self.advanced.attach(Gtk.Label(label="MTU:", xalign=0), 0, arow, 1, 1)
        self.advanced.attach(self.mtu_entry, 1, arow, 1, 1)
        arow += 1
        self.mac_entry = Gtk.Entry()
        self.mac_entry.set_placeholder_text("blank = random (aa:bb:cc:dd:ee:ff)")
        self.mac_entry.set_text(account.virtualMacAddress if account and account.virtualMacAddress else "")
        self.advanced.attach(Gtk.Label(label="Virtual MAC address:", xalign=0), 0, arow, 1, 1)
        self.advanced.attach(self.mac_entry, 1, arow, 1, 1)
        arow += 1
        self.cert_check = self._advanced_check(arow, "Verify Server Certificate",
                                               account.checkServerCert if account else False)
        self.advanced.attach(self.cert_check, 0, arow, 2, 1)
        arow += 1
        self.fingerprint_entry = Gtk.Entry()
        self.fingerprint_entry.set_placeholder_text("SHA-1 / SHA-256, optional (enforced when set)")
        self.fingerprint_entry.set_text(account.serverCertFingerprint or "" if account else "")
        self.advanced.attach(Gtk.Label(label="Server certificate fingerprint:", xalign=0), 0, arow, 1, 1)
        self.advanced.attach(self.fingerprint_entry, 1, arow, 1, 1)
        arow += 1
        self.autoreconnect_check = self._advanced_check(
            arow, "Auto Reconnect on disconnect",
            account.autoReconnect if account else True)
        self.advanced.attach(self.autoreconnect_check, 0, arow, 2, 1)
        arow += 1
        retry_spin = Gtk.SpinButton.new_with_range(1, 300, 1)
        retry_spin.set_value(int(account.reconnectInterval) if account else 3)
        self.advanced.attach(Gtk.Label(label="Retry every (s):", xalign=0), 0, arow, 1, 1)
        self.advanced.attach(retry_spin, 1, arow, 1, 1)
        self.retry_spin = retry_spin
        arow += 1
        count_spin = Gtk.SpinButton.new_with_range(1, 1000, 1)
        count_spin.set_value(account.reconnectCount if account else 8)
        self.advanced.attach(Gtk.Label(label="Give up after attempts:", xalign=0), 0, arow, 1, 1)
        self.advanced.attach(count_spin, 1, arow, 1, 1)
        self.count_spin = count_spin
        arow += 1

        # Routing section
        row = self._heading(grid, row + 1, "Routing")
        self.custom_routing_check = Gtk.CheckButton(
            label="Use custom routing rules for this connection")
        self.custom_routing_check.set_active(account.routing is not None if account else False)
        self.custom_routing_check.connect("toggled", lambda c: self._routing_visibility())
        grid.attach(self.custom_routing_check, 0, row, 2, 1)
        row += 1
        routing_hint = Gtk.Label(xalign=0)
        routing_hint.get_style_context().add_class("dim-label")
        routing_hint.set_markup("<small>When off, the app's global routing rules apply "
                                "(Settings → Routing).</small>")
        grid.attach(routing_hint, 0, row, 2, 1)
        row += 1
        self.routing_editor = RoutingRulesEditor(
            account.routing if account and account.routing is not None else
            __import__("vpngate.core.routing", fromlist=["RoutingConfig"]).RoutingConfig(),
            lambda cfg: None, parent_window=parent)
        self.routing_editor.set_size_request(-1, 260)
        grid.attach(self.routing_editor, 0, row, 2, 1)
        self._routing_row = row

        self._auth_changed()
        self._update_can_save()
        self.connect("response", self._on_response)

    # MARK: helpers

    def _heading(self, grid, row, title) -> int:
        head = Gtk.Label(xalign=0)
        head.set_markup(f"<b>{title}</b>")
        grid.attach(head, 0, row, 2, 1)
        return row + 1

    def _text_row(self, grid, row, title, value) -> Gtk.Entry:
        grid.attach(Gtk.Label(label=title, xalign=0), 0, row, 1, 1)
        entry = Gtk.Entry()
        entry.set_text(value)
        entry.set_hexpand(True)
        grid.attach(entry, 1, row, 1, 1)
        return entry

    def _advanced_check(self, row, label, value) -> Gtk.CheckButton:
        check = Gtk.CheckButton(label=label)
        check.set_active(value)
        return check

    def _auth_changed(self) -> None:
        cert = self.auth_combo.get_active_id() == AccountAuthType.CERTIFICATE
        password = self.auth_combo.get_active_id() in (AccountAuthType.PASSWORD,
                                                       AccountAuthType.PLAIN_PASSWORD)
        for widget in (self.cert_label, self.p12_pass_entry):
            widget.set_visible(cert)
        self.pass_entry.set_visible(password)
        self._update_cert_label()
        self._update_can_save()

    def _routing_visibility(self) -> None:
        self.routing_editor.set_sensitive(self.custom_routing_check.get_active())

    def _update_cert_label(self) -> None:
        cert = self.auth_combo.get_active_id() == AccountAuthType.CERTIFICATE
        if not cert:
            return
        if self.cert_der is not None and self.private_key_der is not None:
            text = "Certificate and RSA key ready to save."
        elif self.has_stored_identity:
            text = ("A certificate and key are stored in the secret store. Import again to "
                    "replace them.")
        else:
            text = ("No certificate yet. Import a PEM/DER certificate with its RSA key, or a "
                    ".p12 file.")
        self.cert_label.set_markup(f"<small>{text}</small>")

    def _set_import_error(self, message: str | None) -> None:
        self.import_error = message
        self.import_error_label.set_markup(
            f'<span foreground="red" size="small">{message or ""}</span>')

    def _import_pem(self, _btn) -> None:
        cert_data = self._pick_file("Choose the certificate (PEM or DER)")
        if cert_data is None:
            return
        key_data = self._pick_file("Choose its RSA private key (PEM or DER, not "
                                   "passphrase-protected)")
        if key_data is None:
            return
        try:
            c, k = cert_identity(cert_data, key_data)
            self.cert_der, self.private_key_der = c, k
            self._set_import_error(None)
        except CertImportError as e:
            self._set_import_error(e.message)
        self._update_cert_label()
        self._update_can_save()

    def _import_p12(self, _btn) -> None:
        data = self._pick_file("Choose the PKCS#12 file (.p12 / .pfx)")
        if data is None:
            return
        try:
            c, k = import_pkcs12(data, self.p12_pass_entry.get_text())
            self.cert_der, self.private_key_der = c, k
            self._set_import_error(None)
        except CertImportError as e:
            self._set_import_error(e.message)
        self._update_cert_label()
        self._update_can_save()

    def _pick_file(self, title: str) -> bytes | None:
        dialog = Gtk.FileChooserDialog(title=title, transient_for=self, modal=True,
                                       action=Gtk.FileChooserAction.OPEN)
        dialog.add_button("_Cancel", Gtk.ResponseType.CANCEL)
        dialog.add_button("_Open", Gtk.ResponseType.OK)
        response = dialog.run()
        path = dialog.get_filename()
        dialog.destroy()
        if response != Gtk.ResponseType.OK or not path:
            return None
        try:
            with open(path, "rb") as f:
                return f.read()
        except OSError as e:
            self._set_import_error(str(e))
            return None

    # MARK: validation & save

    def _parsed_ports(self) -> list[int]:
        out = []
        for tok in self.ports_entry.get_text().split(","):
            tok = tok.strip()
            try:
                p = int(tok)
                if 0 < p < 65536 and p not in out:
                    out.append(p)
            except ValueError:
                continue
        return out

    def _errors(self) -> str | None:
        if not self.name_entry.get_text().strip():
            return "Setting name is required."
        host = self.host_entry.get_text().strip()
        if not host or not is_valid_host(host):
            return "Host name or IP address is not valid."
        hub = self.hub_entry.get_text().strip() or "DEFAULT"
        if not is_valid_identity_field(hub):
            return "Virtual HUB name is not valid (at most 255 bytes, no NUL)."
        if not is_valid_identity_field(self.user_entry.get_text().strip()):
            return "User name is not valid."
        fp = self.fingerprint_entry.get_text().strip()
        if fp and normalized_fingerprint(fp) is None:
            return "Fingerprint must be 40 (SHA-1) or 64 (SHA-256) hex digits."
        cert = self.auth_combo.get_active_id() == AccountAuthType.CERTIFICATE
        if cert and self.cert_der is None and self.private_key_der is None \
                and not self.has_stored_identity:
            return "Certificate login needs an imported certificate and RSA private key."
        mtu = self.mtu_entry.get_text().strip()
        if mtu:
            try:
                v = int(mtu)
                if not 576 <= v <= 1500:
                    raise ValueError
            except ValueError:
                return "MTU must be 576–1500, or blank for automatic."
        mac = self.mac_entry.get_text().strip()
        if mac and parse_mac_address(mac) is None:
            return "MAC must be 6 hex byte pairs, e.g. 00:AC:DE:12:34:56."
        return None

    def _update_can_save(self) -> None:
        self.set_response_sensitive(Gtk.ResponseType.OK, self._errors() is None)

    def _make_account(self) -> ClientAccount:
        base = self.base
        acc = ClientAccount.from_json(base.to_json()) if base else ClientAccount(name="", host="")
        ports = self._parsed_ports()
        acc.name = self.name_entry.get_text().strip()
        acc.host = self.host_entry.get_text().strip()
        acc.portList = ports or [443]
        acc.hub = self.hub_entry.get_text().strip() or "DEFAULT"
        acc.username = self.user_entry.get_text().strip()
        acc.authType = self.auth_combo.get_active_id() or AccountAuthType.PASSWORD
        acc.checkServerCert = self.cert_check.get_active()
        acc.serverCertFingerprint = normalized_fingerprint(
            self.fingerprint_entry.get_text().strip()) if self.fingerprint_entry.get_text().strip() else None
        acc.maxConnection = int(self.max_conn_spin.get_value())
        acc.compression = self.compression_check.get_active()
        acc.udpAcceleration = self.udp_check.get_active()
        acc.disableQoS = not self.qos_check.get_active()
        acc.halfConnection = self.half_check.get_active()
        acc.autoReconnect = self.autoreconnect_check.get_active()
        acc.reconnectInterval = float(int(self.retry_spin.get_value()))
        acc.reconnectCount = int(self.count_spin.get_value())
        mtu = self.mtu_entry.get_text().strip()
        acc.mtu = int(mtu) if mtu else None
        mac = self.mac_entry.get_text().strip()
        acc.virtualMacAddress = mac or None
        acc.routing = self.routing_editor.config if self.custom_routing_check.get_active() else None
        return acc

    def _on_response(self, dialog, response) -> None:
        if response != Gtk.ResponseType.OK:
            self.destroy()
            return
        error = self._errors()
        if error is not None:
            from .dialogs import show_notice
            show_notice(self, error)
            return
        acc = self._make_account()
        is_cert = acc.authType == AccountAuthType.CERTIFICATE
        self.on_saved(acc,
                      self.pass_entry.get_text() or None,
                      self.cert_der if is_cert else None,
                      self.private_key_der if is_cert else None)
        self.destroy()


class AccountsWindow(Gtk.ApplicationWindow):
    def __init__(self, app, model, **kwargs):
        super().__init__(application=app, title="VPN Connection Settings", **kwargs)
        self.app = app
        self.model = model
        self.manager = model.account_manager
        self.set_default_size(760, 460)

        outer = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=0)
        self.add(outer)

        toolbar = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
        toolbar.set_margin_start(12)
        toolbar.set_margin_end(12)
        toolbar.set_margin_top(8)
        toolbar.set_margin_bottom(8)

        def tool_button(label, icon, callback):
            box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
            box.pack_start(Gtk.Image.new_from_icon_name(icon, Gtk.IconSize.BUTTON), False, False, 0)
            box.pack_start(Gtk.Label(label=label), False, False, 0)
            btn = Gtk.Button()
            btn.add(box)
            btn.connect("clicked", callback)
            return btn

        toolbar.pack_start(tool_button("New Setting", "list-add-symbolic",
                                       lambda _b: self._edit(None)), False, False, 0)
        toolbar.pack_start(Gtk.Separator(orientation=Gtk.Orientation.VERTICAL), False, False, 0)
        self.connect_btn = tool_button("Connect", "system-shutdown-symbolic",
                                       lambda _b: self._connect_selected())
        toolbar.pack_start(self.connect_btn, False, False, 0)
        disconnect_btn = tool_button("Disconnect", "system-shutdown-symbolic",
                                     lambda _b: self.model.disconnect())
        toolbar.pack_start(disconnect_btn, False, False, 0)
        toolbar.pack_start(Gtk.Separator(orientation=Gtk.Orientation.VERTICAL), False, False, 0)
        toolbar.pack_start(tool_button("Properties", "document-edit-symbolic",
                                       lambda _b: self._edit(self._selected())), False, False, 0)
        toolbar.pack_start(tool_button("Delete", "user-trash-symbolic",
                                       lambda _b: self._delete()), False, False, 0)
        outer.pack_start(toolbar, False, False, 0)
        outer.pack_start(Gtk.Separator(), False, False, 0)

        # The Windows Client Manager lists "VPN Gate Public VPN Relay Servers" as its first row.
        vg_row = Gtk.ListBox()
        vg_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10, margin_start=14,
                         margin_end=14, margin_top=8, margin_bottom=8)
        globe = Gtk.Label()
        globe.set_markup('<span size="14000">🌐</span>')
        vg_box.pack_start(globe, False, False, 0)
        left = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=1)
        t = Gtk.Label(xalign=0)
        t.set_markup("<b>VPN Gate Public VPN Relay Servers</b>")
        left.pack_start(t, False, False, 0)
        s = Gtk.Label(xalign=0)
        s.get_style_context().add_class("dim-label")
        s.set_markup("<small>Free servers run by volunteers — open the list</small>")
        left.pack_start(s, False, False, 0)
        vg_box.pack_start(left, True, True, 0)
        row = Gtk.ListBoxRow()
        row.set_selectable(False)
        row.add(vg_box)
        row.connect("activate", lambda _r: self.app.open_main())
        vg_row.append(row)
        outer.pack_start(vg_row, False, False, 0)
        outer.pack_start(Gtk.Separator(), False, False, 0)

        if self.manager.load_notice:
            notice = Gtk.Label(xalign=0)
            notice.set_line_wrap(True)
            notice.set_markup(f'<small><span foreground="orange">'
                              f'{self.manager.load_notice}</span></small>')
            notice.set_margin_start(12)
            notice.set_margin_top(4)
            outer.pack_start(notice, False, False, 0)

        self.store = Gtk.ListStore(str, str, str, str, str)  # id, name, status, host, hub
        self.tree = Gtk.TreeView(model=self.store)
        for i, title in enumerate(("VPN Connection Setting Name", "Status",
                                   "VPN Server Hostname", "Virtual Hub")):
            col = Gtk.TreeViewColumn(title, Gtk.CellRendererText(), text=i + 1)
            col.set_resizable(True)
            if i == 0:
                col.set_expand(True)
            self.tree.append_column(col)
        self.tree.get_selection().connect("changed", lambda _s: self._update_buttons())
        scrolled = Gtk.ScrolledWindow()
        scrolled.set_policy(Gtk.PolicyType.AUTOMATIC, Gtk.PolicyType.AUTOMATIC)
        scrolled.set_vexpand(True)
        scrolled.add(self.tree)
        outer.pack_start(scrolled, True, True, 0)
        self.empty_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
        self.empty_box.set_valign(Gtk.Align.CENTER)
        self.empty_box.set_vexpand(True)
        empty_title = Gtk.Label()
        empty_title.set_markup('<span foreground="gray"><b>No VPN connection settings yet</b>'
                               '</span>')
        empty_sub = Gtk.Label(label="Add one to connect to your own SoftEther VPN server.")
        empty_sub.get_style_context().add_class("dim-label")
        empty_btn = Gtk.Button(label="New Setting…")
        empty_btn.connect("clicked", lambda _b: self._edit(None))
        self.empty_box.pack_start(empty_title, False, False, 0)
        self.empty_box.pack_start(empty_sub, False, False, 0)
        self.empty_box.pack_start(empty_btn, False, False, 0)
        outer.pack_start(self.empty_box, False, False, 8)

        self._sync()
        self._unsubscribe = self.manager.changed.connect(lambda: GLibIdle(self._sync))
        self.connect("destroy", self._on_destroy)

    def _on_destroy(self, *_a):
        self._unsubscribe()

    def _sync(self) -> bool:
        self.store.clear()
        state = self.model.event.state
        for acc in self.manager.accounts:
            if self.model.active_account is not None and acc.id == self.model.active_account.id:
                if state == ConnectionState.connected:
                    status = "● Connected"
                elif state == ConnectionState.reconnecting:
                    status = "● Reconnecting…"
                elif state == ConnectionState.disconnected:
                    status = "Offline"
                else:
                    status = "● Connecting"
            else:
                status = "Offline"
            self.store.append([acc.id, acc.name, status,
                               f"{acc.host}:{acc.portList[0] if acc.portList else 443}", acc.hub])
        self.empty_box.set_visible(not self.manager.accounts)
        self._update_buttons()
        return False

    def _update_buttons(self) -> None:
        has = self._selected() is not None
        idle = self.model.event.state == ConnectionState.disconnected
        self.connect_btn.set_sensitive(has and idle)

    def _selected(self) -> ClientAccount | None:
        model, iter_ = self.tree.get_selection().get_selected()
        if iter_ is None:
            return None
        acc_id = model[iter_][0]
        for acc in self.manager.accounts:
            if acc.id == acc_id:
                return acc
        return None

    def _connect_selected(self) -> None:
        acc = self._selected()
        if acc is not None:
            self.model.connect_account(acc)

    def _edit(self, account: ClientAccount | None) -> None:
        def saved(updated, password, cert, key):
            if account is not None:
                self.manager.update(updated, password=password, cert_der=cert,
                                    private_key_der=key)
            else:
                self.manager.add(updated, password=password, cert_der=cert, private_key_der=key)
        AccountEditorDialog(self, self.manager, account, saved).show_all()

    def _duplicate(self) -> None:
        acc = self._selected()
        if acc is not None:
            self.manager.duplicate(acc)

    def _delete(self) -> None:
        acc = self._selected()
        if acc is None:
            return
        dialog = Gtk.MessageDialog(transient_for=self, modal=True,
                                   message_type=Gtk.MessageType.QUESTION,
                                   text=f"Delete “{acc.name}”?",
                                   secondary_text="The saved secrets for this connection are "
                                                  "removed too.")
        dialog.add_button("_Cancel", Gtk.ResponseType.CANCEL)
        dialog.add_button("_Delete", Gtk.ResponseType.OK)
        if dialog.run() == Gtk.ResponseType.OK:
            self.manager.delete(acc)
        dialog.destroy()


class GLibIdle:
    """Marshals a call onto the GTK main loop (model callbacks arrive on worker threads)."""

    def __init__(self, fn) -> None:
        from gi.repository import GLib
        GLib.idle_add(self._run, fn)

    def _run(self, fn) -> bool:
        try:
            fn()
        except Exception:
            import traceback
            traceback.print_exc()
        return False