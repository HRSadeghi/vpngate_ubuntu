"""Dialogs (ports of ServerDetailsSheet and AcademicDisclaimerSheet) plus the one-time
helper setup alert."""

from __future__ import annotations

import gi
gi.require_version("Gtk", "3.0")
from gi.repository import Gtk  # noqa: E402

from ...core.serverlist import VPNServer
from ..formatting import speed


def _detail_row(grid, row, title, value):
    t = Gtk.Label(xalign=0)
    t.set_markup(f'<span foreground="gray">{title}</span>')
    v = Gtk.Label(xalign=0)
    v.set_text(str(value))
    v.set_selectable(True)
    v.set_line_wrap(True)
    grid.attach(t, 0, row, 1, 1)
    grid.attach(v, 1, row, 1, 1)
    return row + 1


def show_server_details(parent, server: VPNServer) -> None:
    dialog = Gtk.Dialog(title=f"{server.flag} {server.hostName}".strip(), transient_for=parent,
                        modal=True)
    dialog.add_button("_Done", Gtk.ResponseType.OK)
    dialog.set_default_size(520, 480)
    scrolled = Gtk.ScrolledWindow()
    scrolled.set_policy(Gtk.PolicyType.AUTOMATIC, Gtk.PolicyType.AUTOMATIC)
    grid = Gtk.Grid(column_spacing=12, row_spacing=8, margin_start=14, margin_end=14,
                    margin_top=12, margin_bottom=12)
    row = 0
    row = _detail_row(grid, row, "DDNS Hostname:", server.fqdn)
    row = _detail_row(grid, row, "IP Address:", server.ip)
    row = _detail_row(grid, row, "Country:", f"{server.countryLong} ({server.countryShort})")
    row = _detail_row(grid, row, "Line Speed:", speed(server.speed))
    row = _detail_row(grid, row, "Score:", server.score)
    row = _detail_row(grid, row, "Ping to Japan:", f"{server.ping} ms")
    row = _detail_row(grid, row, "Ping to Google:",
                      "-" if server.pingToGoogle == 0 else f"{server.pingToGoogle} ms")
    row = _detail_row(grid, row, "UDP port:", server.udpPort if server.udpPort else "-")
    row = _detail_row(grid, row, "SSL-VPN Ports:",
                      "Default (443)" if not server.sslPorts
                      else ", ".join(str(p) for p in server.prioritized_ssl_ports))
    row = _detail_row(grid, row, "OpenVPN UDP Ports:",
                      "None" if not server.openvpnUdpPorts
                      else ", ".join(str(p) for p in server.openvpnUdpPorts))
    row = _detail_row(grid, row, "L2TP / IPsec:",
                      "Supported" if server.l2tp else "Not supported")
    row = _detail_row(grid, row, "Logging Policy:", server.logType)
    row = _detail_row(grid, row, "Operator / Owner:", server.operatorName or "Anonymous")
    if server.abuse:
        row = _detail_row(grid, row, "Abuse Contact:", server.abuse)
    if server.os:
        row = _detail_row(grid, row, "Operating System:", server.os)
    if server.build is not None:
        row = _detail_row(grid, row, "SoftEther Build:", server.build)
    if server.message:
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
        head = Gtk.Label(xalign=0)
        head.set_markup("<b>Server Message:</b>")
        msg = Gtk.Label(xalign=0)
        msg.set_text(server.message)
        msg.set_line_wrap(True)
        msg.set_selectable(True)
        frame = Gtk.Frame()
        frame.add(msg)
        frame.set_margin_top(4)
        box.pack_start(head, False, False, 0)
        box.pack_start(frame, False, False, 0)
        grid.attach(box, 0, row, 2, 1)
        row += 1
    scrolled.add(grid)
    dialog.get_content_area().pack_start(scrolled, True, True, 0)
    dialog.show_all()
    dialog.run()
    dialog.destroy()


def show_disclaimer(parent, model) -> None:
    """The academic-use disclaimer must be accepted before any connection starts."""
    dialog = Gtk.Dialog(title="VPN Gate Academic Experiment Service", transient_for=parent,
                        modal=True)
    dialog.set_resizable(False)
    dialog.set_size_request(500, -1)
    box = dialog.get_content_area()
    box.set_spacing(12)
    box.set_margin_start(24)
    box.set_margin_end(24)
    box.set_margin_top(18)
    box.set_margin_bottom(18)

    icon = Gtk.Label()
    icon.set_markup('<span size="30000">🎓</span>')
    box.pack_start(icon, False, False, 0)
    title = Gtk.Label()
    title.set_markup("<big><b>VPN Gate Academic Experiment Service</b></big>")
    box.pack_start(title, False, False, 0)
    text = Gtk.Label()
    text.set_markup(
        "VPN Gate is an academic research project of the Graduate School of University of "
        "Tsukuba, Japan.\n\nPublic VPN relay servers are hosted by volunteers around the world. "
        "Anyone can connect through these servers to achieve anonymity and bypass censorship."
        "\n\nBy clicking “Agree and Continue”, you confirm that you will use this service in "
        "compliance with local laws.")
    text.set_justify(Gtk.Justification.CENTER)
    box.pack_start(text, False, False, 0)
    note = Gtk.Label()
    note.set_markup('<small><span foreground="gray">Optional diagnostics upload is off and can '
                    'be turned on in Settings → Advanced.</span></small>')
    box.pack_start(note, False, False, 0)

    buttons = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
    decline = Gtk.Button(label="Disagree & Quit")
    decline.connect("clicked", lambda _b: (model.decline_disclaimer(), parent.get_application().quit()))
    buttons.pack_start(decline, False, False, 0)
    agree = Gtk.Button(label="Agree and Continue")
    agree.get_style_context().add_class("suggested-action")
    agree.connect("clicked", lambda _b: (model.agree_to_disclaimer(), dialog.destroy()))
    buttons.pack_end(agree, False, False, 0)
    box.pack_start(buttons, False, False, 0)

    dialog.show_all()
    dialog.run()
    dialog.destroy()
    if not model.has_agreed_to_disclaimer:
        parent.get_application().quit()


def show_setup_alert(parent, model) -> None:
    """One-time setup: the helper is missing or outdated."""
    update = model.setup_prompt == "update"
    dialog = Gtk.MessageDialog(
        transient_for=parent, modal=True,
        message_type=Gtk.MessageType.QUESTION,
        text="Update the VPN component?" if update else "One-time setup",
        secondary_text=(
            "The installed helper predates this app. Updating it fixes connection issues.\n\n"
            if update else
            "VPN Gate needs a small background component to create the VPN connection. The system "
            "will ask for your password once. After that, VPN Gate connects by itself.\n\n"))
    dialog.add_button("Not Now", Gtk.ResponseType.CANCEL)
    dialog.add_button("Continue", Gtk.ResponseType.OK)
    dialog.set_default_response(Gtk.ResponseType.OK)
    response = dialog.run()
    dialog.destroy()
    if response == Gtk.ResponseType.OK:
        model.begin_setup()
    else:
        model.cancel_setup()


def show_notice(parent, message: str) -> None:
    dialog = Gtk.MessageDialog(transient_for=parent, modal=True,
                               message_type=Gtk.MessageType.INFO, buttons=Gtk.ButtonsType.OK,
                               text=message)
    dialog.run()
    dialog.destroy()