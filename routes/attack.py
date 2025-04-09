from flask import Blueprint, request, jsonify
from flask_login import login_required, current_user
import sys

from scripts import arp_poison, icmp_redirect, dhcp_spoof  # import the run functions

attack_bp = Blueprint("attack", __name__)

@attack_bp.route("/attack/arp_poison", methods=["POST"])
@login_required
def trigger_arp_poison():
    if not current_user.is_admin:
        return jsonify({"error": "Admin privileges required"}), 403

    data = request.get_json()
    target_ip = data.get("target_ip")
    gateway_ip = data.get("gateway_ip")

    output = arp_poison.run(target_ip, gateway_ip)
    return jsonify({"message": "ARP Poisoning triggered", "output": output})


@attack_bp.route("/attack/icmp_redirect", methods=["POST"])
@login_required
def trigger_icmp_redirect():
    if not current_user.is_admin:
        return jsonify({"error": "Admin privileges required"}), 403

    data = request.get_json()
    target_ip = data.get("target_ip")
    real_gw = data.get("real_gw")
    fake_gw = data.get("fake_gw")

    output = icmp_redirect.run(target_ip, real_gw, fake_gw)
    return jsonify({"message": "ICMP Redirect sent", "output": output})


@attack_bp.route("/attack/dhcp_spoof", methods=["POST"])
@login_required
def trigger_dhcp_spoof():
    if not current_user.is_admin:
        return jsonify({"error": "Admin privileges required"}), 403

    data = request.get_json()
    spoofed_ip = data.get("spoofed_ip")
    spoofed_gw = data.get("spoofed_gw")

    output = dhcp_spoof.run(spoofed_ip, spoofed_gw)
    return jsonify({"message": "DHCP Spoofing triggered", "output": output})

