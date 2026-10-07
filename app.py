# app.py
import os
import time
import json
import queue
import random
import math
import socket
import threading
import asyncio
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Dict, List, Tuple, Optional, Any
from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
import joblib
import numpy as np
import pandas as pd

BASE_DIR = Path(__file__).resolve().parent

# Global ML State
MODEL_LOADED = False
model = None
scaler = None
features = ['DST_PORT', 'FLOW_DURATION', 'FWD_PKTS', 'BWD_PKTS', 'FWD_BYTES', 'BWD_BYTES']

try:
    model_path = BASE_DIR / 'cyber_threat_model.pkl'
    scaler_path = BASE_DIR / 'cyber_scaler.pkl'
    feat_path = BASE_DIR / 'cyber_features.pkl'

    if model_path.exists() and scaler_path.exists():
        model = joblib.load(model_path)
        scaler = joblib.load(scaler_path)
        if feat_path.exists():
            loaded_feats = joblib.load(feat_path)
            if isinstance(loaded_feats, list) and len(loaded_feats) > 0:
                features = loaded_feats
        MODEL_LOADED = True
        print("[ML] Intrusion detection model and scaler loaded successfully.")
    else:
        print("[ML] [WARN] Serialized model files not found. Running in rule-based fallback mode.")
except Exception as e:
    print(f"[ML] [ERROR] Error loading ML artifacts: {e}. System running in rule-based fallback mode.")

# Scapy Availability Check
SCAPY_AVAILABLE = False
try:
    from scapy.all import sniff, IP, TCP, UDP, conf, get_if_list
    SCAPY_AVAILABLE = True
    print("[SNIFFER] Scapy packet sniffer library available.")
except Exception as e:
    print(f"[SNIFFER] [WARN] Scapy not available: {e}. Socket / simulation fallback enabled.")

# Global Thread-safe alert queues for SSE
connected_clients: List[queue.Queue] = []
connected_clients_lock = threading.Lock()

def calculate_entropy(ports: List[int]) -> float:
    if not ports:
        return 0.0
    from collections import Counter
    counts = Counter(ports)
    total = len(ports)
    entropy = 0.0
    for count in counts.values():
        p = count / total
        entropy -= p * math.log2(p)
    return entropy

def broadcast_alert(alert_data: dict):
    with connected_clients_lock:
        for q in connected_clients:
            try:
                q.put_nowait(alert_data)
            except Exception:
                pass


def list_system_interfaces() -> List[Dict[str, str]]:
    """
    Enumerate all network interfaces on the host (Windows / Linux / macOS).
    """
    interfaces = []
    
    if SCAPY_AVAILABLE:
        try:
            # On Windows, try to get friendly names from Windows if list
            if os.name == 'nt':
                try:
                    from scapy.arch.windows import get_windows_if_list
                    win_ifs = get_windows_if_list()
                    for item in win_ifs:
                        name = item.get("name") or item.get("guid") or "Unknown"
                        desc = item.get("description") or name
                        ips = item.get("ips") or []
                        ip_str = f" ({', '.join(ips)})" if ips else ""
                        interfaces.append({
                            "id": name,
                            "name": f"{desc}{ip_str}",
                            "guid": item.get("guid", "")
                        })
                except Exception:
                    pass
            
            # Standard Scapy interface enumeration if empty
            if not interfaces:
                for iface in get_if_list():
                    interfaces.append({
                        "id": str(iface),
                        "name": str(iface),
                        "guid": ""
                    })
        except Exception as e:
            print(f"[SNIFFER] Interface enumeration warning: {e}")

    # Fallback to standard socket interfaces if still empty
    if not interfaces:
        try:
            hostname = socket.gethostname()
            local_ip = socket.gethostbyname(hostname)
            interfaces.append({
                "id": local_ip,
                "name": f"Local Host ({local_ip})",
                "guid": ""
            })
        except Exception:
            interfaces.append({
                "id": "default",
                "name": "Default Network Interface",
                "guid": ""
            })

    return interfaces


class IDSManager:
    def __init__(self):
        self.running = False
        self.mode = "simulated"  # "live" or "simulated"
        self.stop_event = threading.Event()
        
        self.evaluator_thread = None
        self.sniffer_thread = None
        self.housekeeper_thread = None
        
        self.active_flows = {}
        self.flow_lock = threading.Lock()
        
        self.blocked_ips = {}  # ip -> expire_time
        self.firewall_rules = []  # List of dict rules
        
        self.port_history = {}  # src_ip -> list of ports
        self.port_history_lock = threading.Lock()
        
        # Diagnostics
        self.total_packets = 0
        self.total_flows = 0
        self.blocked_count = 0
        self.current_pps = 0.0
        self.packet_timestamps = []
        self.sniffer_error = None
        self.capture_interface = None
        self.selected_interface = None
        self.lifecycle_lock = threading.RLock()
        
        self.pending_attack = None  # Holds active simulated attack triggers

    def update_port_history(self, src_ip: str, port: int) -> Tuple[bool, float]:
        with self.port_history_lock:
            if src_ip not in self.port_history:
                self.port_history[src_ip] = []
            history = self.port_history[src_ip]
            history.append(port)
            if len(history) > 40:
                history.pop(0)
            
            if len(history) >= 4:
                entropy = calculate_entropy(history)
                unique_ports = len(set(history))
                # High entropy combined with multiple destination ports indicates scanning
                if entropy > 1.7 and unique_ports >= 4:
                    return True, entropy
            return False, 0.0

    def trigger_block(self, src_ip: str, threat_type: str, reason: str):
        now = time.time()
        lease_duration = 60.0  # 60s security block
        expire_time = now + lease_duration
        
        # Avoid duplicate block log spam for already actively blocked IP
        if src_ip in self.blocked_ips and self.blocked_ips[src_ip] > now:
            self.blocked_ips[src_ip] = expire_time  # renew lease
            return

        self.blocked_ips[src_ip] = expire_time
        self.blocked_count += 1
        
        rule = {
            "ip": src_ip,
            "threat_type": threat_type,
            "reason": reason,
            "blocked_at": time.strftime("%H:%M:%S", time.localtime(now)),
            "expire_at": time.strftime("%H:%M:%S", time.localtime(expire_time)),
            "lease_duration": lease_duration,
            "expire_time_raw": expire_time,
            "status": "ACTIVE"
        }
        self.firewall_rules.insert(0, rule)
        print(f"[FIREWALL] [BLOCK] Blocked source IP {src_ip} due to {threat_type} (Reason: {reason})")

    def get_active_blocks(self) -> List[Dict]:
        now = time.time()
        active_rules = []
        for r in self.firewall_rules:
            if r["status"] == "ACTIVE":
                remaining = r["expire_time_raw"] - now
                if remaining > 0:
                    r["remaining"] = round(remaining, 1)
                    active_rules.append(r)
                else:
                    r["status"] = "EXPIRED"
                    r["remaining"] = 0
                    ip = r["ip"]
                    if ip in self.blocked_ips and self.blocked_ips[ip] <= r["expire_time_raw"]:
                        del self.blocked_ips[ip]
        return active_rules

    def revoke_block(self, ip: str) -> bool:
        success = False
        if ip in self.blocked_ips:
            del self.blocked_ips[ip]
            success = True
            
        for r in self.firewall_rules:
            if r["ip"] == ip and r["status"] == "ACTIVE":
                r["status"] = "REVOKED"
                r["remaining"] = 0
                success = True
                
        if success:
            print(f"[FIREWALL] [REVOKE] Unblocked source IP {ip}")
        return success

    def evaluate_flow(self, src_ip: str, dst_ip: str, dport: int, duration_micro: float,
                      fwd_pkts: int, bwd_pkts: int, fwd_bytes: float, bwd_bytes: float, proto: str):
        
        self.total_flows += 1
        classification = "BENIGN"
        confidence = 1.0
        
        # Machine learning inference
        if MODEL_LOADED and model is not None and scaler is not None:
            try:
                raw_input_vector = [
                    float(dport), float(duration_micro), float(fwd_pkts),
                    float(bwd_pkts), float(fwd_bytes), float(bwd_bytes)
                ]
                cols = ['DST_PORT', 'FLOW_DURATION', 'FWD_PKTS', 'BWD_PKTS', 'FWD_BYTES', 'BWD_BYTES']
                scaled = scaler.transform(pd.DataFrame([raw_input_vector], columns=cols))
                pred_class = int(model.predict(scaled)[0])
                probs = model.predict_proba(scaled)[0]
                confidence = float(probs[pred_class])
                
                threat_labels = {0: "BENIGN", 1: "DDOS_FLOOD", 2: "BRUTE_FORCE_SPRAY"}
                classification = threat_labels.get(pred_class, "BENIGN")
            except Exception as e:
                print(f"[ML] [ERROR] Prediction logic error: {e}")
                
        # Heuristics rules layer as safety guard
        if classification == "BENIGN":
            if (dport in [80, 443, 8080] and fwd_pkts >= 2000) or (fwd_bytes > 500_000 and duration_micro < 5_000_000):
                classification = "DDOS_FLOOD"
                confidence = 0.99
            elif dport in [21, 22, 23, 3389] and duration_micro > 10_000_000 and fwd_pkts <= 3 and bwd_pkts <= 3:
                classification = "BRUTE_FORCE_SPRAY"
                confidence = 0.96

        # Check port scan history (Shannon Entropy)
        with self.port_history_lock:
            if src_ip in self.port_history:
                history = self.port_history[src_ip]
                if len(history) >= 4:
                    entropy = calculate_entropy(history)
                    unique_ports = len(set(history))
                    if entropy > 1.7 and unique_ports >= 4:
                        classification = "PORT_SCAN"
                        confidence = 0.99

        # Map actions and forensic explanations
        mitigation_matrix = {
            "BENIGN": ("PASS_TRAFFIC", "No malicious patterns flagged. Permitting flow through perimeter."),
            "DDOS_FLOOD": ("SCRUB_TRAFFIC_RATE_LIMIT", "Volumetric flood patterns matching DDoS attack profiles. Injecting rate-limiting rules and diverting to scrubbing servers."),
            "BRUTE_FORCE_SPRAY": ("BLOCK_IP_DROP_CHAIN", "Sequential anomalous brute-force authentication identified. Issuing immediate hardware firewall drop rule on source IP."),
            "PORT_SCAN": ("BLOCK_IP_DROP_CHAIN", "Multi-port scan patterns identified. Issuing hardware firewall rule to drop all connections from this source IP.")
        }
        
        action_protocol, forensic_summary = mitigation_matrix.get(classification, mitigation_matrix["BENIGN"])
        
        alert_item = {
            "timestamp": time.strftime("%H:%M:%S"),
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "dport": dport,
            "proto": proto,
            "fwd_pkts": fwd_pkts,
            "bwd_pkts": bwd_pkts,
            "fwd_bytes": int(fwd_bytes),
            "bwd_bytes": int(bwd_bytes),
            "duration_ms": round(duration_micro / 1000.0, 2),
            "classification": classification,
            "confidence": round(confidence, 4),
            "mitigation_protocol": action_protocol,
            "forensic_summary": forensic_summary
        }
        
        # Trigger dynamic block if threat detected
        if classification != "BENIGN":
            self.trigger_block(src_ip, classification, forensic_summary)
            
        broadcast_alert(alert_item)

    def run_live_sniffer(self):
        print("[SNIFFER] Starting Live Sniffer Engine...")
        self.packet_timestamps = []
        self.sniffer_error = None

        target_iface = self.selected_interface or os.environ.get("SNIFFER_INTERFACE")

        if SCAPY_AVAILABLE:
            try:
                # Identify appropriate interface
                iface = target_iface if target_iface else conf.iface
                self.capture_interface = str(iface) if iface else "Default Interface"
                print(f"[SNIFFER] Capturing packets on: {self.capture_interface}")
            except Exception as e:
                self.capture_interface = "Default Interface"
                print(f"[SNIFFER] Interface configuration notice: {e}")
        else:
            self.capture_interface = "Raw Socket"

        def packet_handler(pkt):
            if not self.running or self.stop_event.is_set():
                return
            if not (IP in pkt and (TCP in pkt or UDP in pkt)):
                return
            
            self.total_packets += 1
            now = time.time()
            self.packet_timestamps.append(now)
            
            ip_layer = pkt[IP]
            proto = "TCP" if TCP in pkt else "UDP"
            sport = int(pkt.sport) if hasattr(pkt, 'sport') else 0
            dport = int(pkt.dport) if hasattr(pkt, 'dport') else 0
            src_ip = str(ip_layer.src)
            dst_ip = str(ip_layer.dst)
            pkt_len = len(pkt)
            
            # Check firewall block
            if src_ip in self.blocked_ips:
                if now < self.blocked_ips[src_ip]:
                    return  # Packet dropped by active firewall rule
                else:
                    del self.blocked_ips[src_ip]
            
            # Update Port History for port scan detection
            is_scan, entropy = self.update_port_history(src_ip, dport)
            if is_scan:
                self.evaluate_flow(
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    dport=dport,
                    duration_micro=1000.0,
                    fwd_pkts=1,
                    bwd_pkts=0,
                    fwd_bytes=float(pkt_len),
                    bwd_bytes=0.0,
                    proto=proto
                )
                return
            
            # Flow Aggregation
            flow_key_fwd = (src_ip, sport, dst_ip, dport, proto)
            flow_key_bwd = (dst_ip, dport, src_ip, sport, proto)
            
            with self.flow_lock:
                if flow_key_fwd in self.active_flows:
                    flow = self.active_flows[flow_key_fwd]
                    flow['fwd_pkts'] += 1
                    flow['fwd_bytes'] += pkt_len
                    flow['last_seen'] = now
                elif flow_key_bwd in self.active_flows:
                    flow = self.active_flows[flow_key_bwd]
                    flow['bwd_pkts'] += 1
                    flow['bwd_bytes'] += pkt_len
                    flow['last_seen'] = now
                else:
                    self.active_flows[flow_key_fwd] = {
                        'start_time': now,
                        'last_seen': now,
                        'fwd_pkts': 1,
                        'bwd_pkts': 0,
                        'fwd_bytes': pkt_len,
                        'bwd_bytes': 0,
                        'dport': dport,
                        'src_ip': src_ip,
                        'dst_ip': dst_ip,
                        'proto': proto
                    }

        # Multi-tiered Sniffing Execution
        sniff_success = False

        # 1. Try Scapy sniffing with selected interface
        if SCAPY_AVAILABLE and not sniff_success:
            try:
                while self.running and not self.stop_event.is_set() and self.mode == "live":
                    if target_iface:
                        sniff(iface=target_iface, prn=packet_handler, store=0, timeout=1.0)
                    else:
                        sniff(prn=packet_handler, store=0, timeout=1.0)
                    sniff_success = True
            except Exception as e:
                print(f"[SNIFFER] Scapy default sniff attempt: {e}")
                self.sniffer_error = str(e)

        # 2. Try Scapy sniffing with iface=None or L3 fallback
        if SCAPY_AVAILABLE and not sniff_success and self.running and self.mode == "live":
            try:
                print("[SNIFFER] Attempting Scapy L3 socket fallback...")
                while self.running and not self.stop_event.is_set() and self.mode == "live":
                    sniff(store=0, prn=packet_handler, timeout=1.0)
                    sniff_success = True
            except Exception as e:
                print(f"[SNIFFER] Scapy L3 sniff fallback notice: {e}")
                self.sniffer_error = str(e)

        # 3. If live capture driver/permissions are missing, notify and fallback to simulated mode
        if not sniff_success and self.running and self.mode == "live":
            error_msg = self.sniffer_error or "Network capture permissions or Npcap driver required for live raw socket sniffing."
            self.sniffer_error = error_msg
            print(f"[SNIFFER] [INFO] {error_msg} Defaulting to simulated traffic generator.")
            self.mode = "simulated"
            if self.running and not self.stop_event.is_set():
                self.sniffer_thread = threading.Thread(target=self.run_simulation, daemon=True)
                self.sniffer_thread.start()

    def run_simulation(self):
        print("[SIMULATOR] Starting Simulated Traffic Generator...")
        active_attack = None
        attack_start = 0
        
        while self.running and not self.stop_event.is_set() and self.mode == "simulated":
            self.stop_event.wait(random.uniform(0.4, 0.8))
            if not self.running or self.stop_event.is_set():
                break

            now = time.time()
            
            # Calculate simulated packet counts and PPS
            sim_pkts = random.randint(6, 22)
            self.total_packets += sim_pkts
            
            # Record timestamps for real PPS calculation
            for _ in range(sim_pkts):
                self.packet_timestamps.append(now)
            
            # Inject attack presets
            if self.pending_attack:
                active_attack = self.pending_attack
                attack_start = now
                self.pending_attack = None
                print(f"[SIMULATOR] [ATTACK] Simulated attack active: {active_attack}")
            
            # Attacking sequence duration limit (12 seconds)
            if active_attack and (now - attack_start > 12.0):
                print(f"[SIMULATOR] Simulated attack {active_attack} completed.")
                active_attack = None
            
            if not active_attack:
                # Nominal background flow
                src_ip = f"192.168.1.{random.randint(10, 55)}"
                if src_ip in self.blocked_ips:
                    if now < self.blocked_ips[src_ip]:
                        continue
                    else:
                        del self.blocked_ips[src_ip]
                
                dport = random.choice([80, 443, 8080, 22, 53, 3306])
                duration_micro = random.uniform(30000, 250000)
                fwd_pkts = random.randint(1, 8)
                bwd_pkts = random.randint(1, 10)
                fwd_bytes = fwd_pkts * random.randint(60, 180)
                bwd_bytes = bwd_pkts * random.randint(120, 800)
                proto = "TCP" if dport != 53 else "UDP"
                
                # Moderate Port Scan Simulation (6% chance)
                if random.random() < 0.06:
                    scanner_ip = f"192.168.1.{random.choice([88, 99, 144])}"
                    if scanner_ip not in self.blocked_ips:
                        for p in [21, 22, 23, 25, 80, 110, 139, 443, 445, 8080]:
                            self.update_port_history(scanner_ip, p)
                            self.evaluate_flow(
                                scanner_ip, "192.168.1.1", p,
                                600.0, 1, 0, 44.0, 0.0, "TCP"
                            )
                
                self.evaluate_flow(
                    src_ip, "192.168.1.1", dport, duration_micro,
                    fwd_pkts, bwd_pkts, fwd_bytes, bwd_bytes, proto
                )
            else:
                # Active attack simulation
                if active_attack == "DDOS_FLOOD":
                    attacker_ip = "10.0.0.99"
                    
                    if attacker_ip in self.blocked_ips:
                        if now < self.blocked_ips[attacker_ip]:
                            # Attack packets dropped by firewall
                            self.stop_event.wait(0.2)
                            continue
                        else:
                            del self.blocked_ips[attacker_ip]
                    
                    self.evaluate_flow(
                        attacker_ip, "192.168.1.1", 80,
                        random.uniform(500, 1500),
                        random.randint(6000, 12000),
                        0,
                        random.randint(450000, 950000),
                        0,
                        "TCP"
                    )
                elif active_attack == "BRUTE_FORCE_SPRAY":
                    attacker_ip = "172.16.0.45"
                    
                    if attacker_ip in self.blocked_ips:
                        if now < self.blocked_ips[attacker_ip]:
                            self.stop_event.wait(0.5)
                            continue
                        else:
                            del self.blocked_ips[attacker_ip]
                            
                    self.evaluate_flow(
                        attacker_ip, "192.168.1.1", 22,
                        random.uniform(16_000_000, 24_000_000),
                        1, 1, 0, 0, "TCP"
                    )
                    self.stop_event.wait(0.8)

    def flow_evaluator_loop(self):
        while self.running and not self.stop_event.is_set():
            self.stop_event.wait(0.6)
            if not self.running or self.stop_event.is_set():
                break

            now = time.time()
            flows_to_evaluate = []
            
            with self.flow_lock:
                keys_to_remove = []
                for key, flow in list(self.active_flows.items()):
                    # Evaluate if idle for 1.5s, duration > 5s, or flood detected
                    if now - flow['last_seen'] >= 1.5 or now - flow['start_time'] >= 5.0 or flow['fwd_pkts'] >= 50:
                        flows_to_evaluate.append(flow)
                        keys_to_remove.append(key)
                for key in keys_to_remove:
                    del self.active_flows[key]
                    
            for flow in flows_to_evaluate:
                duration_sec = max(flow['last_seen'] - flow['start_time'], 0.001)
                duration_micro = duration_sec * 1_000_000.0
                
                self.evaluate_flow(
                    flow['src_ip'],
                    flow['dst_ip'],
                    flow['dport'],
                    duration_micro,
                    flow['fwd_pkts'],
                    flow['bwd_pkts'],
                    flow['fwd_bytes'],
                    flow['bwd_bytes'],
                    flow['proto']
                )

    def housekeeper_loop(self):
        """
        Background daemon that prunes packet timestamps and updates PPS smoothly.
        """
        while self.running and not self.stop_event.is_set():
            self.stop_event.wait(0.5)
            if not self.running or self.stop_event.is_set():
                break
                
            now = time.time()
            with self.flow_lock:
                self.packet_timestamps = [t for t in self.packet_timestamps if now - t <= 5.0]
                self.current_pps = round(len(self.packet_timestamps) / 5.0, 2)

    def start(self):
        with self.lifecycle_lock:
            if self.running:
                return
            self.running = True
            self.stop_event.clear()
            self.sniffer_error = None
            
            self.evaluator_thread = threading.Thread(target=self.flow_evaluator_loop, daemon=True)
            self.housekeeper_thread = threading.Thread(target=self.housekeeper_loop, daemon=True)
            
            if self.mode == "live" and SCAPY_AVAILABLE:
                self.sniffer_thread = threading.Thread(target=self.run_live_sniffer, daemon=True)
            else:
                self.sniffer_thread = threading.Thread(target=self.run_simulation, daemon=True)
                
            self.evaluator_thread.start()
            self.housekeeper_thread.start()
            self.sniffer_thread.start()
            print(f"[SYSTEM] IDS Engine started in {self.mode.upper()} mode.")

    def stop(self):
        with self.lifecycle_lock:
            if not self.running:
                return
            self.running = False
            self.stop_event.set()
            threads = (self.sniffer_thread, self.evaluator_thread, self.housekeeper_thread)
            
        for thread in threads:
            if thread and thread is not threading.current_thread() and thread.is_alive():
                thread.join(timeout=1.5)
        print("[SYSTEM] IDS Engine stopped.")

    def inject_threat_flow(self, attack_type: str):
        if attack_type == "DDOS_FLOOD":
            self.evaluate_flow(
                "10.0.0.99", "192.168.1.1", 80,
                1200.0, 8500, 0, 750000.0, 0.0, "TCP"
            )
        elif attack_type == "BRUTE_FORCE_SPRAY":
            self.evaluate_flow(
                "172.16.0.45", "192.168.1.1", 22,
                18500000.0, 1, 1, 0.0, 0.0, "TCP"
            )


# Initialize Sniffer Manager
ids_manager = IDSManager()

@asynccontextmanager
async def lifespan(_app):
    ids_manager.start()
    try:
        yield
    finally:
        ids_manager.stop()

app = FastAPI(title="Aegis NetShield: AI Forensic & Mitigation Engine", lifespan=lifespan)


# FastAPI HTTP Route Bindings
class NetworkFlowFrame(BaseModel):
    DST_PORT: int
    FLOW_DURATION: float
    FWD_PKTS: int
    BWD_PKTS: int
    FWD_BYTES: float
    BWD_BYTES: float

@app.post("/inspect")
async def inspect_packet_flow(flow: NetworkFlowFrame):
    """
    Backward-compatible REST endpoint for single-flow verification.
    """
    try:
        raw_input_vector = [
            float(flow.DST_PORT), float(flow.FLOW_DURATION), float(flow.FWD_PKTS),
            float(flow.BWD_PKTS), float(flow.FWD_BYTES), float(flow.BWD_BYTES)
        ]
        
        classification = "BENIGN"
        confidence = 1.0
        
        if MODEL_LOADED and model is not None and scaler is not None:
            cols = ['DST_PORT', 'FLOW_DURATION', 'FWD_PKTS', 'BWD_PKTS', 'FWD_BYTES', 'BWD_BYTES']
            scaled_vector = scaler.transform(pd.DataFrame([raw_input_vector], columns=cols))
            predicted_class = int(model.predict(scaled_vector)[0])
            probabilities = model.predict_proba(scaled_vector)[0]
            confidence = float(probabilities[predicted_class])
            threat_labels = {0: "BENIGN", 1: "DDOS_FLOOD", 2: "BRUTE_FORCE_SPRAY"}
            classification = threat_labels.get(predicted_class, "BENIGN")
        else:
            # Heuristic fallback
            if flow.DST_PORT in [80, 443] and flow.FWD_PKTS > 2000:
                classification = "DDOS_FLOOD"
                confidence = 0.99
            elif flow.DST_PORT == 22 and flow.FLOW_DURATION > 10_000_000:
                classification = "BRUTE_FORCE_SPRAY"
                confidence = 0.95

        mitigation_matrix = {
            "BENIGN": ("PASS_TRAFFIC", "No malicious patterns flagged. Permitting flow through perimeter."),
            "DDOS_FLOOD": ("SCRUB_TRAFFIC_RATE_LIMIT", "Volumetric flood patterns matching DDoS attack profiles. Injecting rate-limiting rules and diverting to scrubbing servers."),
            "BRUTE_FORCE_SPRAY": ("BLOCK_IP_DROP_CHAIN", "Sequential anomalous brute-force authentication identified. Issuing immediate hardware firewall drop rule on source IP."),
            "PORT_SCAN": ("BLOCK_IP_DROP_CHAIN", "Multi-port scan patterns identified. Issuing hardware firewall rule to drop all connections from this source IP.")
        }
        
        action_protocol, forensic_summary = mitigation_matrix.get(classification, mitigation_matrix["BENIGN"])
        return {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "classification": classification,
            "confidence": round(confidence, 4),
            "mitigation_protocol": action_protocol,
            "forensic_summary": forensic_summary,
            "monitored_port": flow.DST_PORT
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Inference Processing Failure: {str(e)}")


@app.get("/api/status")
async def get_status():
    return {
        "model_loaded": MODEL_LOADED,
        "scapy_available": SCAPY_AVAILABLE,
        "sniffer_running": ids_manager.running,
        "sniffer_mode": ids_manager.mode,
        "sniffer_error": ids_manager.sniffer_error,
        "capture_interface": ids_manager.capture_interface,
        "selected_interface": ids_manager.selected_interface,
        "total_packets": ids_manager.total_packets,
        "total_flows": ids_manager.total_flows,
        "blocked_count": ids_manager.blocked_count,
        "current_pps": round(ids_manager.current_pps, 2)
    }


@app.get("/api/sniffer/interfaces")
async def get_interfaces():
    return {
        "interfaces": list_system_interfaces(),
        "selected": ids_manager.selected_interface or ids_manager.capture_interface
    }


@app.post("/api/sniffer/interface")
async def set_capture_interface(iface: str = Query(...)):
    ids_manager.selected_interface = iface if iface != "default" else None
    if ids_manager.running and ids_manager.mode == "live":
        ids_manager.stop()
        ids_manager.start()
    return {"selected_interface": ids_manager.selected_interface}


@app.post("/api/sniffer/toggle")
async def toggle_sniffer():
    if ids_manager.running:
        ids_manager.stop()
    else:
        ids_manager.start()
    return {"running": ids_manager.running}


@app.post("/api/sniffer/mode")
async def change_sniffer_mode(mode: str):
    if mode not in ["live", "simulated"]:
        raise HTTPException(status_code=400, detail="Invalid sniffer mode. Must be 'live' or 'simulated'")
    
    ids_manager.stop()
    ids_manager.mode = mode
    ids_manager.start()
    return {
        "mode": ids_manager.mode,
        "running": ids_manager.running,
        "error": ids_manager.sniffer_error
    }


@app.get("/api/firewall/rules")
async def get_firewall_rules():
    return ids_manager.get_active_blocks()


class IPRequest(BaseModel):
    ip: str

@app.post("/api/firewall/revoke")
async def revoke_firewall_rule(req: IPRequest):
    success = ids_manager.revoke_block(req.ip)
    if not success:
        raise HTTPException(status_code=400, detail="IP address not found in active blocks or already expired.")
    return {"success": True, "ip": req.ip}


class AttackRequest(BaseModel):
    attack_type: str

@app.post("/api/simulate/inject")
async def inject_simulated_attack(req: AttackRequest):
    if req.attack_type not in ["DDOS_FLOOD", "BRUTE_FORCE_SPRAY"]:
        raise HTTPException(status_code=400, detail="Invalid attack type preset.")
        
    threading.Thread(target=ids_manager.inject_threat_flow, args=(req.attack_type,), daemon=True).start()
    return {"success": True, "attack": req.attack_type}


@app.get("/api/alerts")
async def alerts_stream():
    """
    Server-Sent Events (SSE) endpoint to push live flow events.
    """
    q: queue.Queue = queue.Queue(maxsize=100)
    with connected_clients_lock:
        connected_clients.append(q)
    
    async def event_generator():
        last_heartbeat = time.time()
        try:
            while True:
                now = time.time()
                # Send comment heartbeat every 4 seconds to keep connection alive
                if now - last_heartbeat >= 4.0:
                    yield ": ping\n\n"
                    last_heartbeat = now
                    
                while not q.empty():
                    item = q.get_nowait()
                    yield f"data: {json.dumps(item)}\n\n"
                await asyncio.sleep(0.15)
        except asyncio.CancelledError:
            pass
        finally:
            with connected_clients_lock:
                if q in connected_clients:
                    connected_clients.remove(q)
            
    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no"
        }
    )


# Mount Static Files Dashboard (last, so API endpoints take priority)
app.mount("/", StaticFiles(directory=BASE_DIR / "static", html=True), name="static")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        app,
        host=os.environ.get("HOST", "127.0.0.1"),
        port=int(os.environ.get("PORT", "8000")),
    )
