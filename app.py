# app.py
import os
import time
import json
import queue
import random
import math
import threading
import asyncio
from typing import Dict, List, Tuple
from fastapi import FastAPI, HTTPException
from fastapi.responses import StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import joblib
import numpy as np
import pandas as pd

app = FastAPI(title="Aegis NetShield: AI Forensic & Mitigation Engine")

# Enable CORS for external access
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Load XGBoost Model and Scaler
MODEL_LOADED = False
model = None
scaler = None
features = None

try:
    if os.path.exists('cyber_threat_model.pkl') and os.path.exists('cyber_scaler.pkl'):
        model = joblib.load('cyber_threat_model.pkl')
        scaler = joblib.load('cyber_scaler.pkl')
        features = joblib.load('cyber_features.pkl')
        MODEL_LOADED = True
        print("[ML] ML intrusion detection model and scaler loaded successfully.")
    else:
        print("[ML] [WARN] Serialized model files not found. System will run in rule-based fallback mode.")
except Exception as e:
    print(f"[ML] [ERROR] Error loading ML artifacts: {e}. System running in rule-based fallback mode.")

# Scapy availability check
SCAPY_AVAILABLE = False
try:
    from scapy.all import sniff, IP, TCP, UDP
    SCAPY_AVAILABLE = True
    print("[SNIFFER] Scapy packet sniffer successfully imported.")
except Exception as e:
    print(f"[SNIFFER] [WARN] Scapy sniffer not imported or missing Npcap driver: {e}. Fallback simulation enabled.")

# Global Thread-safe alert queues
import queue
connected_clients = []
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

def broadcast_alert(alert_data):
    with connected_clients_lock:
        for q in connected_clients:
            q.put(alert_data)

class IDSManager:
    def __init__(self):
        self.running = False
        self.mode = "simulated"  # "live" or "simulated"
        self.evaluator_thread = None
        self.sniffer_thread = None
        
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
        
        self.pending_attack = None  # Holds active simulated attack triggers

    def update_port_history(self, src_ip: str, port: int) -> Tuple[bool, float]:
        with self.port_history_lock:
            if src_ip not in self.port_history:
                self.port_history[src_ip] = []
            history = self.port_history[src_ip]
            history.append(port)
            if len(history) > 50:
                history.pop(0)
            
            if len(history) >= 8:
                entropy = calculate_entropy(history)
                unique_ports = len(set(history))
                # High entropy combined with multiple destination ports indicates scanning
                if entropy > 2.0 and unique_ports >= 4:
                    return True, entropy
            return False, 0.0

    def trigger_block(self, src_ip: str, threat_type: str, reason: str):
        now = time.time()
        lease_duration = 60.0  # 60s security block
        expire_time = now + lease_duration
        
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
        if MODEL_LOADED:
            try:
                raw_input_vector = [
                    dport, duration_micro, fwd_pkts, bwd_pkts, fwd_bytes, bwd_bytes
                ]
                cols = ['DST_PORT', 'FLOW_DURATION', 'FWD_PKTS', 'BWD_PKTS', 'FWD_BYTES', 'BWD_BYTES']
                scaled = scaler.transform(pd.DataFrame([raw_input_vector], columns=cols))
                pred_class = int(model.predict(scaled)[0])
                probs = model.predict_proba(scaled)[0]
                confidence = float(probs[pred_class])
                
                threat_labels = {0: "BENIGN", 1: "DDOS_FLOOD", 2: "BRUTE_FORCE_SPRAY"}
                classification = threat_labels.get(pred_class, "BENIGN")
            except Exception as e:
                print(f"[ML] [ERROR] Prediction logic failed, falling back to heuristics: {e}")
                
        # Heuristics rules as fallback or safety layer
        if classification == "BENIGN":
            if dport == 80 and fwd_pkts > 5000:
                classification = "DDOS_FLOOD"
                confidence = 0.99
            elif dport == 22 and duration_micro > 10_000_000 and fwd_pkts <= 2 and bwd_pkts <= 2:
                classification = "BRUTE_FORCE_SPRAY"
                confidence = 0.95

        # Check port scan history (Shannon Entropy)
        is_port_scan = False
        with self.port_history_lock:
            if src_ip in self.port_history:
                history = self.port_history[src_ip]
                if len(history) >= 8:
                    entropy = calculate_entropy(history)
                    unique_ports = len(set(history))
                    if entropy > 2.0 and unique_ports >= 4:
                        is_port_scan = True

        if is_port_scan and classification == "BENIGN":
            classification = "PORT_SCAN"
            confidence = 0.99

        # Map actions
        mitigation_matrix = {
            "BENIGN": ("PASS_TRAFFIC", "No malicious patterns flagged. Permitting flow through perimeter."),
            "DDOS_FLOOD": ("SCRUB_TRAFFIC_RATE_LIMIT", "Volumetric flood patterns matching DDoS attack profiles. Injecting rate-limiting rules and diverting to scrubbing servers."),
            "BRUTE_FORCE_SPRAY": ("BLOCK_IP_DROP_CHAIN", "Sequential anomalous brute-force authentication identified. Issuing immediate hardware firewall drop rule on source IP."),
            "PORT_SCAN": ("BLOCK_IP_DROP_CHAIN", "Multi-port scan patterns identified. Issuing hardware firewall rule to drop all connections from this source IP.")
        }
        
        action_protocol, forensic_summary = mitigation_matrix[classification]
        
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
        print("[SNIFFER] Starting Live Sniffer Thread...")
        self.packet_timestamps = []
        
        # Auto-detect the active interface with packet flow
        try:
            from scapy.all import conf, get_if_list
            best_iface = None
            max_pkts = 0
            for iface in get_if_list():
                try:
                    pkts = sniff(iface=iface, timeout=0.2, count=3)
                    if len(pkts) > max_pkts:
                        max_pkts = len(pkts)
                        best_iface = iface
                except Exception:
                    continue
            if best_iface:
                conf.iface = best_iface
                print(f"[SNIFFER] Auto-bound to active interface: {best_iface} ({max_pkts} pps baseline)")
            else:
                print(f"[SNIFFER] No active interface packet flow detected, using default: {conf.iface}")
        except Exception as e:
            print(f"[SNIFFER] [ERROR] Interface auto-binding failed: {e}")
        
        def packet_handler(pkt):
            if not self.running:
                return
            if not (IP in pkt and (TCP in pkt or UDP in pkt)):
                return
            
            self.total_packets += 1
            now = time.time()
            self.packet_timestamps.append(now)
            self.packet_timestamps = [t for t in self.packet_timestamps if now - t <= 5.0]
            self.current_pps = len(self.packet_timestamps) / 5.0
            
            ip_layer = pkt[IP]
            proto = "TCP" if TCP in pkt else "UDP"
            sport = pkt.sport
            dport = pkt.dport
            src_ip = ip_layer.src
            dst_ip = ip_layer.dst
            pkt_len = len(pkt)
            
            # Check firewall block
            if src_ip in self.blocked_ips:
                if now < self.blocked_ips[src_ip]:
                    return  # Packet dropped
                else:
                    del self.blocked_ips[src_ip]
            
            # Update Port History
            is_scan, entropy = self.update_port_history(src_ip, dport)
            if is_scan:
                self.trigger_block(src_ip, "PORT_SCAN", f"Port scan signature matched (Entropy: {entropy:.2f})")
            
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

        try:
            from scapy.all import conf
            # Sniff with a timeout in a loop to handle graceful exit toggles
            while self.running and self.mode == "live":
                sniff(iface=conf.iface, prn=packet_handler, store=0, timeout=1.0)
        except Exception as e:
            print(f"[SNIFFER] [ERROR] Scapy sniff failed: {e}. Switching back to simulated flow mode.")
            self.mode = "simulated"
            # Launch simulated generator in thread
            self.sniffer_thread = threading.Thread(target=self.run_simulation, daemon=True)
            self.sniffer_thread.start()

    def run_simulation(self):
        print("[SIMULATOR] Starting Simulated Traffic Generator...")
        active_attack = None
        attack_start = 0
        
        while self.running and self.mode == "simulated":
            time.sleep(random.uniform(0.4, 0.9))
            now = time.time()
            
            # Calculate simulated packet counts and PPS
            sim_pkts = random.randint(5, 20)
            self.total_packets += sim_pkts
            self.current_pps = random.uniform(12.0, 28.0)
            
            # Inject attack presets
            if self.pending_attack:
                active_attack = self.pending_attack
                attack_start = now
                self.pending_attack = None
                print(f"[SIMULATOR] [ATTACK] Simulated attack initiated: {active_attack}")
            
            # Attacking sequence duration limit (12 seconds)
            if active_attack and (now - attack_start > 12.0):
                print(f"[SIMULATOR] Simulated attack {active_attack} completed.")
                active_attack = None
            
            if not active_attack:
                # Nominal background flow
                src_ip = f"192.168.1.{random.randint(10, 50)}"
                if src_ip in self.blocked_ips:
                    if now < self.blocked_ips[src_ip]:
                        continue
                    else:
                        del self.blocked_ips[src_ip]
                
                dport = random.choice([80, 443, 8080, 22])
                duration_micro = random.uniform(30000, 300000)
                fwd_pkts = random.randint(1, 8)
                bwd_pkts = random.randint(1, 10)
                fwd_bytes = fwd_pkts * random.randint(60, 180)
                bwd_bytes = bwd_pkts * random.randint(120, 800)
                proto = "TCP"
                
                # Moderate Port Scan Simulation (5% chance)
                if random.random() < 0.05:
                    scanner_ip = "192.168.1.99"
                    if scanner_ip not in self.blocked_ips:
                        for p in [21, 23, 25, 110, 139, 445]:
                            self.update_port_history(scanner_ip, p)
                            self.evaluate_flow(
                                scanner_ip, "192.168.1.1", p,
                                800.0, 1, 0, 40.0, 0.0, "TCP"
                            )
                
                self.evaluate_flow(
                    src_ip, "192.168.1.1", dport, duration_micro,
                    fwd_pkts, bwd_pkts, fwd_bytes, bwd_bytes, proto
                )
            else:
                # Active attack simulation
                if active_attack == "DDOS_FLOOD":
                    attacker_ip = "10.0.0.99"
                    self.current_pps = random.uniform(1800.0, 2600.0)
                    
                    if attacker_ip in self.blocked_ips:
                        if now < self.blocked_ips[attacker_ip]:
                            # Attack packets blocked! Show drop packets
                            self.current_pps = random.uniform(2.0, 8.0)
                            continue
                        else:
                            del self.blocked_ips[attacker_ip]
                    
                    self.evaluate_flow(
                        attacker_ip, "192.168.1.1", 80,
                        random.uniform(500, 1500),  # short duration
                        random.randint(6000, 12000),  # high packet counts
                        0,
                        random.randint(400000, 900000),  # high bytes
                        0,
                        "TCP"
                    )
                elif active_attack == "BRUTE_FORCE_SPRAY":
                    attacker_ip = "172.16.0.45"
                    
                    if attacker_ip in self.blocked_ips:
                        if now < self.blocked_ips[attacker_ip]:
                            continue
                        else:
                            del self.blocked_ips[attacker_ip]
                            
                    self.evaluate_flow(
                        attacker_ip, "192.168.1.1", 22,
                        random.uniform(16_000_000, 24_000_000),  # long duration
                        1, 1, 0, 0, "TCP"
                    )
                    time.sleep(1.0)  # brute force cycles are slightly slower

    def flow_evaluator_loop(self):
        while self.running:
            time.sleep(1.0)
            now = time.time()
            flows_to_evaluate = []
            
            with self.flow_lock:
                keys_to_remove = []
                for key, flow in list(self.active_flows.items()):
                    if now - flow['last_seen'] >= 2.0 or now - flow['start_time'] >= 10.0:
                        flows_to_evaluate.append(flow)
                        keys_to_remove.append(key)
                for key in keys_to_remove:
                    del self.active_flows[key]
                    
            for flow in flows_to_evaluate:
                duration_sec = flow['last_seen'] - flow['start_time']
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

    def start(self):
        if self.running:
            return
        self.running = True
        
        # Start evaluator thread
        self.evaluator_thread = threading.Thread(target=self.flow_evaluator_loop, daemon=True)
        self.evaluator_thread.start()
        
        # Start sniffer or simulator thread
        if self.mode == "live" and SCAPY_AVAILABLE:
            self.sniffer_thread = threading.Thread(target=self.run_live_sniffer, daemon=True)
        else:
            self.sniffer_thread = threading.Thread(target=self.run_simulation, daemon=True)
        self.sniffer_thread.start()

    def stop(self):
        self.running = False
        # Threads are daemons, they will exit with main process or cleanup on state check

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
ids_manager.start()

# FastAPI HTTP Route Bindings
@app.on_event("startup")
async def startup_event():
    global main_loop
    main_loop = asyncio.get_running_loop()

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
            flow.DST_PORT, flow.FLOW_DURATION, flow.FWD_PKTS,
            flow.BWD_PKTS, flow.FWD_BYTES, flow.BWD_BYTES
        ]
        
        classification = "BENIGN"
        confidence = 1.0
        
        if MODEL_LOADED:
            cols = ['DST_PORT', 'FLOW_DURATION', 'FWD_PKTS', 'BWD_PKTS', 'FWD_BYTES', 'BWD_BYTES']
            scaled_vector = scaler.transform(pd.DataFrame([raw_input_vector], columns=cols))
            predicted_class = int(model.predict(scaled_vector)[0])
            probabilities = model.predict_proba(scaled_vector)[0]
            confidence = float(probabilities[predicted_class])
            threat_labels = {0: "BENIGN", 1: "DDOS_FLOOD", 2: "BRUTE_FORCE_SPRAY"}
            classification = threat_labels.get(predicted_class, "BENIGN")
        else:
            # Fallback
            if flow.DST_PORT == 80 and flow.FWD_PKTS > 5000:
                classification = "DDOS_FLOOD"
            elif flow.DST_PORT == 22 and flow.FLOW_DURATION > 10_000_000:
                classification = "BRUTE_FORCE_SPRAY"

        threat_labels = {0: "BENIGN", 1: "DDOS_FLOOD", 2: "BRUTE_FORCE_SPRAY", 3: "PORT_SCAN"}
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
            "forensic_reremediation": forensic_summary,
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
        "total_packets": ids_manager.total_packets,
        "total_flows": ids_manager.total_flows,
        "blocked_count": ids_manager.blocked_count,
        "current_pps": round(ids_manager.current_pps, 2)
    }

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
    
    if mode == "live" and not SCAPY_AVAILABLE:
        raise HTTPException(status_code=400, detail="Scapy capture library is not available in this environment.")
        
    ids_manager.stop()
    ids_manager.mode = mode
    ids_manager.start()
    return {"mode": ids_manager.mode, "running": ids_manager.running}

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
    q = queue.Queue()
    with connected_clients_lock:
        connected_clients.append(q)
    
    async def event_generator():
        last_heartbeat = time.time()
        try:
            while True:
                now = time.time()
                # Send comment heartbeat every 5 seconds to keep connection alive and detect dead sockets
                if now - last_heartbeat >= 5.0:
                    yield ": ping\n\n"
                    last_heartbeat = now
                    
                while not q.empty():
                    item = q.get_nowait()
                    yield f"data: {json.dumps(item)}\n\n"
                await asyncio.sleep(0.2)
        except asyncio.CancelledError:
            pass
        finally:
            with connected_clients_lock:
                if q in connected_clients:
                    connected_clients.remove(q)
            
    return StreamingResponse(event_generator(), media_type="text/event-stream")

# Mount Static Files Dashboard (last, so API endpoints take priority)
app.mount("/", StaticFiles(directory="static", html=True), name="static")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)
