import sys
import os
import traceback
from pathlib import Path

BASE = Path(__file__).resolve().parent
out_file = BASE / "sniffer_results.txt"

with open(out_file, "w", encoding="utf-8") as f:
    f.write(f"CWD: {os.getcwd()}\n")
    f.write(f"Script dir: {BASE}\n")
    f.write(f"Python executable: {sys.executable}\n")
    f.write(f"Python version: {sys.version}\n")
    try:
        import scapy
        f.write(f"Scapy version: {scapy.__version__}\n")
        from scapy.all import conf, get_if_list, sniff, IP, TCP, UDP
        f.write(f"conf.iface: {conf.iface}\n")
        f.write(f"conf.use_pcap: {getattr(conf, 'use_pcap', None)}\n")
        f.write(f"conf.L2listen: {getattr(conf, 'L2listen', None)}\n")
        f.write(f"conf.L3socket: {getattr(conf, 'L3socket', None)}\n")
        try:
            from scapy.arch.windows import get_windows_if_list
            win_ifs = get_windows_if_list()
            f.write(f"Windows interfaces count: {len(win_ifs)}\n")
            for idx, iface in enumerate(win_ifs):
                f.write(f"  [{idx}] Name: {iface.get('name')} | Desc: {iface.get('description')} | IP: {iface.get('ips')} | GUID: {iface.get('guid')}\n")
        except Exception as e:
            f.write(f"  Error get_windows_if_list: {e}\n")
            f.write(f"  get_if_list(): {get_if_list()}\n")
            
        # Test basic sniff test
        try:
            f.write("Testing sniff(timeout=1, count=1)...\n")
            pkts = sniff(timeout=1, count=1, store=1)
            f.write(f"Sniff success! Captured {len(pkts)} packets.\n")
        except Exception as e:
            f.write(f"Sniff error: {type(e).__name__}: {e}\n")
            traceback.print_exc(file=f)
            
    except Exception as e:
        f.write(f"Scapy import error: {type(e).__name__}: {e}\n")
        traceback.print_exc(file=f)

    # Test raw socket
    try:
        import socket
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
        f.write("Raw socket creation: Success\n")
        s.close()
    except Exception as e:
        f.write(f"Raw socket creation: {type(e).__name__}: {e}\n")
