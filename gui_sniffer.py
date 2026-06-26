import tkinter as tk
import threading
import os
import sys
import ctypes
import socket
import struct
import textwrap

# Global flag to stop sniffing
stop_sniffing = False
sniffing_thread = None

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def request_admin():
    """Re-run the script with admin privileges"""
    if not is_admin():
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
        sys.exit()

def format_ipv4(bytes_addr):
    bytes_str = map(str, bytes_addr)
    return ".".join(bytes_str)

def format_ipv4_packet(version_header_length):
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4
    return version, header_length

def parse_ipv4(data):
    version_header_length = data[0]
    version, header_length = format_ipv4_packet(version_header_length)
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return format_ipv4(src), format_ipv4(target), proto

def parse_tcp(data):
    (src_port, dest_port, sequence, acknowledgment, offset_reserved_flags) = struct.unpack('! H H L L H', data[:14])
    offset = (offset_reserved_flags >> 12) * 4
    flag_urg = (offset_reserved_flags & 32) >> 5
    flag_ack = (offset_reserved_flags & 16) >> 4
    flag_psh = (offset_reserved_flags & 8) >> 3
    flag_rst = (offset_reserved_flags & 4) >> 2
    flag_syn = (offset_reserved_flags & 2) >> 1
    flag_fin = offset_reserved_flags & 1
    return src_port, dest_port, sequence, acknowledgment, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin

def process_packet(data):
    if stop_sniffing:
        return
    try:
        version, header_length, ttl, proto, src, target = version, header_length, ttl, proto, src, target = None, None, None, None, None, None
        version_header_length = data[0]
        version, header_length = format_ipv4_packet(version_header_length)
        ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
        src = format_ipv4(src)
        target = format_ipv4(target)
        
        log.insert(tk.END, f"Source IP: {src} → Dest IP: {target} (Protocol: {proto})\n")
        
        if proto == 6:  # TCP
            tcp_data = data[header_length:]
            if len(tcp_data) >= 14:
                src_port, dest_port, sequence, acknowledgment, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin = parse_tcp(tcp_data)
                log.insert(tk.END, f"  TCP Port: {src_port} → {dest_port}\n")
                flags = []
                if flag_syn: flags.append("SYN")
                if flag_ack: flags.append("ACK")
                if flag_fin: flags.append("FIN")
                if flag_rst: flags.append("RST")
                if flags:
                    log.insert(tk.END, f"  Flags: {','.join(flags)}\n")
        
        log.insert(tk.END, "-" * 40 + "\n")
        log.see(tk.END)
        root.update()
    except Exception as e:
        log.insert(tk.END, f"Error processing packet: {str(e)}\n")
        log.see(tk.END)
        root.update()

def sniff_packets():
    try:
        # Create raw socket on Windows
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
        sock.bind((socket.gethostbyname(socket.gethostname()), 0))
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
        
        log.insert(tk.END, "Packet capture started...\n")
        log.see(tk.END)
        root.update()
        
        while not stop_sniffing:
            raw_buffer = sock.recvfrom(65535)[0]
            process_packet(raw_buffer)
        
        sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
        sock.close()
        
    except PermissionError:
        log.insert(tk.END, "ERROR: Admin privileges required!\n")
        log.see(tk.END)
        root.update()
    except Exception as e:
        log.insert(tk.END, f"Sniffing error: {str(e)}\n")
        log.see(tk.END)
        root.update()

def start_sniffing():
    global stop_sniffing, sniffing_thread
    
    stop_sniffing = False
    log.insert(tk.END, "Sniffing started...\n\n")
    log.see(tk.END)
    root.update()
    
    sniffing_thread = threading.Thread(target=sniff_packets, daemon=True)
    sniffing_thread.start()

def stop_sniffing_action():
    global stop_sniffing
    stop_sniffing = True
    log.insert(tk.END, "\nSniffing stopped by user.\n")
    log.insert(tk.END, "=" * 40 + "\n\n")
    log.see(tk.END)
    root.update()

# GUI setup
request_admin()

root = tk.Tk()
root.title("Basic Network Sniffer")
root.geometry("700x450")

start_button = tk.Button(root, text="Start Sniffing", command=start_sniffing, bg="green", fg="white", width=20)
start_button.pack(pady=10)

stop_button = tk.Button(root, text="Stop Sniffing", command=stop_sniffing_action, bg="red", fg="white", width=20)
stop_button.pack(pady=5)

log = tk.Text(root, height=20, width=85, bg="black", fg="lime")
log.pack()

root.mainloop()
