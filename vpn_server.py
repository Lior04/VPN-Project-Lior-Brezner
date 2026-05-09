import socket, ssl, threading, json, random, string, sqlite3
from scapy.layers.l2 import Ether, ARP 
from scapy.all import srp, sniff, sendp, conf
from scapy.layers.inet import IP, ICMP
import tkinter as tk 
from tkinter.scrolledtext import ScrolledText
from PIL import Image, ImageTk
import os
import ipaddress
import psutil
from dotenv import load_dotenv
import bcrypt
import secrets

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CERT_FILE = os.path.join(BASE_DIR, "cert.pem")
KEY_FILE = os.path.join(BASE_DIR, "key.pem")



load_dotenv("conf.env")
PASSWORD_HASH = os.getenv("VPN_PASSWORD_HASH")
print(PASSWORD_HASH)



def gen_auth_key(n=8):

    chars = string.ascii_letters + string.digits
    return "".join(random.choice(chars) for _ in range(n))
class TestVPNServerAppGui(tk.Tk):
    def __init__(self):
        super().__init__()
        self.raw_sock = None
        self.title("Python VPN Server")
        self.geometry("760x560")
        self.attributes("-fullscreen", True)

        self.bind("<Escape>", self.toggle_fullscreen)

        img = Image.open("logo.png")
       
        img = img.resize((150, 150), resample=Image.Resampling.LANCZOS)
        logo = ImageTk.PhotoImage(img)
        self.logo = ImageTk.PhotoImage(img)
        self.iconphoto(False, self.logo) 

        tk.Label(self, image=self.logo).pack(pady=10)

        self.stopped = False
        self.log_widget = ScrolledText(self, state="disabled")
        self.log_widget.pack(fill="both", expand=True, padx=10, pady=10)

      
        btn = tk.Button(self, text="Stop Server", bg="red", fg="white",command=self.stop_server)
        btn.pack(pady=10)


        threading.Thread(target=self.server_loop, daemon=True).start()

    def server_loop(self):

        print("CERT:", CERT_FILE)
        print("KEY:", KEY_FILE)
        print("cert exists?", os.path.exists(CERT_FILE))
        print("key exists?", os.path.exists(KEY_FILE))

        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(CERT_FILE, KEY_FILE)

        self.raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.raw_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.raw_sock.bind(("0.0.0.0", 8443))
        self.raw_sock.listen(5)
        self.raw_sock.settimeout(1.0)

        self.append_log("SERVER: listening on 0.0.0.0:8443")



        while not self.stopped:
            try:
                client_sock, addr = self.raw_sock.accept()

            except socket.timeout:
                continue
            except OSError:
                break
            try:
                tls_conn = ctx.wrap_socket(client_sock, server_side=True)
                tls_conn.settimeout(10)
            except:
                continue

            self.after(0, self.append_log, f"SERVER: connection from {addr}")
            threading.Thread(target=self.handle_client, args=(addr, tls_conn), daemon=True).start()


    def handle_client(self, addr, conn):
        try:
            client_ip = addr[0]
            data = self.recv_exact(conn, 4096)
            init = json.loads(data.decode())
            received_password = init.get("password", "")

            if not bcrypt.checkpw(received_password.encode(), PASSWORD_HASH.encode()):
                conn.sendall(json.dumps({'status': 'error', 'reason': 'bad password'}).encode())
                self.after(0, self.append_log, "SERVER: bad password")
                conn.close()
                return

            self.after(0, self.append_log, f"SERVER: auth ok for MAC {init.get('client_mac')}")

            subnet = self.get_local_subnet()
            self.after(0, self.append_log, f"SERVER: detected local subnet {subnet}")
            table = self.arp_sweep(subnet)
        
            key = gen_auth_key()

            session_id = secrets.token_hex(16)

            conn.sendall(json.dumps({
                'status': 'challenge',
                'session_id': session_id,
                'authKey': key,
                'hosts': [{'ip': ip, 'mac': mac} for ip, mac in table.items()]
            }).encode())

    
            ack = json.loads(self.recv_exact(conn, 4096).decode())
            if ack.get('authKey') != key:
                conn.sendall(json.dumps({'status': 'error', 'reason': 'bad authKey'}).encode())
                self.after(0, self.append_log, "SERVER: bad authKey")
                conn.close()
                return

        
            conn.sendall(json.dumps({'status': 'ready'}).encode())
            self.after(0, self.append_log, "SERVER: handshake complete, tunnel open")

        
            threading.Thread(target=self.inject_reqs, args=(conn, table), daemon=True).start()
            threading.Thread(target=self.sniff_repls, args=(conn, client_ip), daemon=True).start()


        except socket.timeout:
            self._log("Connection timeout")

    def append_log(self, msg):
            self.log_widget.config(state="normal")
            self.log_widget.insert(tk.END, msg + "\n")
            self.log_widget.config(state="disabled")
            self.log_widget.yview(tk.END)

    def toggle_fullscreen(self, event=None):
        current_state = self.attributes("-fullscreen")
        self.attributes("-fullscreen", not current_state)
        return "break"


    def stop_server(self):
        self.stopped = True
        print("server stopped, it will shutdown soon :)")
        self.destroy()

    def arp_sweep(self, subnet):

        self.after(0, self.append_log, f"SERVER: ARP sweep on {subnet}")
        pkt = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=subnet)
        answered, _ = srp(pkt, timeout=2, verbose=0, iface=conf.iface)

        table = {}
        for _, rcv in answered:
            ip, mac = rcv.psrc, rcv.hwsrc
            self.after(0, self.append_log, f"SERVER: found {ip} @ {mac}")
            table[ip] = mac
        return table

    def inject_reqs(self, conn, table):
        active_iface = conf.iface 
        server_ip = self.get_primary_local_ip()

        while not self.stopped:
            try:
                hdr = self.recv_exact(conn, 4)
                if not hdr: return
                length = int.from_bytes(hdr, 'big')
                payload = self.recv_exact(conn, length)
                sid = payload[:16].hex()
                data = payload[16:]
                pkt = IP(data)
                
                if ICMP in pkt and pkt[ICMP].type == 8:
                    
                    # Save the original client IP so we know who to send the reply back to later
                    # (Or just rely on the sniff_repls logic below)
                    
                    pkt[IP].src = server_ip # Mask the client's IP with the Server's IP
                    
                    # Delete checksums so Scapy recalculates them for the new IP
                    del pkt[IP].chksum
                    if ICMP in pkt:
                        del pkt[ICMP].chksum
                    
                    dst = pkt[IP].dst
                    mac = table.get(dst)
                    eth = Ether(dst=mac)/pkt if mac else Ether(dst="ff:ff:ff:ff:ff:ff")/pkt
                    
                    sendp(eth, iface=active_iface, verbose=0)
                    self.after(0, self.append_log, f"NAT Inject: {server_ip} -> {dst}")
            except Exception as e:
                print(f"Injection error: {e}")
            except socket.timeout:
                self._log("Connection timeout")



    def sniff_repls(self, conn, client_ip):
        try:
            active_iface = conf.iface
            server_ip = self.get_primary_local_ip()
            
            # Filter for ICMP replies sent to the Server IP
            filter_str = f"icmp and dst host {server_ip} and icmp[0] == 0" 
            
            def prn(pkt):
                if IP in pkt:
                    # We change the destination back to the Client IP 
                    # so the client Scapy parser recognizes it
                    pkt[IP].dst = client_ip
                    
                    raw = bytes(pkt[IP])
                    try:
                        conn.sendall(len(raw).to_bytes(4, 'big') + raw)
                        self.after(0, self.append_log, f"Tunneled reply from {pkt.src} back to client")
                    except:
                        return True 

            sniff(iface=active_iface, filter=filter_str, prn=prn, store=0)
        except socket.timeout:
            self._log("Connection timeout")

    def get_primary_local_ip(self):

        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
        finally:
            s.close()

    def get_local_subnet(self):

        local_ip = self.get_primary_local_ip()

        for iface_name, addrs in psutil.net_if_addrs().items():
            for addr in addrs:
                if addr.family == socket.AF_INET and addr.address == local_ip:
                    if addr.netmask:
                        network = ipaddress.IPv4Network(f"{addr.address}/{addr.netmask}", strict=False)
                        return str(network)

        raise RuntimeError(f"Could not determine subnet for local IP {local_ip}")
    
    def recv_exact(sock, size):
        #makes sure you get the full length of bytes in recv
        data = b""

        while len(data) < size:
            chunk = sock.recv(size - len(data))

            if not chunk:
                raise ConnectionError("Socket closed")

            data += chunk

        return data

if __name__ == "__main__":
    TestVPNServerAppGui().mainloop()