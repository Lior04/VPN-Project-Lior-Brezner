import socket, ssl, threading, json, random, string, sqlite3
from scapy.layers.l2 import Ether, ARP
from scapy.all import srp, sniff, sendp, conf
from scapy.layers.inet import IP, ICMP
import tkinter as tk
from tkinter.scrolledtext import ScrolledText
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CERT_FILE = os.path.join(BASE_DIR, "cert.pem")
KEY_FILE = os.path.join(BASE_DIR, "key.pem")





class VPNServerApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Python VPN Server")
        self.geometry("760x560")

        self.log_widget = ScrolledText(self, state="disabled")
        self.log_widget.pack(fill="both", expand=True)

        btn = tk.Button(self, text="Stop Server", bg="red", fg="white", command=self.stop_server)
        btn.pack(pady=10)

        self.stopped = False
        self.server_thread = threading.Thread(target=self.server_loop, daemon=True)
        self.server_thread.start()

    def append_log(self, msg):
        self.log_widget.config(state="normal")
        self.log_widget.insert(tk.END, msg + "\n")
        self.log_widget.config(state="disabled")
        self.log_widget.yview(tk.END)

    def server_loop(self):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(CERT_FILE, KEY_FILE)

        raw_sock = socket.socket()
        raw_sock.bind(("0.0.0.0", 8443))
        raw_sock.listen(5)

        self.append_log("Server listening...")

        while not self.stopped:
            try:
                client_sock, addr = raw_sock.accept()
                self.append_log(f"[+] TCP connection from {addr}")

                tls_conn = ctx.wrap_socket(client_sock, server_side=True)
                self.append_log(f"[+] TLS established with {addr}")

                threading.Thread(
                    target=self.handle_client,
                    args=(tls_conn, addr),
                    daemon=True
                ).start()

            except Exception as e:
                self.append_log(f"[ERROR] {e}")


    def gen_auth_key(self, n=8):
        chars = string.ascii_letters + string.digits
        return "".join(random.choice(chars) for _ in range(n))

    def get_local_subnet(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            # doesn't actually send anything, just figures out route
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
        finally:
            s.close()

        # assume /24 subnet
        subnet = local_ip + "/24"
        return subnet

    def handle_client(self, conn, addr):
        client_ip = addr[0]
        data = conn.recv(4096)
        init = json.loads(data.decode())

        if init.get('password') != "MyS3cureV!PN":
            conn.sendall(json.dumps({'status': 'error', 'reason': 'bad password'}).encode())
            self.after(0, self.append_log, "SERVER: bad password")
            conn.close()
            return

        self.after(0, self.append_log, f"SERVER: auth ok for MAC {init.get('client_mac')}")

        subnet = self.get_local_subnet()
        self.after(0, self.append_log, f"SERVER: scanning subnet {subnet}")
        table = self.arp_sweep(subnet)
        key = self.gen_auth_key()

        conn.sendall(json.dumps({
            'status': 'challenge',
            'authKey': key,
            'hosts': [{'ip': ip, 'mac': mac} for ip, mac in table.items()]
        }).encode())

        ack = json.loads(conn.recv(4096).decode())

        if ack.get('authKey') != key:
            conn.sendall(json.dumps({'status': 'error', 'reason': 'bad authKey'}).encode())
            self.after(0, self.append_log, "SERVER: bad authKey")
            conn.close()
            return

        conn.sendall(json.dumps({'status': 'ready'}).encode())
        self.after(0, self.append_log, "SERVER: handshake complete, tunnel open")

        threading.Thread(target=self.inject_reqs, args=(conn, table), daemon=True).start()
        threading.Thread(target=self.sniff_repls, args=(conn, addr[0]), daemon=True).start()

    def arp_sweep(self, subnet):
        self.after(0, self.append_log, f"SERVER: ARP sweep on {subnet}")
        pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=subnet)
        answered, _ = srp(pkt, timeout=2, verbose=0, iface=conf.iface)

        table = {}
        for _, rcv in answered:
            ip, mac = rcv.psrc, rcv.hwsrc
            self.after(0, self.append_log, f"SERVER: found {ip} @ {mac}")
            table[ip] = mac

        return table

    def inject_reqs(self, conn, table):
        while not self.stopped:
            hdr = conn.recv(4)
            if not hdr:
                return
            length = int.from_bytes(hdr, 'big')
            data = conn.recv(length)
            pkt = IP(data)
            if ICMP in pkt and pkt[ICMP].type == 8:
                dst = pkt[IP].dst
                mac = table.get(dst)
                eth = Ether(dst=mac) / pkt if mac else Ether(dst="ff:ff:ff:ff:ff:ff") / pkt
                tag = mac if mac else "broadcast"
                self.after(0, self.append_log, f"SERVER: inject {pkt.src}→{pkt.dst} @ {tag}")
                sendp(eth, iface=conf.iface, verbose=0)

    def sniff_repls(self, conn, client_ip):
        iface = conf.iface
        self.after(0, self.append_log, f"SERVER: sniffing replies on {iface} for {client_ip}")

        def prn(pkt):
            if IP in pkt and ICMP in pkt and pkt[IP].dst == client_ip and pkt[ICMP].type == 0:
                raw = bytes(pkt[IP])
                self.after(0, self.append_log, f"SERVER: captured reply {pkt.src}→{pkt.dst}")
                conn.sendall(len(raw).to_bytes(4, 'big') + raw)

        sniff(iface=iface, filter=f"icmp and dst host {client_ip}", prn=prn, store=0)

    def stop_server(self):
        self.stopped = True
        self.sock.close()
        self.destroy()


if __name__ == "__main__":
    VPNServerApp().mainloop()
