import tkinter as tk
from tkinter import messagebox, PhotoImage
from tkinter.scrolledtext import ScrolledText
import socket, ssl, threading, json
from scapy.all import send, conf, get_if_hwaddr
from scapy.layers.inet import IP, ICMP, sr1


class VPNClientApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Python VPN Client")
        self.geometry("800x400")
        self.conn = None
        self.local_ip = None
        self.allowed = set()
        self.pending = {}
        lf = tk.Frame(self)
        lf.pack(fill="both", expand=True)
        tk.Label(lf, text="Server IP:").pack(pady=(10, 5))
        self.server_e = tk.Entry(lf)
        self.server_e.insert(0, "127.0.0.1")  # safer default for testing
        self.server_e.pack(pady=5)
        tk.Label(lf, text="Password:").pack()
        self.pw_e = tk.Entry(lf, show="*")
        self.pw_e.pack()
        tk.Button(lf, text="Connect",
                  command=lambda: threading.Thread(
                      target=self.handshake,
                      daemon=True
                  ).start()
                  ).pack()

    def handshake(self):
        srv = self.server_e.get()
        raw = socket.create_connection((srv, 8443))
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ss = ctx.wrap_socket(raw, server_hostname=srv)
        self.conn = ss
        self.local_ip = ss.getsockname()[0]

        mac = get_if_hwaddr(conf.iface)

        init = {
            'password': self.pw_e.get(),
            'client_mac': mac
        }

        ss.sendall(json.dumps(init).encode())

        ch = json.loads(ss.recv(16384).decode())

        key = ch['authKey']
        hosts = ch['hosts']
        self.allowed = {h['ip'] for h in hosts}

        {h['ip'] for h in hosts}

        ss.recv(4096)

        self.after(0, self.build_main)
        threading.Thread(target=self.receive_loop, daemon=True).start()
    

    def send_packet(self, raw_bytes, dst_ip):
        message = {
            "type" : "ICMP",
            "id": self.packet_id,
            "dst": dst_ip,
            "payload": raw_bytes.hex()
        }

        data = json.dumps(message).encode()

        self.conn.sendall(len(data).to_bytes(4, 'big') + data)
        print(f"[+] Sent packet {self.packet_id} to {dst_ip}")

        self.packet_id += 1



    def build_main(self):
        self.login_frame.pack_forget()
        mf = tk.Frame(self)
        mf.pack(fill="both", expand=True)

        self.lb = tk.Listbox(mf)
        for ip in self.allowed:
            self.lb.insert(tk.END, ip)
        self.lb.pack()

        tk.Button(mf, text="Ping", command=self.ping).pack()

    def ping(self):
        ip = self.lb.get(self.lb.curselection())
        threading.Thread(target=lambda: self._tunnel_ping(ip), daemon=True).start()
        pkt = IP(src=self.local_ip, dst=ip) / ICMP()
        raw = bytes(pkt)

        self.send_packet(raw, ip)


    def recv_replies(self):
        while True:
            hdr = self.conn.recv(4)
            length = int.from_bytes(hdr, 'big')

            data = self.conn.recv(length)

            pkt = IP(data)

            if ICMP in pkt and pkt[ICMP].type == 0:
                print("Reply from", pkt.src)
                threading.Thread(target=self.recv_replies, daemon=True).start()

    def receive_loop(self):
        while True:
            try:
                hdr = self.conn.recv(4)
                if not hdr:
                    break

                length = int.from_bytes(hdr, 'big')

                data = self.conn.recv(length)
                msg = json.loads(data.decode())

                if msg["type"] == "ICMP_REPLY":
                    print(f"[+] Reply from {msg['src']} (id={msg['id']})")

            except Exception as e:
                print("Error receiving:", e)
                break


if __name__ == "__main__":
    VPNClientApp().mainloop()

