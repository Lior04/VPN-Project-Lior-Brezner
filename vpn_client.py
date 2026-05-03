import tkinter as tk
from tkinter import messagebox, PhotoImage
from tkinter.scrolledtext import ScrolledText
import socket, ssl, threading, json
from scapy.all import send, conf, get_if_hwaddr
from scapy.layers.inet import IP, ICMP

SERVER_PORT = 8443

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
        raw = socket.create_connection((srv, SERVER_PORT))
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

        ss.sendall(json.dumps({'authKey':key}).encode())
        rd = json.loads(ss.recv(4096).decode())

        self.after(0, self.build_main)
    

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
        mf.pack(fill="both", expand=True, padx=10, pady=10)

        tk.Label(mf, text="Available Hosts:").grid(row=0,column=0,sticky="w")
        self.lb = tk.Listbox(mf, height=8)
        for ip in sorted(self.allowed):
            self.lb.insert(tk.END, ip)
        self.lb.grid(row=1,column=0,sticky="nsew")

        tk.Button(mf, text="Ping Selected", command=self.ping).grid(
            row=2,column=0,sticky="ew", pady=5
        )

        tk.Label(mf, text="Log:").grid(row=0,column=1,sticky="w",padx=(10,0))
        self.log = ScrolledText(mf, state="disabled")
        self.log.grid(row=1,column=1,rowspan=3,sticky="nsew",padx=(10,0))

        tk.Button(mf, text="Disconnect", command=self.disconnect).grid(
            row=4,column=0,columnspan=2,sticky="ew", pady=(10,0)
        )

        mf.grid_columnconfigure(0, weight=1)
        mf.grid_columnconfigure(1, weight=2)
        mf.grid_rowconfigure(1, weight=1)

        threading.Thread(target=self.recv_replies, daemon=True).start()
        


    def ping(self):
        ip = self.lb.get(self.lb.curselection())
        threading.Thread(target=lambda: self._tunnel_ping(ip), daemon=True).start()
        
    
    


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

