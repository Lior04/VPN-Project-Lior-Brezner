import tkinter as tk
from tkinter import messagebox, PhotoImage
from tkinter.scrolledtext import ScrolledText
import socket, ssl, threading, json
from PIL import Image, ImageTk
from scapy.all import send, conf, get_if_hwaddr
from scapy.layers.inet import IP, ICMP
import os

SERVER_PORT = 8443

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CERT_FILE = os.path.join(BASE_DIR, "cert.pem")
KEY_FILE = os.path.join(BASE_DIR, "key.pem")

class VPNClientApp(tk.Tk):

    def __init__(self):
        super().__init__()
        self.conn = None
        self.title("Python VPN Client")
        self.geometry("1080x1080")
        self.attributes("-fullscreen", True)
        self.bind("<Escape>", self.toggle_fullscreen)

        self.local_ip = None
        self.allowed = set()  
        self.pending = {}  

        img = Image.open("logo.png")
        img = img.resize((250, 250), resample=Image.Resampling.LANCZOS)
        logo = ImageTk.PhotoImage(img)
        self.logo = logo
        lf = tk.Frame(self)
        lf.pack(fill="both", expand=True)
        tk.Label(lf, image=self.logo).pack(pady=(20, 10))
        self.server_e = tk.Entry(lf)
        self.server_e.insert(0, "10.100.102.116")
        self.server_e.pack(pady=5)

        tk.Label(lf, text="Password:").pack(pady=(10, 5))
        self.pw_e = tk.Entry(lf, show="*")
        self.pw_e.insert(0, "MyS3cureV!PN")
        self.pw_e.pack(pady=5)

        tk.Button(lf, text="Connect",
                  command=lambda: threading.Thread(target=self.handshake, daemon=True).start()
                  ).pack(pady=20)
        self.login_frame = lf

    def handshake(self):
        try:
            srv = self.server_e.get()
            raw = socket.create_connection((srv, SERVER_PORT))
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.load_verify_locations('cert.pem')
            ctx.keylog_filename = 'tls-keys.log'
            ss = ctx.wrap_socket(raw, server_hostname=srv)
            ss.settimeout(10)
            self.conn = ss

            self.local_ip = self.conn.getsockname()[0]
            mac = get_if_hwaddr(conf.iface)
            init = {'password': self.pw_e.get(), 'client_mac': mac}
            self.conn.sendall(json.dumps(init).encode())

            ch = json.loads(self.recv_exact(self.conn, 16384).decode())
            if ch['status'] == 'error':
                messagebox.showerror('server say: ' + ch['status'])
                tk.Tk.destroy(self)
                return

            key = ch['authKey']
            self.session_id = ch["session_id"]
            hosts = ch['hosts']
            self.allowed = {h['ip'] for h in hosts}

            self.conn.sendall(json.dumps({'authKey': key}).encode())
            rd = json.loads(self.recv_exact(self.conn, 4096).decode())
            if rd['status'] == 'error':
                messagebox.showerror('server say: ' + rd['status'])
                tk.Tk.destroy(self)
                return

            self.after(0, self.build_main)
        except Exception as e:
            messagebox.showerror("Connection Error", str(e))

    def build_main(self):

        self.login_frame.pack_forget()
        mf = tk.Frame(self)
        mf.pack(fill="both", expand=True, padx=10, pady=10)

        tk.Label(mf, text="Available Hosts:").grid(row=0, column=0, sticky="w")
        self.lb = tk.Listbox(mf, height=8)
        for ip in sorted(self.allowed):
            self.lb.insert(tk.END, ip)
        self.lb.grid(row=1, column=0, sticky="nsew")

        tk.Button(mf, text="Ping Selected" ,command=self.ping).grid(
            row=2, column=0, sticky="ew", pady=5
        )

        tk.Label(mf, text="Log:").grid(row=0, column=1, sticky="w", padx=(10, 0))
        self.log = ScrolledText(mf, state="disabled")
        self.log.grid(row=1, column=1, rowspan=3, sticky="nsew", padx=(10, 0))

        tk.Button(mf, text="Disconnect", command=self.disconnect).grid(
            row=4, column=0, columnspan=2, sticky="ew", pady=(10, 0)
        )

        mf.grid_columnconfigure(0, weight=1)
        mf.grid_columnconfigure(1, weight=2)
        mf.grid_rowconfigure(1, weight=1)

        threading.Thread(target=self.recv_replies, daemon=True).start()

    def ping(self):

        sel = self.lb.curselection()
        if not sel:
            return
        ip = self.lb.get(sel)
        threading.Thread(target=lambda: self._tunnel_ping(ip), daemon=True).start()

    def _tunnel_ping(self, ip):

        from threading import Timer
        pkt = IP(src=self.local_ip, dst=ip)/ICMP(type=8, id=0x1234, seq=1)
        raw = bytes(pkt)
        try:
            #adds session id to packet
            sid = bytes.fromhex(self.session_id)
            payload = sid + raw
            self.conn.sendall(len(raw).to_bytes(4,'big') + raw)
            self._log(f"→ tunneled ping {ip}")
            t = Timer(2.0, lambda: self._log(f"✗ no reply {ip}"))
            self.pending[ip] = t; t.start()
        except Exception as e:
            self._log(f"error {e}")

    def recv_replies(self):

        while True:
            hdr = self.recv_exact(self.conn, 4)
            if not hdr:
                self._log("Server closed")
                return
            length = int.from_bytes(hdr,'big')
            data = self.recv_exact(self.conn, length)
            pkt = IP(data)
            if ICMP in pkt and pkt[ICMP].type == 0:
                src = pkt.src
                self._log(f"← reply {src} → {pkt.dst}")
                t = self.pending.pop(src, None)
                if t:
                    t.cancel()


    def recv_exact(self, conn, size):
        #makes sure you get the full length of bytes in recv
        data = b""

        while len(data) < size:
            chunk = conn.recv(size - len(data))

            if not chunk:
                raise ConnectionError("Socket closed")

            data += chunk

        return data

    def _log(self, msg):
        self.log.config(state="normal")
        self.log.insert(tk.END, msg + "\n")
        self.log.config(state="disabled")
        self.log.yview(tk.END)
    def toggle_fullscreen(self, event=None):
        is_full = self.attributes("-fullscreen")
        self.attributes("-fullscreen", not is_full)

    def disconnect(self):
        if self.conn:
            self.conn.close()
        self.destroy()







if __name__ == "__main__":
    VPNClientApp().mainloop()