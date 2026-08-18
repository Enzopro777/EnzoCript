"""
EnzoCrypt — Encrypt any file. Send it anywhere. No cloud required.
V2 — Streaming chunk architecture, responsive UI
"""

import os
import sys
import secrets
import struct
import time
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend

# ── DPI awareness (Windows only) ──────────────────────────────────────────────
try:
    import ctypes
    ctypes.windll.shcore.SetProcessDpiAwareness(1)
except Exception:
    pass

# ── constants ──────────────────────────────────────────────────────────────────
MAGIC          = b"ENZO"
VERSION_V1     = 1
VERSION_V2     = 2
CONTAINER_EXT  = ".enzocrypt"
BENCHMARK_SIZE = 1 * 1024 * 1024
MIN_CHUNK_SIZE = 1 * 1024 * 1024
MAX_CHUNK_SIZE = 64 * 1024 * 1024
MAX_EXT_LEN    = 255
MAX_RSA_LEN    = 4096
MAX_CHUNKS     = 2**32 - 1

CHUNK_PRESETS = {
    "Low RAM  (1 MB)":    1 * 1024 * 1024,
    "Balanced (8 MB)":    8 * 1024 * 1024,
    "Fast     (32 MB)":  32 * 1024 * 1024,
    "Max speed (64 MB)": 64 * 1024 * 1024,
}
DEFAULT_PRESET = "Balanced (8 MB)"

# ── palette ────────────────────────────────────────────────────────────────────
BG      = "#0F1117"
PANEL   = "#1A1D27"
ACCENT  = "#6C63FF"
ACCENT2 = "#A78BFA"
SUCCESS = "#10B981"
DANGER  = "#EF4444"
WARNING = "#F59E0B"
TEXT    = "#E2E8F0"
SUBTEXT = "#94A3B8"
BORDER  = "#2D3148"
ENTRY   = "#252837"
BTN_FG  = "#FFFFFF"

FT = ("Segoe UI", 22, "bold")
FH = ("Segoe UI", 12, "bold")
FB = ("Segoe UI", 10)
FS = ("Segoe UI", 9)
FK = ("Segoe UI", 10, "bold")
FM = ("Courier New", 9)


# ─────────────────────────────────────────────────────────────────────────────
# SCROLLABLE FRAME — wraps any tab so it works on small screens
# ─────────────────────────────────────────────────────────────────────────────

class ScrollableFrame(tk.Frame):
    """
    A frame with a vertical scrollbar that appears only when needed.
    Children should be packed into self.inner, not self.
    Mouse wheel works on Windows, macOS, and Linux.
    """
    def __init__(self, parent, bg=BG, **kw):
        super().__init__(parent, bg=bg, **kw)
        self._bg = bg

        self._canvas = tk.Canvas(self, bg=bg, bd=0,
                                 highlightthickness=0, takefocus=False)
        self._scrollbar = ttk.Scrollbar(self, orient="vertical",
                                        command=self._canvas.yview)
        self._canvas.configure(yscrollcommand=self._scrollbar.set)

        self._canvas.pack(side="left", fill="both", expand=True)
        # Scrollbar is shown/hidden dynamically
        self._sb_visible = False

        self.inner = tk.Frame(self._canvas, bg=bg)
        self._win_id = self._canvas.create_window(
            (0, 0), window=self.inner, anchor="nw")

        self.inner.bind("<Configure>", self._on_inner_configure)
        self._canvas.bind("<Configure>", self._on_canvas_configure)

        # Mouse wheel
        for widget in (self._canvas, self.inner):
            widget.bind("<Enter>", self._bind_wheel)
            widget.bind("<Leave>", self._unbind_wheel)

    def _on_inner_configure(self, event=None):
        self._canvas.configure(scrollregion=self._canvas.bbox("all"))
        self._toggle_scrollbar()

    def _on_canvas_configure(self, event=None):
        self._canvas.itemconfig(self._win_id, width=event.width)
        self._toggle_scrollbar()

    def _toggle_scrollbar(self):
        inner_h  = self.inner.winfo_reqheight()
        canvas_h = self._canvas.winfo_height()
        if inner_h > canvas_h and not self._sb_visible:
            self._scrollbar.pack(side="right", fill="y", before=self._canvas)
            self._sb_visible = True
        elif inner_h <= canvas_h and self._sb_visible:
            self._scrollbar.pack_forget()
            self._sb_visible = False

    def _bind_wheel(self, event):
        self._canvas.bind_all("<MouseWheel>",   self._on_wheel)
        self._canvas.bind_all("<Button-4>",     self._on_wheel)
        self._canvas.bind_all("<Button-5>",     self._on_wheel)

    def _unbind_wheel(self, event):
        self._canvas.unbind_all("<MouseWheel>")
        self._canvas.unbind_all("<Button-4>")
        self._canvas.unbind_all("<Button-5>")

    def _on_wheel(self, event):
        if event.num == 4:
            self._canvas.yview_scroll(-1, "units")
        elif event.num == 5:
            self._canvas.yview_scroll(1, "units")
        else:
            delta = -1 if event.delta > 0 else 1
            self._canvas.yview_scroll(delta, "units")


# ─────────────────────────────────────────────────────────────────────────────
# CRYPTO CORE
# ─────────────────────────────────────────────────────────────────────────────

def _oaep():
    return padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(), label=None)

def _aad(idx: int) -> bytes:
    return MAGIC + struct.pack("<HI", VERSION_V2, idx)

def _read_exact(f, n, what="data") -> bytes:
    d = f.read(n)
    if len(d) != n:
        raise ValueError(f"Truncated EnzoCrypt file: expected {n} bytes for {what}.")
    return d

def _ru8(f, w):  return struct.unpack("B",  _read_exact(f, 1, w))[0]
def _ru16(f, w): return struct.unpack("<H", _read_exact(f, 2, w))[0]
def _ru32(f, w): return struct.unpack("<I", _read_exact(f, 4, w))[0]

def _scan_chunks(path, offset, chunk_size):
    total = 0; plaintext_bytes = 0
    sz = os.path.getsize(path)
    with open(path, "rb") as f:
        f.seek(offset)
        while True:
            hdr = f.read(4)
            if not hdr: break
            if len(hdr) != 4: raise ValueError("Truncated chunk header.")
            ct_len = struct.unpack("<I", hdr)[0]
            if ct_len > chunk_size: raise ValueError("Invalid chunk length.")
            if f.tell() + 12 + 16 + ct_len > sz: raise ValueError("Truncated chunk.")
            f.seek(12 + 16 + ct_len, 1)
            total += 1; plaintext_bytes += ct_len
            if total > MAX_CHUNKS: raise ValueError("Too many chunks.")
    return total, plaintext_bytes

def benchmark_speed(chunk_size: int) -> float:
    key = secrets.token_bytes(32); nonce = secrets.token_bytes(12)
    data = secrets.token_bytes(BENCHMARK_SIZE)
    t0 = time.perf_counter()
    AESGCM(key).encrypt(nonce, data, _aad(0))
    return BENCHMARK_SIZE / (time.perf_counter() - t0) / (1024*1024)

def generate_identity(save_dir, name, passphrase):
    pk = rsa.generate_private_key(65537, 2048, default_backend())
    pub = pk.public_key()
    priv_pem = pk.private_bytes(serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.BestAvailableEncryption(passphrase))
    pub_pem = pub.public_bytes(serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo)
    pp = os.path.join(save_dir, f"{name}_private.pem")
    qp = os.path.join(save_dir, f"{name}_public.pem")
    open(pp,"wb").write(priv_pem); open(qp,"wb").write(pub_pem)
    return pp, qp

def encrypt_file_v2(input_path, pub_key_path, output_path,
                    chunk_size, progress_cb=None, cancel_flag=None):
    if not (MIN_CHUNK_SIZE <= chunk_size <= MAX_CHUNK_SIZE):
        raise ValueError("Invalid chunk size.")
    pub = serialization.load_pem_public_key(open(pub_key_path,"rb").read())
    aes_key = secrets.token_bytes(32)
    rsa_blob = pub.encrypt(aes_key, _oaep())
    aesgcm = AESGCM(aes_key)
    ext = os.path.splitext(input_path)[1].encode()[:MAX_EXT_LEN]
    file_size = os.path.getsize(input_path)
    total_chunks = max(1, (file_size + chunk_size - 1) // chunk_size)
    mbs = benchmark_speed(chunk_size)
    with open(input_path,"rb") as fin, open(output_path,"wb") as fout:
        fout.write(MAGIC + struct.pack("<H", VERSION_V2)
                   + struct.pack("B", len(ext)) + ext
                   + struct.pack("<H", len(rsa_blob)) + rsa_blob
                   + struct.pack("<I", chunk_size))
        idx = 0; processed = 0; t0 = time.perf_counter()
        while True:
            if cancel_flag and cancel_flag.is_set():
                raise InterruptedError()
            pt = fin.read(chunk_size)
            if not pt and not (file_size == 0 and idx == 0): break
            nonce = secrets.token_bytes(12)
            ct_tag = aesgcm.encrypt(nonce, pt, _aad(idx))
            ct, tag = ct_tag[:-16], ct_tag[-16:]
            fout.write(struct.pack("<I", len(ct)) + nonce + tag + ct)
            processed += len(pt); idx += 1
            if progress_cb:
                elapsed = time.perf_counter() - t0
                speed = (processed/1048576)/elapsed if elapsed > 0 else mbs
                eta = max(0, (file_size - processed)/1048576) / speed if speed > 0 else 0
                progress_cb(idx, total_chunks, eta)

def decrypt_file_v2(container_path, priv_key_path, passphrase, output_path,
                    progress_cb=None, cancel_flag=None):
    pk = serialization.load_pem_private_key(
        open(priv_key_path,"rb").read(), password=passphrase)
    with open(container_path,"rb") as fin:
        if _read_exact(fin,4,"magic") != MAGIC:
            raise ValueError("Not an EnzoCrypt file.")
        v = _ru16(fin,"version")
        if v != VERSION_V2:
            raise ValueError(f"Format V{v} — use matching EnzoCrypt version.")
        el = _ru8(fin,"ext len"); ext = _read_exact(fin,el,"ext").decode()
        rl = _ru16(fin,"rsa len")
        if not 1 <= rl <= MAX_RSA_LEN: raise ValueError("Invalid RSA data.")
        rsa_blob = _read_exact(fin,rl,"rsa blob")
        cs = _ru32(fin,"chunk size")
        if not (MIN_CHUNK_SIZE <= cs <= MAX_CHUNK_SIZE): raise ValueError("Invalid chunk size.")
        data_offset = fin.tell()
        try:    aes_key = pk.decrypt(rsa_blob, _oaep())
        except: raise ValueError("Could not decrypt key. Wrong private key?")
        if len(aes_key) != 32: raise ValueError("Invalid AES key.")
        aesgcm = AESGCM(aes_key)
        total_chunks, total_pt = _scan_chunks(container_path, data_offset, cs)
        if total_chunks == 0: raise ValueError("No data chunks in file.")
        base,_ = os.path.splitext(output_path)
        fp = output_path if output_path.lower().endswith(ext.lower()) else base+ext
        mbs = benchmark_speed(cs); t0 = time.perf_counter()
        idx = 0; processed = 0
        with open(fp,"wb") as fout:
            while True:
                if cancel_flag and cancel_flag.is_set(): raise InterruptedError()
                hdr = fin.read(4)
                if not hdr: break
                ct_len = struct.unpack("<I", hdr)[0]
                nonce = _read_exact(fin,12,"nonce")
                tag   = _read_exact(fin,16,"tag")
                ct    = _read_exact(fin,ct_len,"ct")
                try:    pt = aesgcm.decrypt(nonce, ct+tag, _aad(idx))
                except: raise ValueError(f"Integrity failed on chunk {idx}. Tampered?")
                fout.write(pt); processed += len(pt); idx += 1
                if progress_cb:
                    elapsed = time.perf_counter()-t0
                    speed = (processed/1048576)/elapsed if elapsed>0 else mbs
                    eta = max(0,(total_pt-processed)/1048576)/speed if speed>0 else 0
                    progress_cb(idx, total_chunks, eta)
        if idx != total_chunks: raise ValueError("File ended unexpectedly.")

def decrypt_file_v1(container_path, priv_key_path, passphrase, output_path):
    pk = serialization.load_pem_private_key(
        open(priv_key_path,"rb").read(), password=passphrase)
    with open(container_path,"rb") as f:
        _read_exact(f,4,"magic"); _ru16(f,"ver")
        el = _ru8(f,"ext len"); ext = _read_exact(f,el,"ext").decode()
        rl = _ru16(f,"rsa len"); rsa_blob = _read_exact(f,rl,"rsa")
        nonce = _read_exact(f,12,"nonce"); tag = _read_exact(f,16,"tag"); ct = f.read()
    try:
        aes_key = pk.decrypt(rsa_blob, _oaep())
        pt = AESGCM(aes_key).decrypt(nonce, ct+tag, None)
    except: raise ValueError("Wrong key or tampered file.")
    base,_ = os.path.splitext(output_path)
    fp = output_path if output_path.lower().endswith(ext.lower()) else base+ext
    open(fp,"wb").write(pt)


# ─────────────────────────────────────────────────────────────────────────────
# UI HELPERS
# ─────────────────────────────────────────────────────────────────────────────

def ui(widget, fn, *args, **kw):
    """Schedule fn on the Tk main thread."""
    widget.winfo_toplevel().after(0, lambda: fn(*args, **kw))

def _btn(parent, text, cmd, color=ACCENT, width=22):
    return tk.Button(parent, text=text, command=cmd,
                     bg=color, fg=BTN_FG, font=FK,
                     relief="flat", cursor="hand2",
                     padx=10, pady=7, width=width,
                     activebackground=ACCENT2, activeforeground=BTN_FG,
                     bd=0, highlightthickness=0)

def _card(parent, title):
    """Returns a card Frame with a title label already packed inside."""
    f = tk.Frame(parent, bg=PANEL, highlightthickness=1,
                 highlightbackground=BORDER)
    f.pack(fill="x", padx=16, pady=6, ipady=4)
    tk.Label(f, text=title, font=FH, fg=ACCENT2, bg=PANEL,
             anchor="w").pack(anchor="w", padx=14, pady=(8,3))
    return f

def _filelabel(parent, text="—"):
    lbl = tk.Label(parent, text=text, font=FM, fg=SUBTEXT, bg=PANEL,
                   anchor="w", wraplength=440, justify="left")
    lbl.pack(anchor="w", padx=14, pady=(0,4))
    return lbl

def _divider(parent):
    tk.Frame(parent, height=1, bg=BORDER).pack(fill="x", padx=16, pady=3)

def _status_bar(parent):
    bar = tk.Label(parent, text="Ready", font=FS, fg=SUBTEXT,
                   bg=BG, anchor="w", padx=12)
    bar.pack(fill="x", side="bottom", pady=(3,5))
    return bar

def _password_dialog(title, prompt, confirm=False, parent=None):
    res = [None]
    dlg = tk.Toplevel(parent); dlg.title(title)
    dlg.geometry("340x215" if confirm else "340x185")
    dlg.configure(bg=BG); dlg.resizable(False,False); dlg.grab_set()
    tk.Label(dlg, text=title, font=FH, fg=ACCENT2, bg=BG).pack(pady=(16,2))
    tk.Label(dlg, text=prompt, font=FB, fg=SUBTEXT, bg=BG).pack(pady=(0,5))
    e1 = tk.Entry(dlg, show="●", font=FB, width=28,
                  bg=PANEL, fg=TEXT, insertbackground=TEXT,
                  relief="flat", bd=5)
    e1.pack(ipady=4); e1.focus_set()
    e2 = None
    if confirm:
        tk.Label(dlg, text="Confirm:", font=FS, fg=SUBTEXT, bg=BG).pack(pady=(6,2))
        e2 = tk.Entry(dlg, show="●", font=FB, width=28,
                      bg=PANEL, fg=TEXT, insertbackground=TEXT,
                      relief="flat", bd=5)
        e2.pack(ipady=4)
    def ok(ev=None):
        pw = e1.get()
        if not pw: return
        if confirm and e2 and e2.get() != pw:
            messagebox.showerror("Mismatch","Passwords don't match.",parent=dlg); return
        res[0] = pw.encode(); dlg.destroy()
    bf = tk.Frame(dlg, bg=BG); bf.pack(pady=10)
    _btn(bf,"OK",ok,width=8).pack(side="left",padx=5)
    _btn(bf,"Cancel",dlg.destroy,color=BORDER,width=8).pack(side="left",padx=5)
    e1.bind("<Return>",ok); dlg.wait_window(); return res[0]


# ─────────────────────────────────────────────────────────────────────────────
# PROGRESS PANEL
# ─────────────────────────────────────────────────────────────────────────────

class ProgressPanel(tk.Frame):
    def __init__(self, parent, **kw):
        super().__init__(parent, bg=PANEL, **kw)
        self._root = parent.winfo_toplevel()
        self._pct  = tk.StringVar(value="0%")
        self._eta  = tk.StringVar(value="")
        self._info = tk.StringVar(value="")
        self._val  = 0.0

        top = tk.Frame(self, bg=PANEL)
        top.pack(fill="x", padx=14, pady=(8,2))
        tk.Label(top, textvariable=self._info, font=FS, fg=TEXT,
                 bg=PANEL, anchor="w").pack(side="left")
        tk.Label(top, textvariable=self._pct, font=FS, fg=ACCENT2,
                 bg=PANEL, anchor="e").pack(side="right")

        self._cv = tk.Canvas(self, height=8, bg=ENTRY, bd=0, highlightthickness=0)
        self._cv.pack(fill="x", padx=14, pady=(0,3))
        self._cv.bind("<Configure>", lambda e: self._draw())

        tk.Label(self, textvariable=self._eta, font=FS, fg=SUBTEXT,
                 bg=PANEL, anchor="w").pack(anchor="w", padx=14, pady=(0,8))

    def reset(self, label="Working…"):
        self._val = 0.0
        self._pct.set("0%"); self._info.set(label); self._eta.set("")
        self._draw()

    def update(self, done, total, eta):
        self._root.after(0, self._update, done, total, eta)

    def _update(self, done, total, eta):
        if total <= 0: return
        self._val = min(1.0, done/total)
        self._pct.set(f"{self._val*100:.0f}%")
        self._info.set(f"Chunk {done} / {total}")
        if   eta >= 3600: self._eta.set(f"ETA  {eta/3600:.1f} h")
        elif eta >= 60:   self._eta.set(f"ETA  {eta/60:.0f} min {int(eta)%60} s")
        elif eta > 1:     self._eta.set(f"ETA  {eta:.0f} s")
        else:             self._eta.set("ETA  < 1 s")
        self._draw()

    def done(self):
        self._update(1, 1, 0); self._eta.set("Complete ✓")

    def error(self, msg):
        self._info.set("Failed"); self._eta.set(str(msg)[:70])

    def _draw(self):
        w = self._cv.winfo_width(); h = 8
        if w < 2: return
        self._cv.delete("all")
        self._cv.create_rectangle(0,0,w,h, fill=ENTRY, outline="")
        fw = int(w * self._val)
        if fw > 0:
            self._cv.create_rectangle(0,0,fw,h,
                fill=SUCCESS if self._val >= 1.0 else ACCENT, outline="")


# ─────────────────────────────────────────────────────────────────────────────
# SPEED SELECTOR
# ─────────────────────────────────────────────────────────────────────────────

class SpeedSelector(tk.Frame):
    def __init__(self, parent, **kw):
        super().__init__(parent, bg=PANEL, **kw)
        self._var = tk.StringVar(value=DEFAULT_PRESET)
        self._bench_var = tk.StringVar(value="")

        row = tk.Frame(self, bg=PANEL)
        row.pack(fill="x", padx=14, pady=(4,2))
        tk.Label(row, text="Speed / RAM:", font=FB, fg=TEXT, bg=PANEL).pack(side="left")
        tk.Label(row, textvariable=self._bench_var, font=FS,
                 fg=SUBTEXT, bg=PANEL).pack(side="right")

        menu = tk.OptionMenu(self, self._var, *CHUNK_PRESETS.keys())
        menu.config(bg=PANEL, fg=TEXT, font=FB, relief="flat",
                    bd=0, highlightthickness=0, activebackground=BORDER,
                    cursor="hand2", anchor="w")
        menu["menu"].config(bg=PANEL, fg=TEXT, font=FB)
        menu.pack(anchor="w", padx=14, pady=(0,4), fill="x")
        _btn(self, "Run benchmark", self._bench, color=BORDER, width=14).pack(
            anchor="w", padx=14, pady=(0,8))

    def chunk_size(self) -> int:
        return CHUNK_PRESETS[self._var.get()]

    def _bench(self):
        self._bench_var.set("Benchmarking…")
        self.update_idletasks()
        try:
            mbs = benchmark_speed(self.chunk_size())
            self._bench_var.set(f"~{mbs:.0f} MB/s")
        except Exception as e:
            self._bench_var.set(f"Error: {e}")


# ─────────────────────────────────────────────────────────────────────────────
# RETRO IDENTITY ANIMATION
# ─────────────────────────────────────────────────────────────────────────────

class RetroIdentityAnimation(tk.Frame):
    """
    Lightweight retro-terminal animation for the Identity tab.
    Uses only Tkinter Canvas + after(), so it requires no images/GIFs
    and consumes very little CPU.
    """
    def __init__(self, parent, width=520, height=118, **kw):
        super().__init__(parent, bg=PANEL, **kw)
        self._canvas = tk.Canvas(
            self,
            width=width,
            height=height,
            bg="#0A0C10",
            bd=0,
            highlightthickness=1,
            highlightbackground=BORDER,
        )
        self._canvas.pack(fill="x", expand=True, padx=14, pady=(2, 10))

        self._frame = 0
        self._phase = 0
        self._running = True
        self._root = parent.winfo_toplevel()

        # Small fixed set of characters keeps the animation cheap.
        self._chars = "01ABCDEF"
        self._draw()
        self._tick()

    def _tick(self):
        if not self._running:
            return
        self._frame += 1
        self._phase = (self._phase + 1) % 80
        self._draw()
        self._root.after(140, self._tick)

    def _draw(self):
        c = self._canvas
        c.delete("all")

        w = max(320, c.winfo_width())
        h = max(90, c.winfo_height())

        # Background / scanlines.
        c.create_rectangle(0, 0, w, h, fill="#0A0C10", outline="")
        for y in range(8, h, 4):
            c.create_line(0, y, w, y, fill="#11151C")

        # Header.
        c.create_text(
            14, 13,
            anchor="w",
            text="> ENZOCRYPT // IDENTITY TERMINAL",
            fill=ACCENT2,
            font=("Courier New", 9, "bold"),
        )

        # Animated status cursor.
        dots = "." * (self._frame % 4)
        c.create_text(
            14, 34,
            anchor="w",
            text=f"> SECURE CHANNEL READY{dots}",
            fill=SUCCESS,
            font=("Courier New", 9),
        )

        c.create_text(
            14, 54,
            anchor="w",
            text="> ENCRYPTION : AES-256-GCM",
            fill=SUBTEXT,
            font=("Courier New", 9),
        )

        c.create_text(
            14, 72,
            anchor="w",
            text="> KEY SYSTEM : RSA-2048 / OAEP",
            fill=SUBTEXT,
            font=("Courier New", 9),
        )

        # Small animated waveform / data stream on the right.
        chars = []
        for i in range(14):
            value = (self._frame + i * 7) % 18
            chars.append("█" if value in (0, 1) else "▓" if value < 5 else "░")

        stream = "".join(chars)
        c.create_text(
            w - 14, h - 20,
            anchor="e",
            text=stream,
            fill=ACCENT,
            font=("Courier New", 10, "bold"),
        )

        # Blinking cursor.
        if (self._frame // 3) % 2 == 0:
            c.create_text(
                w - 14, 34,
                anchor="e",
                text="█",
                fill=ACCENT2,
                font=("Courier New", 10, "bold"),
            )

    def destroy(self):
        self._running = False
        super().destroy()


# ─────────────────────────────────────────────────────────────────────────────
# TABS — each tab lives inside a ScrollableFrame
# ─────────────────────────────────────────────────────────────────────────────

class IdentityTab(tk.Frame):
    def __init__(self, master, status):
        super().__init__(master, bg=BG)
        self._status = status
        sf = ScrollableFrame(self); sf.pack(fill="both", expand=True)
        p = sf.inner
        tk.Label(p, text="Your Identity", font=FT, fg=TEXT,
                 bg=BG).pack(anchor="w", padx=16, pady=(16,2))
        tk.Label(p, text="Generate your key pair once. Share only your public key.",
                 font=FB, fg=SUBTEXT, bg=BG,
                 wraplength=520).pack(anchor="w", padx=16, pady=(0,10))

        card = _card(p, "Generate new key pair")
        row = tk.Frame(card, bg=PANEL); row.pack(anchor="w", padx=14, pady=(0,4), fill="x")
        tk.Label(row, text="Name / alias:", font=FB, fg=TEXT, bg=PANEL).pack(side="left")
        self._name = tk.Entry(row, font=FB, bg=ENTRY, fg=TEXT,
                              insertbackground=TEXT, relief="flat", bd=5, width=22)
        self._name.insert(0, "my_identity")
        self._name.pack(side="left", padx=(8,0), ipady=3)
        self._res = tk.Label(card, text="", font=FS, fg=SUCCESS, bg=PANEL,
                             wraplength=480, justify="left")
        self._res.pack(anchor="w", padx=14)
        _btn(card, "Generate Key Pair", self._generate, width=22).pack(
            anchor="w", padx=14, pady=(6,12))

        _divider(p)
        info_card = _card(p, "How it works")
        tk.Label(info_card,
                 text=("Private key — Never share. Decrypt files sent to you.\n"
                       "               Protected with the password you choose.\n\n"
                       "Public key  — Send this to anyone who wants to\n"
                       "               encrypt a file for you."),
                 font=FB, fg=SUBTEXT, bg=PANEL, justify="left").pack(
            anchor="w", padx=14, pady=(0,12))

        # Lightweight retro animation that uses the spare space in Identity.
        anim_card = _card(p, "System status")
        self._retro = RetroIdentityAnimation(anim_card)
        self._retro.pack(fill="x")

    def _generate(self):
        name = "".join(c for c in self._name.get().strip()
                       if c.isalnum() or c in "-_")[:40] or "identity"
        pw = _password_dialog("Protect private key",
                              "Choose a strong password:", confirm=True,
                              parent=self.winfo_toplevel())
        if pw is None: return
        d = filedialog.askdirectory(title="Save key pair to…",
                                    parent=self.winfo_toplevel())
        if not d: return
        try:
            priv, pub = generate_identity(d, name, pw)
            self._res.config(text=f"Saved:\n  {priv}\n  {pub}")
            self._status.config(text=f"Identity '{name}' created.")
            messagebox.showinfo("Keys generated",
                f"Private: {os.path.basename(priv)}\n"
                f"Public:  {os.path.basename(pub)}\n\n"
                "Share ONLY the public key.",
                parent=self.winfo_toplevel())
        except Exception as e:
            messagebox.showerror("Error", str(e), parent=self.winfo_toplevel())


class EncryptTab(tk.Frame):
    def __init__(self, master, status):
        super().__init__(master, bg=BG)
        self._status = status
        self._file = self._pub = None
        self._cancel = threading.Event()

        sf = ScrollableFrame(self); sf.pack(fill="both", expand=True)
        p = sf.inner
        tk.Label(p, text="Encrypt a File", font=FT, fg=TEXT,
                 bg=BG).pack(anchor="w", padx=16, pady=(16,2))
        tk.Label(p, text="Select a file and the recipient's public key.",
                 font=FB, fg=SUBTEXT, bg=BG).pack(anchor="w", padx=16, pady=(0,8))

        c1 = _card(p, "① File to encrypt")
        self._file_lbl = _filelabel(c1, "No file selected")
        _btn(c1, "Browse file…", self._pick_file, width=18).pack(
            anchor="w", padx=14, pady=(0,8))

        c2 = _card(p, "② Recipient's public key")
        self._pub_lbl = _filelabel(c2, "No public key selected")
        _btn(c2, "Browse public key…", self._pick_pub, width=18).pack(
            anchor="w", padx=14, pady=(0,8))

        c3 = _card(p, "③ Speed / RAM")
        self._speed = SpeedSelector(c3); self._speed.pack(fill="x")

        c4 = _card(p, "④ Progress")
        self._prog = ProgressPanel(c4); self._prog.pack(fill="x")

        bf = tk.Frame(p, bg=BG); bf.pack(anchor="w", padx=16, pady=8)
        _btn(bf, "Encrypt & Save", self._start, width=18).pack(side="left", padx=(0,8))
        _btn(bf, "Cancel", self._cancel_op, color=BORDER, width=8).pack(side="left")

    def _pick_file(self):
        f = filedialog.askopenfilename(filetypes=[("All","*.*")],
                                       parent=self.winfo_toplevel())
        if f: self._file = f; self._file_lbl.config(text=f"  {os.path.basename(f)}", fg=TEXT)

    def _pick_pub(self):
        f = filedialog.askopenfilename(filetypes=[("PEM","*.pem"),("All","*.*")],
                                       parent=self.winfo_toplevel())
        if f: self._pub = f; self._pub_lbl.config(text=f"  {os.path.basename(f)}", fg=TEXT)

    def _cancel_op(self): self._cancel.set()

    def _start(self):
        if not self._file:
            messagebox.showwarning("Missing","Select a file first.",
                                   parent=self.winfo_toplevel()); return
        if not self._pub:
            messagebox.showwarning("Missing","Select a public key first.",
                                   parent=self.winfo_toplevel()); return
        base = os.path.splitext(os.path.basename(self._file))[0]
        out = filedialog.asksaveasfilename(
            initialfile=base+CONTAINER_EXT,
            defaultextension=CONTAINER_EXT,
            filetypes=[("EnzoCrypt",f"*{CONTAINER_EXT}"),("All","*.*")],
            parent=self.winfo_toplevel())
        if not out: return
        self._cancel.clear(); cs = self._speed.chunk_size()
        self._prog.reset("Encrypting…"); self._status.config(text="Encrypting…")

        def worker():
            try:
                encrypt_file_v2(self._file, self._pub, out, cs,
                                self._prog.update, self._cancel)
                ui(self, self._prog.done)
                ui(self, self._status.config, text=f"Encrypted → {os.path.basename(out)}")
                ui(self, messagebox.showinfo, "Done",
                   f"Encrypted!\n\n{os.path.basename(out)}")
            except InterruptedError:
                _cleanup(out); ui(self, self._prog.error, "Cancelled")
                ui(self, self._status.config, text="Cancelled.")
            except Exception as e:
                _cleanup(out); ui(self, self._prog.error, str(e))
                ui(self, messagebox.showerror, "Failed", str(e))

        threading.Thread(target=worker, daemon=True).start()


class DecryptTab(tk.Frame):
    def __init__(self, master, status):
        super().__init__(master, bg=BG)
        self._status = status
        self._cont = self._priv = None
        self._cancel = threading.Event()

        sf = ScrollableFrame(self); sf.pack(fill="both", expand=True)
        p = sf.inner
        tk.Label(p, text="Decrypt a File", font=FT, fg=TEXT,
                 bg=BG).pack(anchor="w", padx=16, pady=(16,2))
        tk.Label(p, text="Open a .enzocrypt file using your private key.",
                 font=FB, fg=SUBTEXT, bg=BG).pack(anchor="w", padx=16, pady=(0,8))

        c1 = _card(p, "① Encrypted file (.enzocrypt)")
        self._cont_lbl = _filelabel(c1, "No file selected")
        _btn(c1, "Browse encrypted file…", self._pick_cont, width=22).pack(
            anchor="w", padx=14, pady=(0,8))

        c2 = _card(p, "② Your private key (.pem)")
        self._priv_lbl = _filelabel(c2, "No private key selected")
        _btn(c2, "Browse private key…", self._pick_priv, width=22).pack(
            anchor="w", padx=14, pady=(0,8))

        c3 = _card(p, "③ Progress")
        self._prog = ProgressPanel(c3); self._prog.pack(fill="x")

        bf = tk.Frame(p, bg=BG); bf.pack(anchor="w", padx=16, pady=8)
        _btn(bf, "Decrypt & Save", self._start, width=18).pack(side="left", padx=(0,8))
        _btn(bf, "Cancel", self._cancel_op, color=BORDER, width=8).pack(side="left")

    def _pick_cont(self):
        f = filedialog.askopenfilename(
            filetypes=[("EnzoCrypt",f"*{CONTAINER_EXT}"),("All","*.*")],
            parent=self.winfo_toplevel())
        if f: self._cont = f; self._cont_lbl.config(text=f"  {os.path.basename(f)}", fg=TEXT)

    def _pick_priv(self):
        f = filedialog.askopenfilename(filetypes=[("PEM","*.pem"),("All","*.*")],
                                       parent=self.winfo_toplevel())
        if f: self._priv = f; self._priv_lbl.config(text=f"  {os.path.basename(f)}", fg=TEXT)

    def _cancel_op(self): self._cancel.set()

    def _start(self):
        if not self._cont:
            messagebox.showwarning("Missing","Select an .enzocrypt file.",
                                   parent=self.winfo_toplevel()); return
        if not self._priv:
            messagebox.showwarning("Missing","Select your private key.",
                                   parent=self.winfo_toplevel()); return
        pw = _password_dialog("Private key password",
                              "Password for your private key:",
                              parent=self.winfo_toplevel())
        if pw is None: return
        out = filedialog.asksaveasfilename(initialfile="decrypted_file",
                                           parent=self.winfo_toplevel())
        if not out: return

        # Detect version
        try:
            with open(self._cont,"rb") as f:
                if f.read(4) != MAGIC: raise ValueError("Not an EnzoCrypt file.")
                version = struct.unpack("<H", f.read(2))[0]
        except Exception as e:
            messagebox.showerror("Invalid file", str(e),
                                 parent=self.winfo_toplevel()); return
        if version not in (VERSION_V1, VERSION_V2):
            messagebox.showerror("Unsupported",
                f"Format V{version} is not supported.",
                parent=self.winfo_toplevel()); return

        self._cancel.clear()
        self._prog.reset("Decrypting…"); self._status.config(text="Decrypting…")

        def worker():
            try:
                if version == VERSION_V1:
                    decrypt_file_v1(self._cont, self._priv, pw, out)
                else:
                    decrypt_file_v2(self._cont, self._priv, pw, out,
                                    self._prog.update, self._cancel)
                ui(self, self._prog.done)
                ui(self, self._status.config, text="Decrypted successfully.")
                ui(self, messagebox.showinfo, "Done",
                   "Decrypted successfully.\nOriginal extension restored.")
            except InterruptedError:
                _cleanup(out); ui(self, self._prog.error, "Cancelled")
                ui(self, self._status.config, text="Cancelled.")
            except ValueError as e:
                _cleanup(out); ui(self, self._prog.error, str(e))
                ui(self, messagebox.showerror, "Failed", str(e))
            except Exception as e:
                _cleanup(out)
                msg = ("Wrong password or corrupted key."
                       if "password" in str(e).lower() else str(e))
                ui(self, self._prog.error, msg)
                ui(self, messagebox.showerror, "Error", msg)

        threading.Thread(target=worker, daemon=True).start()


def _cleanup(path):
    try:
        if os.path.exists(path): os.remove(path)
    except OSError:
        pass


# ─────────────────────────────────────────────────────────────────────────────
# MAIN WINDOW
# ─────────────────────────────────────────────────────────────────────────────

class EnzoCryptApp:
    TABS = ["Identity", "Encrypt", "Decrypt"]

    def __init__(self):
        root = tk.Tk()
        self.root = root
        root.title("EnzoCrypt")
        root.configure(bg=BG)

        # ── Responsive initial size: 75% of usable screen ──────────────────
        root.update_idletasks()
        sw = root.winfo_screenwidth()
        sh = root.winfo_screenheight()
        w  = max(520, min(680, int(sw * 0.55)))
        h  = max(480, min(760, int(sh * 0.80)))
        x  = (sw - w) // 2
        y  = max(0, (sh - h) // 2 - 30)
        root.geometry(f"{w}x{h}+{x}+{y}")
        root.minsize(480, 420)          # absolute floor — fits even 800×600
        root.resizable(True, True)
        # ────────────────────────────────────────────────────────────────────

        self._build()

    def _build(self):
        root = self.root

        # Header
        hdr = tk.Frame(root, bg=PANEL, height=50)
        hdr.pack(fill="x"); hdr.pack_propagate(False)
        tk.Label(hdr, text="ENZO", font=("Segoe UI",16,"bold"),
                 fg=ACCENT, bg=PANEL).pack(side="left", padx=(16,0), pady=10)
        tk.Label(hdr, text="CRYPT", font=("Segoe UI",16,"bold"),
                 fg=TEXT, bg=PANEL).pack(side="left")
        tk.Label(hdr, text="  v2 · streaming · any screen",
                 font=FS, fg=SUBTEXT, bg=PANEL).pack(side="left", padx=8)
        tk.Frame(root, height=1, bg=BORDER).pack(fill="x")

        # Tab bar
        tbar = tk.Frame(root, bg=BG); tbar.pack(fill="x")
        self._tbtns = []
        for i, lbl in enumerate(self.TABS):
            b = tk.Button(tbar, text=lbl, font=FK, relief="flat",
                          bd=0, cursor="hand2", padx=18, pady=9,
                          highlightthickness=0,
                          command=lambda i=i: self._switch(i))
            b.pack(side="left"); self._tbtns.append(b)
        tk.Frame(root, height=2, bg=ACCENT).pack(fill="x")

        # Content
        self._content = tk.Frame(root, bg=BG)
        self._content.pack(fill="both", expand=True)
        tk.Frame(root, height=1, bg=BORDER).pack(fill="x")
        self._status = _status_bar(root)

        self._tabs = [
            IdentityTab(self._content, self._status),
            EncryptTab(self._content, self._status),
            DecryptTab(self._content, self._status),
        ]
        self._switch(0)

    def _switch(self, idx):
        for t in self._tabs: t.pack_forget()
        self._tabs[idx].pack(fill="both", expand=True)
        for i, b in enumerate(self._tbtns):
            b.config(bg=PANEL if i == idx else BG,
                     fg=ACCENT2 if i == idx else SUBTEXT)

    def run(self): self.root.mainloop()


if __name__ == "__main__":
    EnzoCryptApp().run()