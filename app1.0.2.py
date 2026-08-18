
#EnzoCrypt — Encrypt any file. Send it anywhere. No cloud required.
#─────────────────────────────────────────────────────────────────
#V2 — Streaming chunk architecture
#  • AES-256-GCM with independent nonce per chunk
#  • AAD = magic + version + chunk_index  (prevents chunk reordering attacks)
#  • Configurable chunk size (1–64 MB) — user-selectable speed/RAM tradeoff
#  • Live benchmark: encrypts 1 MB of random data → extrapolates ETA
#  • Exact progress bar: chunk_done / total_chunks
#  • RSA-2048 OAEP/SHA-256 wraps the AES key
#  • Private key protected with BestAvailableEncryption (password)
#  • Single .enzocrypt container, VERSION=2

#File format  (.enzocrypt V2)
#  ┌──────────────────────────────────────────────┐
#  │  2 bytes  version = 2  (little-endian)       │
#  │  1 byte   ext_len                            │
#  │  N bytes  original extension                 │
#  │  2 bytes  rsa_blob_len                       │
#  │  M bytes  RSA-encrypted AES key              │
#  │  4 bytes  chunk_size  (little-endian)        │
#  │  ── repeated per chunk ──                    │
#  │  4 bytes  chunk_data_len                     │
#  │ 12 bytes  AES-GCM nonce                      │
#  │ 16 bytes  GCM authentication tag             │
#  │  K bytes  ciphertext                         │
#  └──────────────────────────────────────────────┘

#V1 files are still decryptable (version field checked at runtime).


import os
import secrets
import struct
import time
import threading
import tkinter as tk
from tkinter import filedialog, messagebox

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend

# ─── constants ────────────────────────────────────────────────────────────────
MAGIC        = b"ENZO"
VERSION_V1   = 1
VERSION_V2   = 2
CONTAINER_EXT = ".enzocrypt"

CHUNK_PRESETS = {
    "Low RAM  (1 MB)":    1 * 1024 * 1024,
    "Balanced (8 MB)":    8 * 1024 * 1024,
    "Fast     (32 MB)":  32 * 1024 * 1024,
    "Max speed (64 MB)": 64 * 1024 * 1024,
}
DEFAULT_PRESET = "Balanced (8 MB)"
BENCHMARK_SIZE = 1 * 1024 * 1024   # 1 MB benchmark payload
MIN_CHUNK_SIZE = 1 * 1024 * 1024
MAX_CHUNK_SIZE = 64 * 1024 * 1024
MAX_EXT_LEN = 255
MAX_RSA_BLOB_LEN = 4096
MAX_CHUNK_COUNT = 2**32 - 1


def _read_exact(stream, size: int, what: str = "data") -> bytes:
    """Read exactly *size* bytes or fail with a useful format error."""
    data = stream.read(size)
    if len(data) != size:
        raise ValueError(f"Invalid or incomplete EnzoCrypt file: truncated {what}.")
    return data


def _read_u8(stream, what: str) -> int:
    return struct.unpack("B", _read_exact(stream, 1, what))[0]


def _read_u16(stream, what: str) -> int:
    return struct.unpack("<H", _read_exact(stream, 2, what))[0]


def _read_u32(stream, what: str) -> int:
    return struct.unpack("<I", _read_exact(stream, 4, what))[0]


def _validate_chunk_size(chunk_size: int) -> None:
    if not (MIN_CHUNK_SIZE <= chunk_size <= MAX_CHUNK_SIZE):
        raise ValueError("Invalid chunk size in EnzoCrypt file.")


def _decode_extension(raw: bytes) -> str:
    try:
        ext = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("Invalid file extension in EnzoCrypt header.") from exc
    if len(raw) > MAX_EXT_LEN:
        raise ValueError("File extension in EnzoCrypt header is too long.")
    return ext


def _encode_extension(input_path: str) -> bytes:
    raw = os.path.splitext(input_path)[1].encode("utf-8")
    if len(raw) <= MAX_EXT_LEN:
        return raw
    # Keep the byte limit without cutting a UTF-8 sequence.
    return raw[:MAX_EXT_LEN].decode("utf-8", errors="ignore").encode("utf-8")


def _get_v2_chunk_count(container_path: str, data_offset: int, chunk_size: int):
    """Scan only chunk headers to obtain exact chunk count and plaintext size."""
    total_chunks = 0
    total_plaintext = 0
    container_size = os.path.getsize(container_path)
    with open(container_path, "rb") as f:
        f.seek(data_offset)
        while True:
            hdr = f.read(4)
            if not hdr:
                break
            if len(hdr) != 4:
                raise ValueError("Invalid or incomplete EnzoCrypt file: truncated chunk header.")
            ct_len = struct.unpack("<I", hdr)[0]
            if ct_len > chunk_size:
                raise ValueError("Invalid chunk length in EnzoCrypt file.")
            next_pos = f.tell() + 12 + 16 + ct_len
            if next_pos > container_size:
                raise ValueError("Invalid or incomplete EnzoCrypt file: truncated chunk.")
            f.seek(next_pos)
            total_chunks += 1
            total_plaintext += ct_len
            if total_chunks > MAX_CHUNK_COUNT:
                raise ValueError("Too many chunks in EnzoCrypt file.")
    return total_chunks, total_plaintext

# ─── color palette ────────────────────────────────────────────────────────────
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
BTN_FG  = "#FFFFFF"

FONT_TITLE = ("Segoe UI", 22, "bold")
FONT_HEAD  = ("Segoe UI", 13, "bold")
FONT_BODY  = ("Segoe UI", 10)
FONT_SMALL = ("Segoe UI", 9)
FONT_BTN   = ("Segoe UI", 10, "bold")
FONT_MONO  = ("Courier New", 9)

# ─────────────────────────────────────────────────────────────────────────────
# CRYPTO CORE
# ─────────────────────────────────────────────────────────────────────────────

def _oaep():
    return padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(), label=None)


def _aad(chunk_index: int) -> bytes:
    """Additional Authenticated Data — binds each chunk to its position."""
    return MAGIC + struct.pack("<HI", VERSION_V2, chunk_index)


def benchmark_speed(chunk_size: int) -> float:
    """
    Encrypt BENCHMARK_SIZE bytes and return MB/s.
    Uses real AES-GCM to reflect actual CPU performance.
    """
    key   = secrets.token_bytes(32)
    nonce = secrets.token_bytes(12)
    data  = secrets.token_bytes(BENCHMARK_SIZE)
    aesgcm = AESGCM(key)
    t0 = time.perf_counter()
    aesgcm.encrypt(nonce, data, _aad(0))
    elapsed = time.perf_counter() - t0
    return BENCHMARK_SIZE / elapsed / (1024 * 1024)   # MB/s


def generate_identity(save_dir: str, name: str, passphrase: bytes):
    private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048, backend=default_backend())
    pub_key = private_key.public_key()

    priv_pem = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.BestAvailableEncryption(passphrase))
    pub_pem = pub_key.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo)

    priv_path = os.path.join(save_dir, f"{name}_private.pem")
    pub_path  = os.path.join(save_dir, f"{name}_public.pem")
    with open(priv_path, "wb") as f: f.write(priv_pem)
    with open(pub_path,  "wb") as f: f.write(pub_pem)
    return priv_path, pub_path


def encrypt_file_v2(input_path: str, pub_key_path: str, output_path: str,
                    chunk_size: int, progress_cb=None, cancel_flag=None):
    """Stream-encrypt input_path -> output_path in authenticated chunks."""
    _validate_chunk_size(chunk_size)

    with open(pub_key_path, "rb") as f:
        pub_key = serialization.load_pem_public_key(f.read())

    if not isinstance(pub_key, rsa.RSAPublicKey):
        raise ValueError("The selected public key is not an RSA public key.")

    aes_key = secrets.token_bytes(32)
    rsa_blob = pub_key.encrypt(aes_key, _oaep())
    aesgcm = AESGCM(aes_key)

    ext = _encode_extension(input_path)
    file_size = os.path.getsize(input_path)
    total_chunks = max(1, (file_size + chunk_size - 1) // chunk_size)
    if total_chunks > MAX_CHUNK_COUNT:
        raise ValueError("The selected chunk size is too small for this file.")

    # Keep the benchmark optional; it is only an estimate and not part of crypto.
    mb_per_sec = benchmark_speed(chunk_size)

    with open(input_path, "rb") as fin, open(output_path, "wb") as fout:
        fout.write(MAGIC)
        fout.write(struct.pack("<H", VERSION_V2))
        fout.write(struct.pack("B", len(ext)))
        fout.write(ext)
        fout.write(struct.pack("<H", len(rsa_blob)))
        fout.write(rsa_blob)
        fout.write(struct.pack("<I", chunk_size))

        chunk_idx = 0
        processed = 0
        t_start = time.perf_counter()

        while True:
            if cancel_flag and cancel_flag.is_set():
                raise InterruptedError("Cancelled by user.")

            plaintext = fin.read(chunk_size)
            if not plaintext and not (file_size == 0 and chunk_idx == 0):
                break

            nonce = secrets.token_bytes(12)
            aad = _aad(chunk_idx)
            ct_tag = aesgcm.encrypt(nonce, plaintext, aad)
            ct, tag = ct_tag[:-16], ct_tag[-16:]

            fout.write(struct.pack("<I", len(ct)))
            fout.write(nonce)
            fout.write(tag)
            fout.write(ct)

            processed += len(plaintext)
            chunk_idx += 1

            if progress_cb:
                elapsed = time.perf_counter() - t_start
                speed = (processed / (1024 * 1024)) / elapsed if elapsed > 0 else mb_per_sec
                remaining = max(0, file_size - processed)
                eta = (remaining / (1024 * 1024)) / speed if speed > 0 else 0
                progress_cb(chunk_idx, total_chunks, eta)


def decrypt_file_v2(container_path: str, priv_key_path: str,
                    passphrase: bytes, output_path: str,
                    progress_cb=None, cancel_flag=None):
    """Decrypt a V2 .enzocrypt file, validating every chunk before writing it."""
    with open(priv_key_path, "rb") as f:
        priv_key = serialization.load_pem_private_key(f.read(), password=passphrase)

    if not isinstance(priv_key, rsa.RSAPrivateKey):
        raise ValueError("The selected private key is not an RSA private key.")

    with open(container_path, "rb") as fin:
        if _read_exact(fin, 4, "magic") != MAGIC:
            raise ValueError("Not an EnzoCrypt file.")
        version = _read_u16(fin, "version")
        if version != VERSION_V2:
            raise ValueError(f"This file uses format V{version}. Use the matching version of EnzoCrypt to open it.")

        ext_len = _read_u8(fin, "extension length")
        ext = _decode_extension(_read_exact(fin, ext_len, "extension"))
        rsa_len = _read_u16(fin, "RSA blob length")
        if not (1 <= rsa_len <= MAX_RSA_BLOB_LEN):
            raise ValueError("Invalid RSA key data in EnzoCrypt file.")
        rsa_blob = _read_exact(fin, rsa_len, "RSA key data")
        chunk_size = _read_u32(fin, "chunk size")
        _validate_chunk_size(chunk_size)
        data_offset = fin.tell()

        try:
            aes_key = priv_key.decrypt(rsa_blob, _oaep())
        except Exception as exc:
            raise ValueError("Could not decrypt the file key. Check the private key.") from exc

        if len(aes_key) != 32:
            raise ValueError("Invalid AES key in EnzoCrypt file.")
        aesgcm = AESGCM(aes_key)

        total_chunks, total_plaintext = _get_v2_chunk_count(
            container_path, data_offset, chunk_size)
        if total_chunks == 0:
            raise ValueError("EnzoCrypt file contains no data chunks.")

        base, _ = os.path.splitext(output_path)
        final_path = output_path if output_path.lower().endswith(ext.lower()) else base + ext

        file_size = os.path.getsize(container_path)
        mb_per_sec = benchmark_speed(chunk_size)
        t_start = time.perf_counter()
        chunk_idx = 0
        processed = 0

        with open(final_path, "wb") as fout:
            while True:
                if cancel_flag and cancel_flag.is_set():
                    raise InterruptedError("Cancelled by user.")

                hdr = fin.read(4)
                if not hdr:
                    break
                if len(hdr) != 4:
                    raise ValueError("Invalid or incomplete EnzoCrypt file: truncated chunk header.")

                ct_len = struct.unpack("<I", hdr)[0]
                if ct_len > chunk_size:
                    raise ValueError("Invalid chunk length in EnzoCrypt file.")
                nonce = _read_exact(fin, 12, "nonce")
                tag = _read_exact(fin, 16, "authentication tag")
                ct = _read_exact(fin, ct_len, "ciphertext")

                try:
                    pt = aesgcm.decrypt(nonce, ct + tag, _aad(chunk_idx))
                except Exception as exc:
                    raise ValueError(
                        f"Integrity check failed on chunk {chunk_idx}. "
                        "The file may be corrupted, tampered with, or incomplete.") from exc

                fout.write(pt)
                processed += len(pt)
                chunk_idx += 1

                if progress_cb:
                    elapsed = time.perf_counter() - t_start
                    speed = (processed / (1024 * 1024)) / elapsed if elapsed > 0 else mb_per_sec
                    remaining = max(0, total_plaintext - processed)
                    eta = (remaining / (1024 * 1024)) / speed if speed > 0 else 0
                    progress_cb(chunk_idx, total_chunks, eta)

        if chunk_idx != total_chunks:
            raise ValueError("EnzoCrypt file ended unexpectedly.")


def decrypt_file_v1(container_path: str, priv_key_path: str,
                    passphrase: bytes, output_path: str):
    """Decrypt the legacy V1 format (whole-file, kept for compatibility)."""
    with open(priv_key_path, "rb") as f:
        priv_key = serialization.load_pem_private_key(f.read(), password=passphrase)
    if not isinstance(priv_key, rsa.RSAPrivateKey):
        raise ValueError("The selected private key is not an RSA private key.")

    with open(container_path, "rb") as f:
        if _read_exact(f, 4, "magic") != MAGIC:
            raise ValueError("Not an EnzoCrypt file.")
        version = _read_u16(f, "version")
        if version != VERSION_V1:
            raise ValueError(f"Expected EnzoCrypt V1, found V{version}.")
        ext_len = _read_u8(f, "extension length")
        ext = _decode_extension(_read_exact(f, ext_len, "extension"))
        rsa_len = _read_u16(f, "RSA blob length")
        if not (1 <= rsa_len <= MAX_RSA_BLOB_LEN):
            raise ValueError("Invalid RSA key data in EnzoCrypt file.")
        rsa_blob = _read_exact(f, rsa_len, "RSA key data")
        nonce = _read_exact(f, 12, "nonce")
        tag = _read_exact(f, 16, "authentication tag")
        ct = f.read()

    try:
        aes_key = priv_key.decrypt(rsa_blob, _oaep())
        pt = AESGCM(aes_key).decrypt(nonce, ct + tag, None)
    except Exception as exc:
        raise ValueError("Integrity check failed — wrong key or tampered file.") from exc

    base, _ = os.path.splitext(output_path)
    fp = output_path if output_path.lower().endswith(ext.lower()) else base + ext
    with open(fp, "wb") as f:
        f.write(pt)


# ─────────────────────────────────────────────────────────────────────────────
# UI HELPERS
# ─────────────────────────────────────────────────────────────────────────────

def _btn(parent, text, command, color=ACCENT, width=28):
    return tk.Button(parent, text=text, command=command,
                     bg=color, fg=BTN_FG, font=FONT_BTN,
                     relief="flat", cursor="hand2",
                     padx=12, pady=8, width=width,
                     activebackground=ACCENT2, activeforeground=BTN_FG,
                     bd=0, highlightthickness=0)


def _label(parent, text, font=FONT_BODY, color=TEXT, **kw):
    return tk.Label(parent, text=text, font=font, fg=color, bg=PANEL, **kw)


def _section_card(parent, title):
    frame = tk.Frame(parent, bg=PANEL, bd=0,
                     highlightthickness=1, highlightbackground=BORDER)
    frame.pack(fill="x", padx=20, pady=8, ipady=6)
    tk.Label(frame, text=title, font=FONT_HEAD, fg=ACCENT2, bg=PANEL,
             anchor="w").pack(anchor="w", padx=16, pady=(10, 4))
    return frame


def _divider(parent):
    tk.Frame(parent, height=1, bg=BORDER).pack(fill="x", padx=20, pady=2)


def _status_bar(parent):
    bar = tk.Label(parent, text="Ready", font=FONT_SMALL, fg=SUBTEXT,
                   bg=BG, anchor="w", padx=14)
    bar.pack(fill="x", side="bottom", pady=(4, 6))
    return bar


def _file_label(frame, text):
    lbl = tk.Label(frame, text=text, font=FONT_MONO, fg=SUBTEXT, bg=PANEL,
                   anchor="w", wraplength=460, justify="left")
    lbl.pack(anchor="w", padx=16, pady=(0, 4))
    return lbl


def _password_dialog(title, prompt, confirm=False, parent=None):
    result = [None]
    dlg = tk.Toplevel(parent)
    dlg.title(title)
    dlg.geometry("360x220" if confirm else "360x190")
    dlg.configure(bg=BG)
    dlg.resizable(False, False)
    dlg.grab_set()

    tk.Label(dlg, text=title, font=FONT_HEAD, fg=ACCENT2, bg=BG).pack(pady=(18, 2))
    tk.Label(dlg, text=prompt, font=FONT_BODY, fg=SUBTEXT, bg=BG).pack(pady=(0, 6))

    e1 = tk.Entry(dlg, show="●", font=FONT_BODY, width=28,
                  bg=PANEL, fg=TEXT, insertbackground=TEXT,
                  relief="flat", bd=6)
    e1.pack(ipady=4)
    e1.focus_set()

    e2 = None
    if confirm:
        tk.Label(dlg, text="Confirm password:", font=FONT_SMALL,
                 fg=SUBTEXT, bg=BG).pack(pady=(8, 2))
        e2 = tk.Entry(dlg, show="●", font=FONT_BODY, width=28,
                      bg=PANEL, fg=TEXT, insertbackground=TEXT,
                      relief="flat", bd=6)
        e2.pack(ipady=4)

    def ok(event=None):
        pw = e1.get()
        if not pw:
            return
        if confirm and e2 and e2.get() != pw:
            messagebox.showerror("Mismatch", "Passwords don't match.", parent=dlg)
            return
        result[0] = pw.encode()
        dlg.destroy()

    bf = tk.Frame(dlg, bg=BG)
    bf.pack(pady=12)
    _btn(bf, "OK",     ok,              width=10).pack(side="left", padx=6)
    _btn(bf, "Cancel", dlg.destroy,     color=BORDER, width=10).pack(side="left", padx=6)
    e1.bind("<Return>", ok)
    dlg.wait_window()
    return result[0]


# ─────────────────────────────────────────────────────────────────────────────
# PROGRESS WIDGET
# ─────────────────────────────────────────────────────────────────────────────

class ProgressPanel(tk.Frame):
    """
    Reusable progress panel: animated bar + chunk counter + ETA.
    Call update(done, total, eta) from any thread (uses after()).
    Call reset() when starting a new operation.
    """
    def __init__(self, parent, **kw):
        super().__init__(parent, bg=PANEL, **kw)
        self._root = parent.winfo_toplevel()

        self._pct_var  = tk.StringVar(value="0%")
        self._eta_var  = tk.StringVar(value="")
        self._info_var = tk.StringVar(value="")

        # Row 1: label + pct
        row1 = tk.Frame(self, bg=PANEL)
        row1.pack(fill="x", padx=16, pady=(10, 2))
        tk.Label(row1, textvariable=self._info_var, font=FONT_SMALL,
                 fg=TEXT, bg=PANEL, anchor="w").pack(side="left")
        tk.Label(row1, textvariable=self._pct_var, font=FONT_SMALL,
                 fg=ACCENT2, bg=PANEL, anchor="e").pack(side="right")

        # Bar canvas
        self._canvas = tk.Canvas(self, height=10, bg="#252837",
                                 bd=0, highlightthickness=0)
        self._canvas.pack(fill="x", padx=16, pady=(0, 4))
        self._bar = None
        self._canvas.bind("<Configure>", self._on_resize)

        # ETA row
        tk.Label(self, textvariable=self._eta_var, font=FONT_SMALL,
                 fg=SUBTEXT, bg=PANEL, anchor="w").pack(anchor="w", padx=16, pady=(0, 8))

        self._pct = 0.0

    def reset(self, label="Processing…"):
        self._pct = 0.0
        self._pct_var.set("0%")
        self._info_var.set(label)
        self._eta_var.set("")
        self._draw_bar()

    def update(self, done, total, eta):
        """Thread-safe update."""
        self._root.after(0, self._do_update, done, total, eta)

    def _do_update(self, done, total, eta):
        if total <= 0:
            return
        pct = min(1.0, done / total)
        self._pct = pct
        self._pct_var.set(f"{pct*100:.0f}%")
        self._info_var.set(f"Chunk {done} / {total}")
        if eta >= 3600:
            self._eta_var.set(f"ETA: {eta/3600:.1f} h")
        elif eta >= 60:
            self._eta_var.set(f"ETA: {eta/60:.0f} min {eta%60:.0f} s")
        else:
            self._eta_var.set(f"ETA: {eta:.0f} s" if eta > 1 else "ETA: < 1 s")
        self._draw_bar()

    def done(self):
        self._do_update(1, 1, 0)
        self._eta_var.set("Complete")

    def error(self, msg):
        self._eta_var.set(f"Error: {msg[:60]}")
        self._info_var.set("Failed")

    def _on_resize(self, event):
        self._draw_bar()

    def _draw_bar(self):
        w = self._canvas.winfo_width()
        h = 10
        if w < 2:
            return
        self._canvas.delete("all")
        self._canvas.create_rectangle(0, 0, w, h, fill="#252837", outline="")
        fill_w = int(w * self._pct)
        if fill_w > 0:
            color = SUCCESS if self._pct >= 1.0 else ACCENT
            self._canvas.create_rectangle(0, 0, fill_w, h, fill=color, outline="")


# ─────────────────────────────────────────────────────────────────────────────
# SPEED SELECTOR WIDGET
# ─────────────────────────────────────────────────────────────────────────────

class SpeedSelector(tk.Frame):
    """Dropdown + benchmark label for chunk-size selection."""
    def __init__(self, parent, **kw):
        super().__init__(parent, bg=PANEL, **kw)
        self._var = tk.StringVar(value=DEFAULT_PRESET)

        row = tk.Frame(self, bg=PANEL)
        row.pack(fill="x", padx=16, pady=(4, 2))
        tk.Label(row, text="Speed / RAM mode:", font=FONT_BODY,
                 fg=TEXT, bg=PANEL).pack(side="left")
        self._bench_lbl = tk.Label(row, text="", font=FONT_SMALL,
                                   fg=SUBTEXT, bg=PANEL)
        self._bench_lbl.pack(side="right")

        menu = tk.OptionMenu(self, self._var, *CHUNK_PRESETS.keys())
        menu.config(bg=PANEL, fg=TEXT, font=FONT_BODY,
                    relief="flat", bd=0, highlightthickness=0,
                    activebackground=BORDER, cursor="hand2")
        menu["menu"].config(bg=PANEL, fg=TEXT, font=FONT_BODY)
        menu.pack(anchor="w", padx=16, pady=(0, 6))

        _btn(self, "Run benchmark", self._run_bench,
             color=BORDER, width=16).pack(anchor="w", padx=16, pady=(0, 8))

    def chunk_size(self) -> int:
        return CHUNK_PRESETS[self._var.get()]

    def _run_bench(self):
        self._bench_lbl.config(text="Benchmarking…", fg=WARNING)
        self.update_idletasks()
        try:
            mbs = benchmark_speed(self.chunk_size())
            self._bench_lbl.config(
                text=f"~{mbs:.1f} MB/s on this machine", fg=SUCCESS)
        except Exception as e:
            self._bench_lbl.config(text=f"Error: {e}", fg=DANGER)


# ─────────────────────────────────────────────────────────────────────────────
# TABS
# ─────────────────────────────────────────────────────────────────────────────

def _ui_after(widget, callback, *args):
    """Schedule a Tk callback on the main thread."""
    widget.winfo_toplevel().after(0, callback, *args)


def _show_error(widget, title, message):
    _ui_after(widget, lambda: messagebox.showerror(title, message, parent=widget.winfo_toplevel()))


def _show_info(widget, title, message):
    _ui_after(widget, lambda: messagebox.showinfo(title, message, parent=widget.winfo_toplevel()))


class IdentityTab(tk.Frame):
    def __init__(self, master, status):
        super().__init__(master, bg=BG)
        self._status = status
        self._build()

    def _build(self):
        tk.Label(self, text="Your Identity", font=FONT_TITLE,
                 fg=TEXT, bg=BG).pack(anchor="w", padx=20, pady=(20, 4))
        tk.Label(self,
                 text="Generate your key pair once. Share only your public key.",
                 font=FONT_BODY, fg=SUBTEXT, bg=BG).pack(anchor="w", padx=20, pady=(0, 14))

        card = _section_card(self, "Generate new key pair")
        row = tk.Frame(card, bg=PANEL)
        row.pack(anchor="w", padx=16, pady=(0, 6), fill="x")
        tk.Label(row, text="Name / alias:", font=FONT_BODY, fg=TEXT, bg=PANEL).pack(side="left")
        self._name_entry = tk.Entry(row, font=FONT_BODY, bg="#252837",
                                    fg=TEXT, insertbackground=TEXT,
                                    relief="flat", bd=6, width=24)
        self._name_entry.insert(0, "my_identity")
        self._name_entry.pack(side="left", padx=(8, 0), ipady=3)

        self._result_lbl = tk.Label(card, text="", font=FONT_SMALL,
                                    fg=SUCCESS, bg=PANEL, wraplength=500, justify="left")
        self._result_lbl.pack(anchor="w", padx=16, pady=(0, 4))
        _btn(card, "Generate Key Pair", self._generate, width=26).pack(
            anchor="w", padx=16, pady=(4, 14))

        _divider(self)
        card2 = _section_card(self, "Info")
        info = ("Private key  — Never share. Needed to decrypt. Protected with your password.\n\n"
                "Public key   — Send to anyone who wants to encrypt a file for you.")
        tk.Label(card2, text=info, font=FONT_BODY, fg=SUBTEXT, bg=PANEL,
                 justify="left", wraplength=520).pack(anchor="w", padx=16, pady=(0, 12))

    def _generate(self):
        name = "".join(c for c in self._name_entry.get().strip()
                       if c.isalnum() or c in "-_")[:40] or "identity"
        pw = _password_dialog("Protect your private key",
                              "Choose a strong password:", confirm=True,
                              parent=self.winfo_toplevel())
        if pw is None:
            return
        save_dir = filedialog.askdirectory(title="Save key pair to…",
                                           parent=self.winfo_toplevel())
        if not save_dir:
            return
        try:
            priv, pub = generate_identity(save_dir, name, pw)
            self._result_lbl.config(text=f"Saved:\n  {priv}\n  {pub}")
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
        self._file   = None
        self._pubkey = None
        self._cancel = threading.Event()
        self._build()

    def _build(self):
        tk.Label(self, text="Encrypt a File", font=FONT_TITLE,
                 fg=TEXT, bg=BG).pack(anchor="w", padx=20, pady=(20, 4))
        tk.Label(self,
                 text="Select a file and the recipient's public key.",
                 font=FONT_BODY, fg=SUBTEXT, bg=BG).pack(anchor="w", padx=20, pady=(0, 10))

        c1 = _section_card(self, "File to encrypt")
        self._file_lbl = _file_label(c1, "No file selected")
        _btn(c1, "Browse file…", self._pick_file, width=20).pack(
            anchor="w", padx=16, pady=(0, 8))

        c2 = _section_card(self, "Recipient's public key (.pem)")
        self._pub_lbl = _file_label(c2, "No public key selected")
        _btn(c2, "Browse public key…", self._pick_pubkey, width=20).pack(
            anchor="w", padx=16, pady=(0, 8))

        c3 = _section_card(self, "Speed / RAM")
        self._speed = SpeedSelector(c3)
        self._speed.pack(fill="x")

        c4 = _section_card(self, "Progress")
        self._progress = ProgressPanel(c4)
        self._progress.pack(fill="x")

        bf = tk.Frame(self, bg=BG)
        bf.pack(anchor="w", padx=20, pady=8)
        _btn(bf, "Encrypt & Save", self._start_encrypt, width=20).pack(side="left", padx=(0, 8))
        _btn(bf, "Cancel", self._cancel_op, color=BORDER, width=10).pack(side="left")

    def _pick_file(self):
        f = filedialog.askopenfilename(title="Select file to encrypt",
                                       filetypes=[("All files", "*.*")],
                                       parent=self.winfo_toplevel())
        if f:
            self._file = f
            self._file_lbl.config(text=f"  {os.path.basename(f)}", fg=TEXT)

    def _pick_pubkey(self):
        f = filedialog.askopenfilename(title="Select public key (.pem)",
                                       filetypes=[("PEM", "*.pem"), ("All", "*.*")],
                                       parent=self.winfo_toplevel())
        if f:
            self._pubkey = f
            self._pub_lbl.config(text=f"  {os.path.basename(f)}", fg=TEXT)

    def _cancel_op(self):
        self._cancel.set()

    def _start_encrypt(self):
        if not self._file:
            messagebox.showwarning("Missing", "Select a file first.",
                                   parent=self.winfo_toplevel()); return
        if not self._pubkey:
            messagebox.showwarning("Missing", "Select a public key first.",
                                   parent=self.winfo_toplevel()); return

        base = os.path.splitext(os.path.basename(self._file))[0]
        out = filedialog.asksaveasfilename(
            title="Save encrypted file as",
            initialfile=base + CONTAINER_EXT,
            defaultextension=CONTAINER_EXT,
            filetypes=[("EnzoCrypt", f"*{CONTAINER_EXT}"), ("All", "*.*")],
            parent=self.winfo_toplevel())
        if not out:
            return

        self._cancel.clear()
        chunk_size = self._speed.chunk_size()
        self._progress.reset("Benchmarking speed…")
        self._status.config(text="Encrypting…")

        def worker():
            try:
                encrypt_file_v2(
                    self._file, self._pubkey, out,
                    chunk_size=chunk_size,
                    progress_cb=self._progress.update,
                    cancel_flag=self._cancel)
                _ui_after(self, self._progress.done)
                _ui_after(self, self._status.config, {"text": f"Encrypted → {os.path.basename(out)}"})
                _show_info(self, "Done", f"Encrypted successfully!\n\n{os.path.basename(out)}")
            except InterruptedError:
                try:
                    if os.path.exists(out): os.remove(out)
                except OSError:
                    pass
                _ui_after(self, self._progress.error, "Cancelled")
                _ui_after(self, self._status.config, {"text": "Cancelled."})
            except Exception as e:
                try:
                    if os.path.exists(out): os.remove(out)
                except OSError:
                    pass
                _ui_after(self, self._progress.error, str(e))
                _show_error(self, "Encryption failed", str(e))

        threading.Thread(target=worker, daemon=True).start()


class DecryptTab(tk.Frame):
    def __init__(self, master, status):
        super().__init__(master, bg=BG)
        self._status    = status
        self._container = None
        self._privkey   = None
        self._cancel    = threading.Event()
        self._build()

    def _build(self):
        tk.Label(self, text="Decrypt a File", font=FONT_TITLE,
                 fg=TEXT, bg=BG).pack(anchor="w", padx=20, pady=(20, 4))
        tk.Label(self,
                 text="Open an .enzocrypt file. V1 and V2 files both supported.",
                 font=FONT_BODY, fg=SUBTEXT, bg=BG).pack(anchor="w", padx=20, pady=(0, 10))

        c1 = _section_card(self, ".enzocrypt file")
        self._cont_lbl = _file_label(c1, "No file selected")
        _btn(c1, "Browse encrypted file…", self._pick_container, width=24).pack(
            anchor="w", padx=16, pady=(0, 8))

        c2 = _section_card(self, "Your private key (.pem)")
        self._priv_lbl = _file_label(c2, "No private key selected")
        _btn(c2, "Browse private key…", self._pick_privkey, width=24).pack(
            anchor="w", padx=16, pady=(0, 8))

        c3 = _section_card(self, "Progress")
        self._progress = ProgressPanel(c3)
        self._progress.pack(fill="x")

        bf = tk.Frame(self, bg=BG)
        bf.pack(anchor="w", padx=20, pady=8)
        _btn(bf, "Decrypt & Save", self._start_decrypt, width=20).pack(side="left", padx=(0, 8))
        _btn(bf, "Cancel", self._cancel_op, color=BORDER, width=10).pack(side="left")

    def _pick_container(self):
        f = filedialog.askopenfilename(
            title="Select encrypted file",
            filetypes=[("EnzoCrypt", f"*{CONTAINER_EXT}"), ("All", "*.*")],
            parent=self.winfo_toplevel())
        if f:
            self._container = f
            self._cont_lbl.config(text=f"  {os.path.basename(f)}", fg=TEXT)

    def _pick_privkey(self):
        f = filedialog.askopenfilename(
            title="Select private key (.pem)",
            filetypes=[("PEM", "*.pem"), ("All", "*.*")],
            parent=self.winfo_toplevel())
        if f:
            self._privkey = f
            self._priv_lbl.config(text=f"  {os.path.basename(f)}", fg=TEXT)

    def _cancel_op(self):
        self._cancel.set()

    def _start_decrypt(self):
        if not self._container:
            messagebox.showwarning("Missing", "Select an .enzocrypt file.",
                                   parent=self.winfo_toplevel()); return
        if not self._privkey:
            messagebox.showwarning("Missing", "Select your private key.",
                                   parent=self.winfo_toplevel()); return

        pw = _password_dialog("Private key password",
                              "Enter the password for your private key:",
                              parent=self.winfo_toplevel())
        if pw is None:
            return

        out = filedialog.asksaveasfilename(
            title="Save decrypted file as",
            initialfile="decrypted_file",
            parent=self.winfo_toplevel())
        if not out:
            return

        # Detect version before starting the worker.
        try:
            with open(self._container, "rb") as f:
                magic = _read_exact(f, 4, "magic")
                if magic != MAGIC:
                    raise ValueError("Not an EnzoCrypt file.")
                version = _read_u16(f, "version")
        except Exception as e:
            messagebox.showerror("Invalid file", str(e), parent=self.winfo_toplevel())
            return

        if version not in (VERSION_V1, VERSION_V2):
            messagebox.showerror("Unsupported version",
                                 f"This file uses unsupported format V{version}.",
                                 parent=self.winfo_toplevel())
            return

        self._cancel.clear()
        self._progress.reset("Decrypting…")
        self._status.config(text="Decrypting…")

        def worker():
            try:
                if version == VERSION_V1:
                    decrypt_file_v1(self._container, self._privkey, pw, out)
                    _ui_after(self, self._progress.done)
                else:
                    decrypt_file_v2(
                        self._container, self._privkey, pw, out,
                        progress_cb=self._progress.update,
                        cancel_flag=self._cancel)
                    _ui_after(self, self._progress.done)

                _ui_after(self, self._status.config, {"text": "Decrypted successfully."})
                _show_info(self, "Done", "File decrypted successfully.\nOriginal extension restored.")
            except InterruptedError:
                try:
                    if os.path.exists(out): os.remove(out)
                except OSError:
                    pass
                _ui_after(self, self._progress.error, "Cancelled")
                _ui_after(self, self._status.config, {"text": "Cancelled."})
            except ValueError as e:
                try:
                    if os.path.exists(out): os.remove(out)
                except OSError:
                    pass
                _ui_after(self, self._progress.error, str(e))
                _show_error(self, "Decryption failed", str(e))
            except Exception as e:
                try:
                    if os.path.exists(out): os.remove(out)
                except OSError:
                    pass
                msg = "Wrong password or corrupted key." if (
                    "password" in str(e).lower() or "decrypt" in str(e).lower()
                ) else str(e)
                _ui_after(self, self._progress.error, msg)
                _show_error(self, "Error", msg)

        threading.Thread(target=worker, daemon=True).start()


# ─────────────────────────────────────────────────────────────────────────────
# MAIN WINDOW
# ─────────────────────────────────────────────────────────────────────────────

class EnzoCryptApp:
    TAB_LABELS = ["Identity", "Encrypt", "Decrypt"]

    def __init__(self):
        self.root = tk.Tk()
        self.root.title("EnzoCrypt")
        self.root.geometry("640x640")
        self.root.minsize(580, 560)
        self.root.configure(bg=BG)
        self._build()

    def _build(self):
        header = tk.Frame(self.root, bg=PANEL, height=56)
        header.pack(fill="x")
        header.pack_propagate(False)
        tk.Label(header, text="ENZO", font=("Segoe UI", 18, "bold"),
                 fg=ACCENT, bg=PANEL).pack(side="left", padx=(18, 0), pady=12)
        tk.Label(header, text="CRYPT", font=("Segoe UI", 18, "bold"),
                 fg=TEXT, bg=PANEL).pack(side="left")
        tk.Label(header, text="  v2 — streaming encryption",
                 font=FONT_SMALL, fg=SUBTEXT, bg=PANEL).pack(side="left", padx=8)
        tk.Frame(self.root, height=1, bg=BORDER).pack(fill="x")

        self._tab_bar = tk.Frame(self.root, bg=BG)
        self._tab_bar.pack(fill="x")
        self._tab_btns = []

        for i, lbl in enumerate(self.TAB_LABELS):
            b = tk.Button(self._tab_bar, text=lbl, font=FONT_BTN,
                          relief="flat", bd=0, cursor="hand2",
                          padx=20, pady=10, highlightthickness=0,
                          command=lambda idx=i: self._switch(idx))
            b.pack(side="left")
            self._tab_btns.append(b)

        tk.Frame(self.root, height=2, bg=ACCENT).pack(fill="x")

        self._content = tk.Frame(self.root, bg=BG)
        self._content.pack(fill="both", expand=True)

        tk.Frame(self.root, height=1, bg=BORDER).pack(fill="x")
        self._status = _status_bar(self.root)

        self._tabs = [
            IdentityTab(self._content, self._status),
            EncryptTab(self._content, self._status),
            DecryptTab(self._content, self._status),
        ]
        self._switch(0)

    def _switch(self, idx):
        for t in self._tabs: t.pack_forget()
        self._tabs[idx].pack(fill="both", expand=True)
        for i, b in enumerate(self._tab_btns):
            b.config(bg=PANEL if i == idx else BG,
                     fg=ACCENT2 if i == idx else SUBTEXT)

    def run(self):
        self.root.mainloop()


if __name__ == "__main__":
    EnzoCryptApp().run()