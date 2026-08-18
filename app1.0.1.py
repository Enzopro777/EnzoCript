

"""
EnzoCrypt — Encrypt any file. Send it anywhere. No cloud required.
─────────────────────────────────────────────────────────────────
Architecture
  • AES-256-GCM   → authenticated encryption (confidentiality + integrity)
  • RSA-2048 OAEP/SHA-256 → wraps the AES key
  • Private key protected with a password (BestAvailableEncryption)
  • Single .enzocrypt container: [header | rsa_key_len | rsa_key | iv | tag | ciphertext]
  • No separate .bin files — one file per encrypted asset

File format  (.enzocrypt)
  ┌──────────────────────────────────────────────┐
  │  4 bytes  magic  "ENZO"                      │
  │  2 bytes  version (little-endian, now = 1)   │
  │  1 byte   ext_len                            │
  │  N bytes  original extension  (e.g. ".pdf")  │
  │  2 bytes  rsa_blob_len (little-endian)        │
  │  M bytes  RSA-encrypted AES key              │
  │ 12 bytes  AES-GCM nonce                      │
  │ 16 bytes  GCM authentication tag             │
  │ rest      AES-GCM ciphertext                 │
  └──────────────────────────────────────────────┘
"""

import os
import secrets
import struct
import tkinter as tk
from tkinter import filedialog, messagebox
import traceback

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend

# ─── constants ────────────────────────────────────────────────────────────────
MAGIC = b"ENZO"
VERSION = 1
CONTAINER_EXT = ".enzocrypt"

# ─── color palette ────────────────────────────────────────────────────────────
BG      = "#0F1117"   # near-black
PANEL   = "#1A1D27"   # dark card
ACCENT  = "#6C63FF"   # violet
ACCENT2 = "#A78BFA"   # soft lavender
SUCCESS = "#10B981"   # emerald
DANGER  = "#EF4444"   # red
TEXT    = "#E2E8F0"   # near-white
SUBTEXT = "#94A3B8"   # slate
BORDER  = "#2D3148"   # subtle border
BTN_FG  = "#FFFFFF"

FONT_TITLE  = ("Segoe UI", 22, "bold")
FONT_HEAD   = ("Segoe UI", 13, "bold")
FONT_BODY   = ("Segoe UI", 10)
FONT_SMALL  = ("Segoe UI", 9)
FONT_BTN    = ("Segoe UI", 10, "bold")
FONT_MONO   = ("Courier New", 9)

# ─────────────────────────────────────────────────────────────────────────────
# CRYPTO CORE
# ─────────────────────────────────────────────────────────────────────────────

def _oaep_padding():
    return padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None,
    )


def generate_identity(save_dir: str, name: str, passphrase: bytes) -> tuple[str, str]:
    """
    Generate an RSA-2048 key pair.
    Private key is written encrypted with `passphrase` (BestAvailableEncryption).
    Returns (private_path, public_path).
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048, backend=default_backend()
    )
    pub_key = private_key.public_key()

    priv_enc = serialization.BestAvailableEncryption(passphrase)
    priv_pem = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        priv_enc,
    )
    pub_pem = pub_key.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    priv_path = os.path.join(save_dir, f"{name}_private.pem")
    pub_path  = os.path.join(save_dir, f"{name}_public.pem")
    with open(priv_path, "wb") as f: f.write(priv_pem)
    with open(pub_path,  "wb") as f: f.write(pub_pem)
    return priv_path, pub_path


def encrypt_file(input_path: str, pub_key_path: str, output_path: str) -> None:
    """
    Encrypt `input_path` for the owner of `pub_key_path`.
    Produces a single self-contained `output_path` (.enzocrypt).
    """
    # Load public key
    with open(pub_key_path, "rb") as f:
        pub_key = serialization.load_pem_public_key(f.read())

    # Generate fresh 256-bit AES key + 96-bit nonce
    aes_key = secrets.token_bytes(32)
    nonce   = secrets.token_bytes(12)

    # RSA-wrap the AES key
    rsa_blob = pub_key.encrypt(aes_key, _oaep_padding())

    # Read plaintext
    with open(input_path, "rb") as f:
        plaintext = f.read()

    # AES-256-GCM encrypt (produces ciphertext + 16-byte tag appended)
    aesgcm = AESGCM(aes_key)
    ct_and_tag = aesgcm.encrypt(nonce, plaintext, None)
    ciphertext = ct_and_tag[:-16]
    tag        = ct_and_tag[-16:]

    # Original extension
    ext = os.path.splitext(input_path)[1].encode()[:255]

    # Write container
    with open(output_path, "wb") as f:
        f.write(MAGIC)
        f.write(struct.pack("<H", VERSION))
        f.write(struct.pack("B", len(ext)))
        f.write(ext)
        f.write(struct.pack("<H", len(rsa_blob)))
        f.write(rsa_blob)
        f.write(nonce)       # 12 bytes
        f.write(tag)         # 16 bytes
        f.write(ciphertext)


def decrypt_file(container_path: str, priv_key_path: str,
                 passphrase: bytes, output_path: str) -> None:
    """
    Decrypt an .enzocrypt container using the private key + passphrase.
    Raises ValueError on integrity failure (tampered file).
    """
    with open(container_path, "rb") as f:
        magic = f.read(4)
        if magic != MAGIC:
            raise ValueError("Not an EnzoCrypt file.")
        version = struct.unpack("<H", f.read(2))[0]
        if version != VERSION:
            raise ValueError(f"Unsupported container version: {version}")
        ext_len = struct.unpack("B", f.read(1))[0]
        ext     = f.read(ext_len).decode()
        rsa_len = struct.unpack("<H", f.read(2))[0]
        rsa_blob   = f.read(rsa_len)
        nonce      = f.read(12)
        tag        = f.read(16)
        ciphertext = f.read()

    # Load password-protected private key
    with open(priv_key_path, "rb") as f:
        priv_key = serialization.load_pem_private_key(f.read(), password=passphrase)

    # Unwrap AES key
    aes_key = priv_key.decrypt(rsa_blob, _oaep_padding())

    # AES-256-GCM decrypt (raises InvalidTag on tamper)
    aesgcm = AESGCM(aes_key)
    try:
        plaintext = aesgcm.decrypt(nonce, ciphertext + tag, None)
    except Exception:
        raise ValueError(
            "Integrity check failed — the file may have been tampered with "
            "or the wrong private key was used."
        )

    # Preserve original extension
    base, _ = os.path.splitext(output_path)
    final_path = base + ext if ext and not output_path.endswith(ext) else output_path
    with open(final_path, "wb") as f:
        f.write(plaintext)


# ─────────────────────────────────────────────────────────────────────────────
# UI HELPERS
# ─────────────────────────────────────────────────────────────────────────────

def _btn(parent, text, command, color=ACCENT, width=28):
    b = tk.Button(
        parent, text=text, command=command,
        bg=color, fg=BTN_FG, font=FONT_BTN,
        relief="flat", cursor="hand2",
        padx=12, pady=8, width=width,
        activebackground=ACCENT2, activeforeground=BTN_FG,
        bd=0, highlightthickness=0,
    )
    return b


def _label(parent, text, font=FONT_BODY, color=TEXT, **kw):
    return tk.Label(parent, text=text, font=font, fg=color, bg=PANEL, **kw)


def _section_card(parent, title):
    frame = tk.Frame(parent, bg=PANEL, bd=0, highlightthickness=1,
                     highlightbackground=BORDER)
    frame.pack(fill="x", padx=20, pady=8, ipady=10)
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


def _password_dialog(title: str, prompt: str) -> bytes | None:
    """Modal password entry — returns bytes or None if cancelled."""
    result = [None]

    dlg = tk.Toplevel()
    dlg.title(title)
    dlg.geometry("360x200")
    dlg.configure(bg=BG)
    dlg.resizable(False, False)
    dlg.grab_set()

    tk.Label(dlg, text=title, font=FONT_HEAD, fg=ACCENT2, bg=BG).pack(pady=(18, 2))
    tk.Label(dlg, text=prompt, font=FONT_BODY, fg=SUBTEXT, bg=BG).pack(pady=(0, 8))

    entry = tk.Entry(dlg, show="●", font=FONT_BODY, width=28,
                     bg=PANEL, fg=TEXT, insertbackground=TEXT,
                     relief="flat", bd=6)
    entry.pack(ipady=4)
    entry.focus_set()

    def confirm(event=None):
        val = entry.get()
        if val:
            result[0] = val.encode()
        dlg.destroy()

    def cancel():
        dlg.destroy()

    btn_frame = tk.Frame(dlg, bg=BG)
    btn_frame.pack(pady=14)
    _btn(btn_frame, "Confirm", confirm, width=10).pack(side="left", padx=6)
    _btn(btn_frame, "Cancel", cancel, color=BORDER, width=10).pack(side="left", padx=6)

    entry.bind("<Return>", confirm)
    dlg.wait_window()
    return result[0]


def _file_label(frame, text):
    """Small monospace label showing a file path."""
    lbl = tk.Label(frame, text=text, font=FONT_MONO, fg=SUBTEXT, bg=PANEL,
                   anchor="w", wraplength=480, justify="left")
    lbl.pack(anchor="w", padx=16, pady=(0, 6))
    return lbl


# ─────────────────────────────────────────────────────────────────────────────
# TABS
# ─────────────────────────────────────────────────────────────────────────────

class IdentityTab(tk.Frame):
    """Generate and manage your key pair (identity)."""

    def __init__(self, master, status):
        super().__init__(master, bg=BG)
        self._status = status
        self._build()

    def _build(self):
        tk.Label(self, text="Your Identity", font=FONT_TITLE,
                 fg=TEXT, bg=BG).pack(anchor="w", padx=20, pady=(20, 4))
        tk.Label(self,
                 text="Generate your key pair once. Share only your public key — keep the private key safe.",
                 font=FONT_BODY, fg=SUBTEXT, bg=BG, wraplength=560, justify="left"
                 ).pack(anchor="w", padx=20, pady=(0, 14))

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
                                    fg=SUCCESS, bg=PANEL, wraplength=520, justify="left")
        self._result_lbl.pack(anchor="w", padx=16, pady=(0, 4))

        _btn(card, "⚡  Generate Key Pair", self._generate, width=30).pack(
            anchor="w", padx=16, pady=(4, 14))

        _divider(self)

        card2 = _section_card(self, "Info")
        info = (
            "🔑  Private key  —  Never share this. Needed to decrypt files sent to you.\n"
            "    It is protected with the password you choose at generation time.\n\n"
            "📤  Public key   —  Send this to anyone who wants to encrypt a file for you."
        )
        tk.Label(card2, text=info, font=FONT_BODY, fg=SUBTEXT, bg=PANEL,
                 justify="left", wraplength=540).pack(anchor="w", padx=16, pady=(0, 12))

    def _generate(self):
        name = self._name_entry.get().strip() or "my_identity"
        # Sanitize
        name = "".join(c for c in name if c.isalnum() or c in "-_")[:40] or "identity"

        pw = _password_dialog(
            "Protect your private key",
            "Choose a strong password to encrypt your private key:"
        )
        if pw is None:
            return

        pw2 = _password_dialog(
            "Confirm password",
            "Re-enter the same password to confirm:"
        )
        if pw2 is None:
            return
        if pw != pw2:
            messagebox.showerror("Password mismatch",
                                 "The passwords don't match. Please try again.",
                                 parent=self.winfo_toplevel())
            return

        save_dir = filedialog.askdirectory(
            title="Choose folder to save your key pair",
            parent=self.winfo_toplevel()
        )
        if not save_dir:
            return

        try:
            priv, pub = generate_identity(save_dir, name, pw)
            self._result_lbl.config(
                text=f"✅  Keys saved:\n  {priv}\n  {pub}"
            )
            self._status.config(text=f"Identity '{name}' created successfully.")
            messagebox.showinfo(
                "Keys generated",
                f"Your key pair has been saved:\n\n"
                f"🔒 Private: {os.path.basename(priv)}\n"
                f"📤 Public:  {os.path.basename(pub)}\n\n"
                f"Share only the PUBLIC key with others.",
                parent=self.winfo_toplevel()
            )
        except Exception as e:
            messagebox.showerror("Error", str(e), parent=self.winfo_toplevel())
            traceback.print_exc()


class EncryptTab(tk.Frame):
    """Encrypt any file for a recipient using their public key."""

    def __init__(self, master, status):
        super().__init__(master, bg=BG)
        self._status = status
        self._file = None
        self._pubkey = None
        self._build()

    def _build(self):
        tk.Label(self, text="Encrypt a File", font=FONT_TITLE,
                 fg=TEXT, bg=BG).pack(anchor="w", padx=20, pady=(20, 4))
        tk.Label(self,
                 text="Select any file and the recipient's public key. "
                      "The result is a single .enzocrypt file you can send anywhere.",
                 font=FONT_BODY, fg=SUBTEXT, bg=BG, wraplength=560, justify="left"
                 ).pack(anchor="w", padx=20, pady=(0, 14))

        # Step 1
        c1 = _section_card(self, "① Select file to encrypt")
        self._file_lbl = _file_label(c1, "No file selected")
        _btn(c1, "📂  Browse file…", self._pick_file, width=22).pack(
            anchor="w", padx=16, pady=(0, 10))

        # Step 2
        c2 = _section_card(self, "② Select recipient's public key (.pem)")
        self._pub_lbl = _file_label(c2, "No public key selected")
        _btn(c2, "🔑  Browse public key…", self._pick_pubkey, width=22).pack(
            anchor="w", padx=16, pady=(0, 10))

        # Step 3
        c3 = _section_card(self, "③ Encrypt")
        _btn(c3, "🔐  Encrypt & Save", self._encrypt, width=22).pack(
            anchor="w", padx=16, pady=(4, 14))

    def _pick_file(self):
        f = filedialog.askopenfilename(
            title="Select file to encrypt",
            filetypes=[("All files", "*.*")],
            parent=self.winfo_toplevel()
        )
        if f:
            self._file = f
            self._file_lbl.config(text=f"  {os.path.basename(f)}", fg=TEXT)
            self._status.config(text=f"File: {f}")

    def _pick_pubkey(self):
        f = filedialog.askopenfilename(
            title="Select public key (.pem)",
            filetypes=[("PEM public key", "*.pem"), ("All files", "*.*")],
            parent=self.winfo_toplevel()
        )
        if f:
            self._pubkey = f
            self._pub_lbl.config(text=f"  {os.path.basename(f)}", fg=TEXT)
            self._status.config(text=f"Public key: {f}")

    def _encrypt(self):
        if not self._file:
            messagebox.showwarning("Missing file",
                                   "Please select a file to encrypt.",
                                   parent=self.winfo_toplevel()); return
        if not self._pubkey:
            messagebox.showwarning("Missing key",
                                   "Please select the recipient's public key.",
                                   parent=self.winfo_toplevel()); return

        base = os.path.splitext(os.path.basename(self._file))[0]
        out = filedialog.asksaveasfilename(
            title="Save encrypted file as",
            initialfile=base + CONTAINER_EXT,
            defaultextension=CONTAINER_EXT,
            filetypes=[("EnzoCrypt file", f"*{CONTAINER_EXT}"), ("All files", "*.*")],
            parent=self.winfo_toplevel()
        )
        if not out:
            return

        try:
            encrypt_file(self._file, self._pubkey, out)
            self._status.config(text=f"Encrypted → {out}")
            messagebox.showinfo(
                "Encrypted ✅",
                f"File encrypted successfully!\n\n"
                f"Send this file to the recipient:\n{os.path.basename(out)}\n\n"
                f"Only they can decrypt it with their private key.",
                parent=self.winfo_toplevel()
            )
        except Exception as e:
            messagebox.showerror("Encryption failed", str(e), parent=self.winfo_toplevel())
            traceback.print_exc()


class DecryptTab(tk.Frame):
    """Decrypt an .enzocrypt file using your private key."""

    def __init__(self, master, status):
        super().__init__(master, bg=BG)
        self._status = status
        self._container = None
        self._privkey = None
        self._build()

    def _build(self):
        tk.Label(self, text="Decrypt a File", font=FONT_TITLE,
                 fg=TEXT, bg=BG).pack(anchor="w", padx=20, pady=(20, 4))
        tk.Label(self,
                 text="Open an .enzocrypt file sent to you. "
                      "You need your private key and the password you chose at key generation.",
                 font=FONT_BODY, fg=SUBTEXT, bg=BG, wraplength=560, justify="left"
                 ).pack(anchor="w", padx=20, pady=(0, 14))

        c1 = _section_card(self, "① Select .enzocrypt file")
        self._cont_lbl = _file_label(c1, "No file selected")
        _btn(c1, "📂  Browse encrypted file…", self._pick_container, width=26).pack(
            anchor="w", padx=16, pady=(0, 10))

        c2 = _section_card(self, "② Select your private key (.pem)")
        self._priv_lbl = _file_label(c2, "No private key selected")
        _btn(c2, "🔑  Browse private key…", self._pick_privkey, width=26).pack(
            anchor="w", padx=16, pady=(0, 10))

        c3 = _section_card(self, "③ Decrypt")
        _btn(c3, "🔓  Decrypt & Save", self._decrypt, width=26).pack(
            anchor="w", padx=16, pady=(4, 14))

    def _pick_container(self):
        f = filedialog.askopenfilename(
            title="Select encrypted file",
            filetypes=[("EnzoCrypt file", f"*{CONTAINER_EXT}"), ("All files", "*.*")],
            parent=self.winfo_toplevel()
        )
        if f:
            self._container = f
            self._cont_lbl.config(text=f"  {os.path.basename(f)}", fg=TEXT)
            self._status.config(text=f"Encrypted file: {f}")

    def _pick_privkey(self):
        f = filedialog.askopenfilename(
            title="Select your private key (.pem)",
            filetypes=[("PEM private key", "*.pem"), ("All files", "*.*")],
            parent=self.winfo_toplevel()
        )
        if f:
            self._privkey = f
            self._priv_lbl.config(text=f"  {os.path.basename(f)}", fg=TEXT)
            self._status.config(text=f"Private key: {f}")

    def _decrypt(self):
        if not self._container:
            messagebox.showwarning("Missing file",
                                   "Please select an .enzocrypt file.",
                                   parent=self.winfo_toplevel()); return
        if not self._privkey:
            messagebox.showwarning("Missing key",
                                   "Please select your private key.",
                                   parent=self.winfo_toplevel()); return

        pw = _password_dialog(
            "Private key password",
            "Enter the password that protects your private key:"
        )
        if pw is None:
            return

        # Ask where to save — extension will be restored automatically
        out = filedialog.asksaveasfilename(
            title="Save decrypted file as",
            initialfile="decrypted_file",
            parent=self.winfo_toplevel()
        )
        if not out:
            return

        try:
            decrypt_file(self._container, self._privkey, pw, out)
            self._status.config(text=f"Decrypted successfully.")
            messagebox.showinfo(
                "Decrypted ✅",
                f"File decrypted and saved successfully!\n\n"
                f"The original file extension has been restored.",
                parent=self.winfo_toplevel()
            )
        except ValueError as e:
            messagebox.showerror("Decryption failed", str(e), parent=self.winfo_toplevel())
        except Exception as e:
            if "password" in str(e).lower() or "bad decrypt" in str(e).lower():
                messagebox.showerror(
                    "Wrong password",
                    "The password is incorrect or the key file is corrupted.",
                    parent=self.winfo_toplevel()
                )
            else:
                messagebox.showerror("Error", str(e), parent=self.winfo_toplevel())
            traceback.print_exc()


# ─────────────────────────────────────────────────────────────────────────────
# MAIN WINDOW
# ─────────────────────────────────────────────────────────────────────────────

class EnzoCryptApp:
    TAB_LABELS = ["🪪  Identity", "🔐  Encrypt", "🔓  Decrypt"]

    def __init__(self):
        self.root = tk.Tk()
        self.root.title("EnzoCrypt")
        self.root.geometry("620x560")
        self.root.minsize(560, 480)
        self.root.configure(bg=BG)
        self._build()

    def _build(self):
        # ── Header bar ──────────────────────────────────────────────────────
        header = tk.Frame(self.root, bg=PANEL, height=56)
        header.pack(fill="x")
        header.pack_propagate(False)

        tk.Label(header, text="ENZO", font=("Segoe UI", 18, "bold"),
                 fg=ACCENT, bg=PANEL).pack(side="left", padx=(18, 0), pady=12)
        tk.Label(header, text="CRYPT", font=("Segoe UI", 18, "bold"),
                 fg=TEXT, bg=PANEL).pack(side="left")
        tk.Label(header,
                 text="Encrypt any file. Send it anywhere. No cloud required.",
                 font=FONT_SMALL, fg=SUBTEXT, bg=PANEL).pack(side="left", padx=14)

        tk.Frame(self.root, height=1, bg=BORDER).pack(fill="x")

        # ── Tab bar ─────────────────────────────────────────────────────────
        self._tab_bar = tk.Frame(self.root, bg=BG)
        self._tab_bar.pack(fill="x")

        self._tab_btns = []
        self._active_tab = tk.IntVar(value=0)

        for i, lbl in enumerate(self.TAB_LABELS):
            b = tk.Button(
                self._tab_bar, text=lbl,
                font=FONT_BTN,
                relief="flat", bd=0, cursor="hand2",
                padx=16, pady=10,
                highlightthickness=0,
                command=lambda idx=i: self._switch(idx),
            )
            b.pack(side="left")
            self._tab_btns.append(b)

        self._indicator = tk.Frame(self.root, height=2, bg=ACCENT)
        self._indicator.pack(fill="x")

        # ── Content area ────────────────────────────────────────────────────
        self._content = tk.Frame(self.root, bg=BG)
        self._content.pack(fill="both", expand=True)

        # ── Status bar ──────────────────────────────────────────────────────
        tk.Frame(self.root, height=1, bg=BORDER).pack(fill="x")
        self._status = _status_bar(self.root)

        # ── Tabs ────────────────────────────────────────────────────────────
        self._tabs = [
            IdentityTab(self._content, self._status),
            EncryptTab(self._content, self._status),
            DecryptTab(self._content, self._status),
        ]

        self._switch(0)

    def _switch(self, idx):
        self._active_tab.set(idx)
        for t in self._tabs:
            t.pack_forget()
        self._tabs[idx].pack(fill="both", expand=True)

        for i, b in enumerate(self._tab_btns):
            if i == idx:
                b.config(bg=PANEL, fg=ACCENT2)
            else:
                b.config(bg=BG, fg=SUBTEXT)

    def run(self):
        self.root.mainloop()


if __name__ == "__main__":
    EnzoCryptApp().run()
