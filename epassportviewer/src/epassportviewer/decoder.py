import logging
import tkinter as tk
from tkinter import ttk, messagebox
from hashlib import sha1
from Crypto.Cipher import DES3
from pypassport.iso9797 import mac, pad, unpad
from pypassport.asn1 import asn1Length
from pypassport.utils import toHexString, toBytes, parseTLV


def _des_parity(data: bytes) -> bytes:
    adjusted = bytearray(data)
    for i in range(len(adjusted)):
        adjusted[i] = adjusted[i] & 0xFE | (bin(adjusted[i]).count("1") + 1) % 2
    return bytes(adjusted)


class DecoderPane:
    _KENC = b"\x00\x00\x00\x01"
    _KMAC = b"\x00\x00\x00\x02"

    def __init__(self, main):
        self.root = main.root
        tab = self.root.decoder_tab

        # ── Inputs ──────────────────────────────────────────────────────────
        fields_frame = ttk.LabelFrame(tab, text=" Inputs (hex) ", padding=10)
        fields_frame.pack(fill="x", padx=5, pady=8)

        ttk.Label(fields_frame, text="Field 1:").grid(row=0, column=0, padx=5, pady=4, sticky="w")
        self.field_one = tk.StringVar()
        ttk.Entry(fields_frame, textvariable=self.field_one, width=60).grid(row=0, column=1, padx=5, pady=4, sticky="ew")

        ttk.Label(fields_frame, text="Field 2:").grid(row=1, column=0, padx=5, pady=4, sticky="w")
        self.field_two = tk.StringVar()
        ttk.Entry(fields_frame, textvariable=self.field_two, width=60).grid(row=1, column=1, padx=5, pady=4, sticky="ew")

        fields_frame.columnconfigure(1, weight=1)

        # ── Crypto ──────────────────────────────────────────────────────────
        crypto_frame = ttk.LabelFrame(tab, text=" Crypto ", padding=10)
        crypto_frame.pack(fill="x", padx=5, pady=8)

        ttk.Label(crypto_frame, text="3DES CBC / IV=0x00*8:  Field 2 = key,  Field 1 = data").grid(
            row=0, column=0, columnspan=4, sticky="w", padx=5, pady=(0, 4)
        )
        ttk.Button(crypto_frame, text="3DES Encrypt →", width=16, command=self.enc_3des).grid(
            row=1, column=0, padx=5, pady=3
        )
        ttk.Button(crypto_frame, text="3DES Decrypt ←", width=16, command=self.dec_3des).grid(
            row=1, column=1, padx=3, pady=3
        )
        ttk.Button(crypto_frame, text="SHA-1 (F1→bytes)", width=18, command=self.sha1_hash).grid(
            row=1, column=2, padx=3, pady=3
        )

        # ── ISO 9797 ────────────────────────────────────────────────────────
        iso_frame = ttk.LabelFrame(tab, text=" ISO 9797-1  —  Field 1 = data,  Field 2 = key (MAC only) ", padding=10)
        iso_frame.pack(fill="x", padx=5, pady=8)

        ttk.Button(iso_frame, text="Retail MAC", width=14, command=self.retail_mac).grid(
            row=0, column=0, padx=5, pady=3
        )
        ttk.Button(iso_frame, text="Pad (F1)", width=14, command=self.iso9797_pad).grid(
            row=0, column=1, padx=3, pady=3
        )
        ttk.Button(iso_frame, text="Unpad (F1)", width=14, command=self.iso9797_unpad).grid(
            row=0, column=2, padx=3, pady=3
        )

        # ── BAC ─────────────────────────────────────────────────────────────
        bac_frame = ttk.LabelFrame(
            tab,
            text=" BAC key derivation  —  Field 1 = Kseed;  SSC: Field 1 = RND.ICC,  Field 2 = RND.IFD ",
            padding=10,
        )
        bac_frame.pack(fill="x", padx=5, pady=8)

        ttk.Button(bac_frame, text="Derive Kenc", width=14, command=self.derive_kenc).grid(
            row=0, column=0, padx=5, pady=3
        )
        ttk.Button(bac_frame, text="Derive Kmac", width=14, command=self.derive_kmac).grid(
            row=0, column=1, padx=3, pady=3
        )
        ttk.Button(bac_frame, text="SSC generator", width=14, command=self.generate_ssc).grid(
            row=0, column=2, padx=3, pady=3
        )

        # ── Functions ───────────────────────────────────────────────────────
        fn_frame = ttk.LabelFrame(tab, text=" Functions ", padding=10)
        fn_frame.pack(fill="x", padx=5, pady=8)

        ttk.Button(fn_frame, text="XOR  F1 ^ F2", width=14, command=self.xor).grid(row=0, column=0, padx=5, pady=3)

        # ── TLV / DER ───────────────────────────────────────────────────────
        tlv_frame = ttk.LabelFrame(tab, text=" TLV / DER  —  Field 1 = hex data ", padding=10)
        tlv_frame.pack(fill="x", padx=5, pady=8)

        ttk.Button(tlv_frame, text="Read header", width=14, command=self.read_header).grid(
            row=0, column=0, padx=5, pady=3
        )
        ttk.Button(tlv_frame, text="Parse TLV", width=14, command=self.parse_tlv).grid(
            row=0, column=1, padx=3, pady=3
        )

        # ── Result ──────────────────────────────────────────────────────────
        result_frame = ttk.LabelFrame(tab, text=" Result ", padding=10)
        result_frame.pack(fill="both", expand=True, padx=5, pady=8)

        self._result = tk.Text(result_frame, height=6, wrap="word", state="disabled", font=("Courier", 9))
        scroll = ttk.Scrollbar(result_frame, orient="vertical", command=self._result.yview)
        self._result.configure(yscrollcommand=scroll.set)
        scroll.pack(side="right", fill="y")
        self._result.pack(fill="both", expand=True)

    # ── helpers ─────────────────────────────────────────────────────────────

    def _show(self, text: str):
        self._result.configure(state="normal")
        self._result.delete("1.0", "end")
        self._result.insert("end", text)
        self._result.configure(state="disabled")

    def _f1(self) -> str:
        return self.field_one.get().strip().replace(" ", "")

    def _f2(self) -> str:
        return self.field_two.get().strip().replace(" ", "")

    # ── crypto ──────────────────────────────────────────────────────────────

    def enc_3des(self):
        try:
            key = toBytes(self._f2())
            plaintext = toBytes(self._f1())
            cipher = DES3.new(key, DES3.MODE_CBC, b"\x00" * 8)
            result = toHexString(cipher.encrypt(plaintext))
            logging.info(f"3DES ENC  key={self._f2()}  pt={self._f1()}  ct={result}")
            self._show(result)
        except Exception as e:
            messagebox.showerror("3DES Encrypt", str(e))

    def dec_3des(self):
        try:
            key = toBytes(self._f2())
            ciphertext = toBytes(self._f1())
            cipher = DES3.new(key, DES3.MODE_CBC, b"\x00" * 8)
            result = toHexString(cipher.decrypt(ciphertext))
            logging.info(f"3DES DEC  key={self._f2()}  ct={self._f1()}  pt={result}")
            self._show(result)
        except Exception as e:
            messagebox.showerror("3DES Decrypt", str(e))

    def sha1_hash(self):
        try:
            data = toBytes(self._f1())
            result = toHexString(sha1(data).digest())
            logging.info(f"SHA-1  in={self._f1()}  hash={result}")
            self._show(result)
        except Exception as e:
            messagebox.showerror("SHA-1", str(e))

    # ── ISO 9797 ────────────────────────────────────────────────────────────

    def retail_mac(self):
        try:
            message = toBytes(self._f1())
            key = toBytes(self._f2())
            result = toHexString(mac(key, pad(message)))
            logging.info(f"RETAIL MAC  msg={self._f1()}  key={self._f2()}  mac={result}")
            self._show(result)
        except Exception as e:
            messagebox.showerror("Retail MAC", str(e))

    def iso9797_pad(self):
        try:
            data = toBytes(self._f1())
            result = toHexString(pad(data))
            logging.info(f"ISO9797 PAD  in={self._f1()}  out={result}")
            self._show(result)
        except Exception as e:
            messagebox.showerror("ISO 9797 Pad", str(e))

    def iso9797_unpad(self):
        try:
            data = toBytes(self._f1())
            result = toHexString(unpad(data))
            logging.info(f"ISO9797 UNPAD  in={self._f1()}  out={result}")
            self._show(result)
        except Exception as e:
            messagebox.showerror("ISO 9797 Unpad", str(e))

    # ── BAC ─────────────────────────────────────────────────────────────────

    def _key_derive(self, c: bytes) -> str:
        kseed = toBytes(self._f1())
        h = sha1(kseed + c).digest()
        ka = _des_parity(h[:8])
        kb = _des_parity(h[8:16])
        return toHexString(ka + kb)

    def derive_kenc(self):
        try:
            result = self._key_derive(self._KENC)
            logging.info(f"DERIVE KENC  kseed={self._f1()}  Kenc={result}")
            self._show(result)
        except Exception as e:
            messagebox.showerror("Key Derivation", str(e))

    def derive_kmac(self):
        try:
            result = self._key_derive(self._KMAC)
            logging.info(f"DERIVE KMAC  kseed={self._f1()}  Kmac={result}")
            self._show(result)
        except Exception as e:
            messagebox.showerror("Key Derivation", str(e))

    def generate_ssc(self):
        try:
            rnd_icc = toBytes(self._f1())
            rnd_ifd = toBytes(self._f2())
            result = toHexString(rnd_icc[-4:] + rnd_ifd[-4:])
            logging.info(f"SSC  RND.ICC={self._f1()}  RND.IFD={self._f2()}  SSC={result}")
            self._show(result)
        except Exception as e:
            messagebox.showerror("SSC Generator", str(e))

    # ── functions ───────────────────────────────────────────────────────────

    def xor(self):
        try:
            a = toBytes(self._f1())
            b = toBytes(self._f2())
            if len(a) != len(b):
                raise ValueError(f"Length mismatch: Field 1 is {len(a)} bytes, Field 2 is {len(b)} bytes")
            result = toHexString(bytes(x ^ y for x, y in zip(a, b)))
            logging.info(f"XOR  F1={self._f1()}  F2={self._f2()}  out={result}")
            self._show(result)
        except Exception as e:
            messagebox.showerror("XOR", str(e))

    # ── TLV / DER ───────────────────────────────────────────────────────────

    def read_header(self):
        try:
            data = toBytes(self._f1())
            tag_size = 2 if (data[0] & 0x0F) == 0x0F else 1
            body_size, len_size = asn1Length(data[tag_size:])
            header_size = tag_size + len_size
            tag_hex = toHexString(data[:tag_size])
            output = (
                f"Tag:         {tag_hex}\n"
                f"Header size: {header_size} byte(s)\n"
                f"Body size:   {body_size} byte(s)\n"
                f"Body offset: {header_size} (0x{header_size:02X})\n"
                f"Body:        {toHexString(data[header_size : header_size + body_size])}"
            )
            logging.info(f"READ HEADER  tag={tag_hex}  header={header_size}  body={body_size}")
            self._show(output)
        except Exception as e:
            messagebox.showerror("Read Header", str(e))

    def parse_tlv(self):
        try:
            data = toBytes(self._f1())
            lines = []
            offset = 0
            while offset < len(data):
                tag, value, consumed = parseTLV(data[offset:])
                lines.append(f"[{tag}]  len={len(value)}  value={toHexString(value)}")
                offset += consumed
            self._show("\n".join(lines) if lines else "(empty)")
        except Exception as e:
            messagebox.showerror("Parse TLV", str(e))
