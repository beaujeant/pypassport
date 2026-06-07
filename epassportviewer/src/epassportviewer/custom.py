import logging
from pathlib import Path
import tkinter as tk
from tkinter import ttk, filedialog
from PIL import Image, ImageTk
from tkinter import messagebox
from Crypto.Cipher import DES3
from pypassport.doc9303 import secure_messaging
from hashlib import sha1
from pypassport import asn1
from pypassport.doc9303 import mrz, bac
from pypassport.iso7816 import ISO7816, APDUCommand
from pypassport.utils import toHexString, toBytes


class CustomPane:
    def __init__(self, main):
        self.parent = main
        self.root = main.root

        # Block 1: Analyzing
        block1 = ttk.LabelFrame(self.root.custom_tab, text=" Analyzing ", padding=10)
        block1.pack(fill="x", pady=8, padx=5)

        tk.Button(block1, text="Dump randomness", command=self.dump_randomness).grid(row=0, column=0, padx=5, pady=5)
        tk.Label(block1, text="Nb of get challenge").grid(row=0, column=1, padx=5, pady=5)
        self.nb_challenge = tk.Entry(block1, width=6)
        self.nb_challenge.grid(row=0, column=2, padx=5, pady=5)

        # Block 2: Automatic Function
        block2 = ttk.LabelFrame(self.root.custom_tab, text=" Automatic Function ", padding=10)
        block2.pack(fill="x", pady=8, padx=5)

        tk.Button(block2, text="Init (select file)", command=self.init).pack(side="left", padx=5)
        tk.Button(block2, text="Reset", command=self.reset).pack(side="left", padx=5)
        tk.Button(block2, text="BAC", command=self.bac).pack(side="left", padx=5)
        tk.Button(block2, text="Generate BAC Keys", command=self.gen_bac_keys).pack(side="left", padx=5)
        tk.Button(block2, text="Get ATR", command=self.get_atr).pack(side="left", padx=5)

        # Block 3: Tools
        block3 = ttk.LabelFrame(self.root.custom_tab, text=" Tools ", padding=10)
        block3.pack(fill="x", pady=8, padx=5)

        # Row 1
        tk.Label(block3, text="Crypto:").grid(row=0, column=0, padx=5, pady=5)
        tk.Button(block3, text="3DES >", width=12, command=self.enc_3des).grid(row=0, column=1, padx=3, pady=5)
        tk.Button(block3, text="3DES <", width=12, command=self.dec_3des).grid(row=0, column=2, padx=3, pady=5)
        tk.Button(block3, text="SHA-1", width=12, command=self.sha1_hash).grid(row=0, column=3, padx=3, pady=5)
        tk.Button(block3, text="Create MAC", width=12, command=self.mac).grid(row=0, column=4, padx=3, pady=5)

        # Row 2
        tk.Label(block3, text="Functions:").grid(row=1, column=0, padx=5, pady=5)
        tk.Button(block3, text="XOR", width=12, command=self.xor).grid(row=1, column=1, padx=3, pady=5)
        tk.Button(block3, text="Key derivation", width=12, command=self.key_derivation).grid(
            row=1, column=2, padx=3, pady=5
        )
        tk.Button(block3, text="SSC generator", width=12, command=self.generate_ssc).grid(
            row=1, column=3, padx=3, pady=5
        )
        tk.Button(block3, text="Read header", width=12, command=self.read_header).grid(row=1, column=4, padx=3, pady=5)

        # Row 3
        tk.Label(block3, text="Fields:").grid(row=2, column=0, padx=5, pady=5)
        tk.Label(block3, text="HEX:").grid(row=2, column=1, padx=5, pady=5)
        self.field_one = tk.StringVar()
        tk.Entry(block3, textvariable=self.field_one).grid(row=2, column=2, padx=5, pady=5)
        tk.Label(block3, text="HEX:").grid(row=2, column=3, padx=5, pady=5)
        self.field_two = tk.StringVar()
        tk.Entry(block3, textvariable=self.field_two).grid(row=2, column=4, padx=5, pady=5)

        # Block 4: Requests
        block4 = ttk.LabelFrame(self.root.custom_tab, text=" Requests ", padding=10)
        block4.pack(fill="x", pady=8, padx=5)

        first_line = tk.Frame(block4)
        first_line.pack(fill="x", pady=5)

        tk.Button(first_line, text="External Auth.", command=self.external_auth).pack(side="left", padx=5)
        tk.Button(first_line, text="Internal Auth.", command=self.internal_auth).pack(side="left", padx=0)
        tk.Button(first_line, text="Select file", command=self.select_file).pack(side="left", padx=5)
        tk.Button(first_line, text="Read binary", command=self.read_binary).pack(side="left", padx=0)
        tk.Button(first_line, text="Rehabilitate", command=self.rehabilitate).pack(side="left", padx=5)
        tk.Button(first_line, text="Get UID", command=self.get_uid).pack(side="left", padx=0)
        tk.Button(first_line, text="Get ATS", command=self.get_ats).pack(side="left", padx=5)
        tk.Button(first_line, text="Get Challenge", command=self.get_challenge).pack(side="left", padx=0)

        second_line = tk.Frame(block4)
        second_line.pack(fill="x", pady=5)
        tk.Button(second_line, text="Send custom APDU", command=self.send_apdu).pack(side="left", padx=5)
        tk.Label(second_line, text="CLA:").pack(side="left", padx=5)
        self.cla = tk.StringVar()
        tk.Entry(second_line, width=2, textvariable=self.cla).pack(side="left", padx=5)
        tk.Label(second_line, text="INS:").pack(side="left", padx=5)
        self.ins = tk.StringVar()
        tk.Entry(second_line, width=2, textvariable=self.ins).pack(side="left", padx=5)
        tk.Label(second_line, text="P1:").pack(side="left", padx=5)
        self.p1 = tk.StringVar()
        tk.Entry(second_line, width=2, textvariable=self.p1).pack(side="left", padx=5)
        tk.Label(second_line, text="P2:").pack(side="left", padx=5)
        self.p2 = tk.StringVar()
        tk.Entry(second_line, width=2, textvariable=self.p2).pack(side="left", padx=5)
        tk.Label(second_line, text="LC:").pack(side="left", padx=5)
        self.lc = tk.StringVar()
        tk.Entry(second_line, width=4, textvariable=self.lc).pack(side="left", padx=5)
        tk.Label(second_line, text="DATA:").pack(side="left", padx=5)
        self.data = tk.StringVar()
        tk.Entry(second_line, textvariable=self.data).pack(side="left", padx=5)
        tk.Label(second_line, text="LE:").pack(side="left", padx=5)
        self.le = tk.StringVar()
        tk.Entry(second_line, width=4, textvariable=self.le).pack(side="left", padx=5)

        third_line = tk.Frame(block4)
        third_line.pack(fill="x", pady=5)
        tk.Button(third_line, text="Set ciphering", command=self.set_ciphering).pack(side="left", padx=5)

        tk.Label(third_line, text="KSenc:").pack(side="left", padx=5)
        self.ksenc = tk.StringVar()
        tk.Entry(third_line, textvariable=self.ksenc).pack(side="left", padx=5)
        tk.Label(third_line, text="KSmac:").pack(side="left", padx=5)
        self.ksmac = tk.StringVar()
        tk.Entry(third_line, textvariable=self.ksmac).pack(side="left", padx=5)
        tk.Label(third_line, text="SSC:").pack(side="left", padx=5)
        self.ssc = tk.StringVar()
        tk.Entry(third_line, textvariable=self.ssc).pack(side="left", padx=5)

        # Block 5: Response
        block5 = ttk.LabelFrame(self.root.custom_tab, text=" Response ", padding=10)
        block5.pack(fill="x", pady=8, padx=5)

        tk.Label(block5, text="APDU:").grid(row=0, column=0, padx=5, pady=5)
        self.response_data = tk.StringVar()
        tk.Entry(block5, width=80, textvariable=self.response_data).grid(row=0, column=1, padx=5, pady=5)

        # Save data to file
        image = Image.open(Path(__file__).parent / "resources" / "img" / "download.png")
        image = image.resize((20, 20), resample=Image.LANCZOS)
        photo = ImageTk.PhotoImage(image)
        image_button = tk.Button(block5, image=photo, command=self.download_data)
        image_button.image = photo
        image_button.grid(row=0, column=2, padx=0, pady=5)

        self.sw1 = tk.StringVar()
        tk.Entry(block5, width=4, textvariable=self.sw1).grid(row=0, column=3, padx=5, pady=5)
        self.sw2 = tk.StringVar()
        tk.Entry(block5, width=4, textvariable=self.sw2).grid(row=0, column=4, padx=5, pady=5)

        response_labels = ["Response data", "", "SW1", "SW2"]
        for i, text in enumerate(response_labels):
            tk.Label(block5, text=text).grid(row=1, column=i + 1, padx=0, pady=0)

    def get_ready(self):
        if not self.parent.reader:
            self.parent.get_reader()
        if not self.parent.reader:
            messagebox.showerror(
                "Reader missing", "Make sure you have the reader connected and the PCSC service running."
            )
            return False
        if not self.parent.iso7816:
            self.parent.iso7816 = ISO7816(self.parent.reader)
        return True

    def dump_randomness(self):
        if not self.get_ready():
            return False

        file_path = filedialog.asksaveasfilename(
            defaultextension=".bin",  # Default file extension
            filetypes=[("Binary files", "*.bin"), ("All files", "*.*")],  # Allowed file types
            title="Select a file to save data",
        )

        if file_path:
            output = ""
            try:
                if self.nb_challenge.get():
                    until = int(self.nb_challenge.get())
                else:
                    until = 200
                self.parent.iso7816.rstConnection()
                for i in range(until):
                    random = toHexString(self.parent.iso7816.getChallenge())
                    output += f"{random}\n"
                with open(file_path, "w") as file:
                    file.write(output)
                messagebox.showinfo("Challenges saved...", f"{until} challenge(s) have been saved in {file_path}")
            except Exception as e:
                messagebox.showerror("Error", e)
                return False
            return True

    def init(self):
        if not self.get_ready():
            return False
        self.parent.iso7816.rstConnection()
        return True

    def reset(self):
        if not self.get_ready():
            return False
        self.parent.iso7816.rstConnectionRaw()
        self.parent.iso7816.ciphering = False
        return True

    def bac(self):
        if not self.get_ready():
            return False
        try:
            doc_number = self.parent.doc_number.get()
            dob = self.parent.dob.get()
            expiry = self.parent.expiry.get()
            build_mrz = mrz.MRZ((doc_number, dob, expiry))
            self.parent.iso7816.ciphering = False
            self.init()
            basic_access_control = bac.BAC(self.parent.iso7816)
            (KSenc, KSmac, ssc) = basic_access_control.authenticationAndEstablishmentOfSessionKeys(build_mrz)
            sm = secure_messaging.SecureMessaging(KSenc, KSmac, ssc)
            self.parent.iso7816.ciphering = sm
        except Exception as msg:
            messagebox.showerror("Error: BAC", str(msg))

    def gen_bac_keys(self):
        if not self.get_ready():
            return False
        try:
            doc_number = self.parent.doc_number.get()
            dob = self.parent.dob.get()
            expiry = self.parent.expiry.get()
            mrz_to_send = mrz.MRZ((doc_number, dob, expiry))
            basic_access_control = bac.BAC(self.parent.iso7816)
            (Kenc, Kmac) = basic_access_control.derivationOfDocumentBasicAccesKeys(mrz_to_send)
            Kenc = toHexString(Kenc)
            Kmac = toHexString(Kmac)
            self.field_one.set(Kenc)
            self.field_two.set(Kmac)
        except Exception as msg:
            messagebox.showerror("Error: BAC", str(msg))

    def get_atr(self):
        if not self.get_ready():
            return False
        self.field_one.set(toHexString(self.parent.reader.getATR()))
        self.field_two.set("")

    def enc_3des(self):
        try:
            key = self.field_two.get()
            cleartext = self.field_one.get()
            tdes = DES3.new(toBytes(key), DES3.MODE_CBC, b"\x00\x00\x00\x00\x00\x00\x00\x00")
            m = toHexString(tdes.encrypt(toBytes(cleartext)))

            logging.info(f"TDES ENCRYPTION:\n  message: {cleartext}\n  key: {key}\n  cipher: {m}")

            self.field_one.set(m)
            self.field_two.set("")

        except Exception as msg:
            messagebox.showerror("Error: 3DES Encryption", str(msg))

    def dec_3des(self):
        try:
            key = self.field_two.get()
            cipher = self.field_one.get()
            tdes = DES3.new(toBytes(key), DES3.MODE_CBC, b"\x00\x00\x00\x00\x00\x00\x00\x00")
            m = toHexString(tdes.decrypt(toBytes(cipher)))

            logging.info(f"TDES DECRYPTION:\n  cipher: {cipher}\n  key: {key}\n  cleartext: {m}")

            self.field_one.set(m)
            self.field_two.set("")

        except Exception as msg:
            messagebox.showerror("Error: 3DES Decryption", str(msg))

    def sha1_hash(self):
        message = self.field_one.get()
        h = toHexString(sha1(message).digest())

        logging.info(f"SHA-1 HASH:\n  message: {message}\n  hash: {h}")

        self.field_one.set(h)
        self.field_two("")

    def xor(self):
        out = ""
        a = self.field_one.get()
        b = self.field_two.get()

        for i in range(len(a)):
            out += hex(int(a[i], 16) ^ int(b[i], 16))[2:]

        logging.info(f"XOR:\n  HEX 1: {a}\n  HEX 2: {b}\n  XOR:   {out.upper()}")

        self.field_one.set(out.upper())
        self.field_two.set("")

    def mac(self):
        if not self.get_ready():
            return False
        try:
            key = toBytes(self.field_two.get())
            message = toBytes(self.field_one.get())
            m = toHexString(self.parent.iso7816.mac(key, self.parent.iso7816.pad(message)))

            logging.info(f"MAC:\n  message: {message}\n  Key: {key}\n  MAC: {m}")

            self.field_one.set(m)
            self.field_two.set("")
        except Exception as msg:
            messagebox.showerror("Error: MAC", str(msg))

    def key_derivation(self):

        keyBin = toBytes(self.field_one.get())
        h = sha1(keyBin).digest()

        Ka = h[:8]
        Kb = h[8:16]

        Ka = self.des_parity(Ka)
        Kb = self.des_parity(Kb)

        key = toHexString(Ka + Kb)

        logging.info(f"KEY DERIVATION:\n  key: {self.field_one.get()}\n  derived key: {key}")
        self.field_one.set(key)
        self.field_two.set("")

    def des_parity(self, data):
        adjusted = []
        for c in data:
            y = c & 0xFE
            parity = 0
            for z in range(8):
                parity += y >> z & 1
            adjusted.append(y + (not parity % 2))
        return bytes(adjusted)

    def generate_ssc(self):
        rnd_icc = toBytes(self.field_one.get())
        rnd_ifd = toBytes(self.field_two.get())
        ssc = toHexString(rnd_icc[-4:] + rnd_ifd[-4:])
        logging.info(
            f"SSC GENERATOR:\n  RND ICC: {self.field_one.get()}\n  RND IFD: {self.field_two.get()}\n  SSC: {ssc}"
        )

        self.field_one.set(ssc)
        self.field_two.set("")

    def read_header(self):
        try:
            header = toBytes(self.field_one.get())
            (bodySize, offset) = asn1.asn1Length(header[1:])
            bodySize = toHexString(bodySize)
            offset = toHexString(offset + 1)
            logging.info(f"HEADER:\n  Body size: {bodySize}\n  Offset: {offset}")
            self.field_one.set(bodySize)
            self.field_two.set(offset)
        except Exception as msg:
            messagebox.showerror("Error: Read header", str(msg))

    def set_request(self, cla="00", ins="00", p1="00", p2="00", lc="", data="", le="00"):
        self.cla.set(cla)
        self.ins.set(ins)
        self.p1.set(p1)
        self.p2.set(p2)
        self.lc.set(lc)
        self.data.set(data)
        self.le.set(le)

    def external_auth(self):
        self.set_request(ins="82", le="28")

    def internal_auth(self):
        self.set_request(ins="88")

    def select_file(self):
        self.set_request(ins="A4", p1="02", p2="0C", le="")

    def read_binary(self):
        self.set_request(ins="B0")

    def rehabilitate(self):
        self.set_request(ins="44")

    def get_uid(self):
        self.set_request(cla="FF", ins="CA", p1="00", p2="00")

    def get_ats(self):
        self.set_request(cla="FF", ins="CA", p1="01", p2="00")

    def get_challenge(self):
        self.set_request(ins="84", le="08")

    def send_apdu(self):
        if not self.get_ready():
            return False
        try:
            cla = self.cla.get()
            ins = self.ins.get()
            p1 = self.p1.get()
            p2 = self.p2.get()
            lc = self.lc.get()
            data = self.data.get()
            le = self.le.get()

            if not lc and data:
                print("Helo")
                lc = toHexString(len(data) // 2)

            toSend = APDUCommand(cla, ins, p1, p2, lc, data, le)
            ans = self.parent.iso7816.transmit(toSend, "Custom APDU", full=True)
            rep = toHexString(ans.data)
            sw1 = ans.sw1
            sw2 = ans.sw2
            logging.info(f"REQUEST:\n  APDU: CLA:{cla} INS:{ins} P1:{p1} P2:{p2} LC:{lc} DATA:{data} LE:{le}")
            logging.info(f"RESPONSE:\n  APDU:\n    Data:{rep}\n    SW1:{hex(sw1)}\n    SW2:{hex(sw2)}")

            self.response_data.set(rep)
            self.sw1.set(toHexString(sw1))
            self.sw2.set(toHexString(sw2))
        except Exception as msg:
            messagebox.showerror("Error: Send", str(msg))

    def set_ciphering(self):
        if not self.get_ready():
            return False
        try:
            KSenc = toBytes(self.ksenc.get())
            KSmac = toBytes(self.ksmac.get())
            ssc = toBytes(self.ssc.get())
            sm = secure_messaging.SecureMessaging(KSenc, KSmac, ssc)
            self.parent.iso7868.setCiphering(sm)
            logging.ingo(f"CIPHERING SET:\n{sm}")
        except Exception as msg:
            messagebox.showerror("Error: Set ciphering", str(msg))

    def download_data(self):
        file_path = filedialog.asksaveasfilename(
            defaultextension=".bin",
            filetypes=[("Binary files", "*.bin"), ("All files", "*.*")],
            title="Select a file to save data",
        )

        if file_path:
            output = ""
            try:
                if self.nb_challenge.get():
                    until = int(self.nb_challenge.get())
                else:
                    until = 200
                self.parent.iso7816.rstConnection()
                for i in range(until):
                    random = toHexString(self.parent.iso7816.getChallenge())
                    output += f"{random}\n"
                with open(file_path, "w") as file:
                    file.write(output)
                messagebox.showinfo("Challenges saved...", f"{until} challenge(s) have been saved in {file_path}")
            except Exception as e:
                messagebox.showerror("Error", e)
                return False
            return True
