from pathlib import Path
import tkinter as tk
from tkinter import ttk
from PIL import Image, ImageTk

class AttacksPane:

    def __init__(self, main):
        self.root = main.root

        # Create the notebook (tabbed pane) for View, Attacks, Custom
        notebook = ttk.Notebook(self.root.attacks_tab)
        self.root.fingerprint_tab = ttk.Frame(notebook)
        self.root.bf_tab = ttk.Frame(notebook)
        self.root.mac_tab = ttk.Frame(notebook)
        self.root.aa_tab = ttk.Frame(notebook)

        notebook.add(self.root.fingerprint_tab, text="Error Fingerprinting")
        notebook.add(self.root.bf_tab, text="Brute Force")
        notebook.add(self.root.mac_tab, text="MAC Traceability")
        notebook.add(self.root.aa_tab, text="Active Authentication")
        notebook.pack(fill=tk.BOTH, expand=True, pady=15)

        FingerprintPane(self.root)
        ActiveAuthenticationPane(self.root)


class FingerprintPane:
    def __init__(self, root):
        self.root = root


        first_line = tk.Frame(self.root.fingerprint_tab)
        first_line.pack(fill="x", pady=5)
        tk.Label(first_line, text="CLA:").pack(side="left", padx=5)
        self.cla = tk.Entry(first_line, width=2)
        self.cla.pack(side="left", padx=5)
        tk.Label(first_line, text="INS:").pack(side="left", padx=5)
        self.ins = tk.Entry(first_line, width=2)
        self.ins.pack(side="left", padx=5)
        tk.Label(first_line, text="P1:").pack(side="left", padx=5)
        self.p1 = tk.Entry(first_line, width=2)
        self.p1.pack(side="left", padx=5)
        tk.Label(first_line, text="P2:").pack(side="left", padx=5)
        self.p2 = tk.Entry(first_line, width=2)
        self.p2.pack(side="left", padx=5)
        tk.Label(first_line, text="LC:").pack(side="left", padx=5)
        self.lc = tk.Entry(first_line, width=4)
        self.lc.pack(side="left", padx=5)
        tk.Label(first_line, text="DATA:").pack(side="left", padx=5)
        self.data = tk.Entry(first_line)
        self.data.pack(side="left", padx=5)
        tk.Label(first_line, text="LE:").pack(side="left", padx=5)
        self.le = tk.Entry(first_line, width=4)
        self.le.pack(side="left", padx=5)

        second_line = tk.Frame(self.root.fingerprint_tab)
        second_line.pack(fill="x", pady=5)
        tk.Button(second_line, text="Send custom APDU", command=self.send_apdu).pack(side="left", padx=5)

        third_line = tk.Frame(self.root.fingerprint_tab)
        third_line.pack(fill="x", pady=5)
        tk.Button(third_line, text="Add Error", command=self.save_error).pack(side="left", padx=5)
        tk.Label(third_line, text="Country:").pack(side="left", padx=5)
        self.cla = tk.Entry(third_line, width=2)
        self.cla.pack(side="left", padx=5)
        tk.Label(third_line, text="Year:").pack(side="left", padx=5)
        self.ins = tk.Entry(third_line, width=2)
        self.ins.pack(side="left", padx=5)

        fourth_line = tk.Frame(self.root.fingerprint_tab)
        fourth_line.pack(fill="x", pady=5)
        tk.Button(fourth_line, text="Identify", command=self.identify).pack(side="left", padx=5)


    def send_apdu(self):
        return


    def save_error(self):
        return


    def identify(self):
        return




class ActiveAuthenticationPane:
    def __init__(self, root):
        self.root = root

        # Save data to file
        image_help = Image.open(Path(__file__).parent / "resources" / "img" / "help.png")
        image_help = image_help.resize((20, 20), resample=Image.LANCZOS)
        image = ImageTk.PhotoImage(image_help)

        # IS VULNERABLE?
        vulnAAFrame = tk.Frame(self.root.aa_tab, border=1)
        vulnAAFrame.pack(fill="x")

        vulnerableAAButton = tk.Button(vulnAAFrame, text="Is vulnerable?", width=13, command=self.isVulnerableAA)
        vulnerableAAButton.pack(side="left", padx=5, pady=5)

        helpVulnAA = tk.Button(vulnAAFrame, image=image, command=self.helpVulnAADialog)
        helpVulnAA.image = image
        helpVulnAA.pack(side="right", padx=5, pady=5)

        # GET HIGHEST SIGNATURE
        modulusAttack = tk.Frame(self.root.aa_tab, border=1)
        modulusAttack.pack(fill="x",)

        getHighestFrame = tk.Frame(modulusAttack)
        getHighestFrame.pack(fill="x")

        getHighestButton = tk.Button(getHighestFrame, text="Get highest sign", width=13, command=self.getHighestSign)
        getHighestButton.pack(side="left", padx=5, pady=5)

        maxHighestLabel = tk.Label(getHighestFrame, text="Iteration:", justify="left")
        maxHighestLabel.pack(side="left", padx=5, pady=5)

        self.maxHighestForm = tk.Entry(getHighestFrame, width=3)
        self.maxHighestForm.pack(side="left", pady=5)

        helpGetHighest = tk.Button(getHighestFrame, image=image, command=self.helpGetHighestDialog)
        helpGetHighest.image = image
        helpGetHighest.pack(side="right", padx=5, pady=5)

        # GET MODULO
        getModuloFrame = tk.Frame(modulusAttack)
        getModuloFrame.pack(fill="x")

        getModuloButton = tk.Button(getModuloFrame, text="Get modulo", width=13, command=self.getModulo)
        getModuloButton.pack(side="left", padx=5, pady=5)

        helpGetModulo = tk.Button(getModuloFrame, image=image, command=self.helpGetModuloDialog)
        helpGetModulo.image = image
        helpGetModulo.pack(side="right", padx=5, pady=5)

        # COMPARE
        compareFrame = tk.Frame(modulusAttack)
        compareFrame.pack(fill="x")

        compareButton = tk.Button(compareFrame, text="Compare", width=13, command=self.compare)
        compareButton.pack(side="left", padx=5, pady=5)

        self.moduloCompareForm = tk.Entry(compareFrame, width=8)
        self.moduloCompareForm.pack(side="left", padx=5, pady=5)
        self.moduloCompareForm.insert(0, "Modulo")

        self.signCompareForm = tk.Entry(compareFrame, width=8)
        self.signCompareForm.pack(side="left", padx=5, pady=5)
        self.signCompareForm.insert(0, "Signature")

        accCompareLabel = tk.Label(compareFrame, text="Accuracy:", justify="left")
        accCompareLabel.pack(side="left", padx=5, pady=5)

        self.accCompareForm = tk.Entry(compareFrame, width=2)
        self.accCompareForm.pack(side="left", pady=5)

        helpCompare = tk.Button(compareFrame, image=image, command=self.helpCompareDialog)
        helpCompare.image = image
        helpCompare.pack(side="right", padx=5, pady=5)

        # MATCH?
        matchFrame = tk.Frame(modulusAttack)
        matchFrame.pack(fill="x")

        matchButton = tk.Button(matchFrame, text="Match?", width=13, command=self.mayBelongsTo)
        matchButton.pack(side="left", padx=5, pady=5)

        self.moduloMatchForm = tk.Entry(matchFrame, width=8)
        self.moduloMatchForm.pack(side="left", padx=5, pady=5)
        self.moduloMatchForm.insert(0, "Modulo")

        self.signMatchForm = tk.Entry(matchFrame, width=8)
        self.signMatchForm.pack(side="left", padx=5, pady=5)
        self.signMatchForm.insert(0, "Signature")

        helpMatch = tk.Button(matchFrame, image=image, command=self.helpMatchDialog)
        helpMatch.image = image
        helpMatch.pack(side="right", padx=5, pady=5)

        # SAVE
        saveSignFrame = tk.Frame(modulusAttack)
        saveSignFrame.pack(fill="x")

        saveSignButton = tk.Button(saveSignFrame, text="Save sign/mod...", width=13, command=self.saveSign)
        saveSignButton.pack(side="left", padx=5, pady=5)

        self.typeSign = tk.IntVar()
        self.typeSign.set(1)
        signatureRadiobutton = tk.Radiobutton(saveSignFrame, text="Signature", variable=self.typeSign, value=1)
        signatureRadiobutton.pack(side="left", padx=5, pady=5)

        moduloRadiobutton = tk.Radiobutton(saveSignFrame, text="Modulo", variable=self.typeSign, value=2)
        moduloRadiobutton.pack(side="left", padx=5, pady=5)

        helpSaveSign = tk.Button(saveSignFrame, image=image, command=self.helpSaveSignDialog)
        helpSaveSign.image = image
        helpSaveSign.pack(side="right", padx=5, pady=5)

        # CHECK FROM FILE
        checkSignFrame = tk.Frame(modulusAttack)
        checkSignFrame.pack(fill="x")

        checkSignButton = tk.Button(checkSignFrame, text="Check from file...", width=13, command=self.checkSignFromFile)
        checkSignButton.pack(side="left", padx=5, pady=5)

        self.moduloFileForm = tk.Entry(checkSignFrame, width=8)
        self.moduloFileForm.pack(side="left", padx=5, pady=5)
        self.moduloFileForm.insert(0, "Signature")

        coFileLabel = tk.Label(checkSignFrame, text="Accuracy:", justify="left")
        coFileLabel.pack(side="left", padx=5, pady=5)

        self.accFileForm = tk.Entry(checkSignFrame, width=3)
        self.accFileForm.pack(side="left", padx=5, pady=5)

        helpCheckSign = tk.Button(checkSignFrame, image=image, command=self.helpCheckSignDialog)
        helpCheckSign.image = image
        helpCheckSign.pack(side="right", padx=5, pady=5)

        # SIGN EVERYTHING
        signEverythingFrame = tk.Frame(self.root.aa_tab, border=1)
        signEverythingFrame.pack(fill="x")

        signEverythingButton = tk.Button(signEverythingFrame, text="Sign...", width=13, command=self.signEverything)
        signEverythingButton.pack(side="left", padx=5, pady=5)

        self.nonceToSignForm = tk.Entry(signEverythingFrame, width=16)
        self.nonceToSignForm.pack(side="left", pady=5)
        self.nonceToSignForm.insert(0, "Nonce to sign...")

        helpSignEverything = tk.Button(signEverythingFrame, image=image, command=self.helpSignEverythingDialog)
        helpSignEverything.image = image
        helpSignEverything.pack(side="right", padx=5, pady=5)



    def isVulnerableAA(self):
        return


    def helpVulnAADialog(self):
        return


    def getHighestSign(self):
        return

    def helpGetHighestDialog(self):
        return

    def getModulo(self):
        return

    def helpGetModuloDialog(self):
        return

    def compare(self):
        return

    def helpCompareDialog(self):
        return

    def mayBelongsTo(self):
        return

    def helpMatchDialog(self):
        return

    def saveSign(self):
        return

    def helpSaveSignDialog(self):
        return

    def checkSignFromFile(self):
        return

    def helpCheckSignDialog(self):
        return

    def signEverything(self):
        return

    def helpSignEverythingDialog(self):
        return