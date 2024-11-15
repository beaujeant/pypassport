pypassport
===========

This project has been developed by the Information Security Group (ISG) from the University of Louvain (ULC). The tool allows everyone to check whether a passport resists to the attacks known in the literature.

For more information, you can read the paper from the ISG and al. published the in ACM journal: [A Survey of Security and Privacy Issues in ePassports](https://www.researchgate.net/publication/286047538_A_Survey_of_Security_and_Privacy_Issues_in_ePassports).


Installation guide
------------------

Here is the complete installation guide for __pypassport__ on Linux (tested on Ubuntu 18.08 64bit) with an ACR122 using python 3.11.

### Install pypassport

You first need to download the latest version of __pypassport__:

```
sudo apt install git
git clone https://github.com/beaujeant/pypassport.git
```

Once the repository cloned, you need to install the dependencies:

```
python -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install pycryptodome
pip install ecdsa
pip install pyasn1
pip install Pillow
pip install pyscard
```

### Install driver

You then need to unplug the reader, then install the following resource:

```
sudo apt install libusb-dev
sudo apt install pcscd
```

#### ACR

For the ACR122 from acs, you need to unplug the reader, then install the driver available here: https://www.acs.com.hk/en/driver/3/acr122u-usb-nfc-reader/

For instance, if you are on Ubuntu 18.08 64-bit:

```
cd /tmp/
wget https://www.acs.com.hk/download-driver-unified/10312/ACS-Unified-PKG-Lnx-116-P.zip
unzip ACS-Unified-PKG-Lnx-116-P.zip
cd ACS-Unified-PKG-Lnx-116-P/acsccid_linux_bin-1.1.6/ubuntu/bionic/
sudo dpkg -i libacsccid1_1.1.6-1~ubuntu18.04.1_amd64.deb
```

Once installed, you need to [unload the pn533](https://ludovicrousseau.blogspot.com/2013/11/linux-nfc-driver-conflicts-with-ccid.html):

```
sudo rm -r /lib/modules/*/kernel/drivers/nfc/pn533
```

Now you should be able to use your reader. You can connect your reader and test if the driver has been properly installed with the following command:

```
sudo service pcscd stop
sudo pcscd -f -d
# "Ctrl + C" to quit
```

When placing your passport on the reader, you should see something similar to:

```
00001241 eventhandler.c:404:EHStatusHandlerThread() powerState: POWER_STATE_POWERED
00000010 eventhandler.c:421:EHStatusHandlerThread() Card inserted into ACS ACR122U 00 00
00000008 Card ATR: 12 23 34 45 56 67 78 89 90 01 12 23 34 45 56 67 78 89 90 01
```

### Troubleshooting

#### Failure to list reader

If you have the following error message:

```
'Failure to list readers: Service not Available.'.
Please check your passport is on the reader
```

Close ePassportViewer and run the following command:

```
sudo service pcscd restart
```

