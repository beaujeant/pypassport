"""ISO 19794-5/-4/-6 biometric image/fingerprint/iris CBEFF header parsers.

References:
  ISO/IEC 19794-4:2005 — Finger image data
  ISO/IEC 19794-5:2005 — Face image data
  ISO/IEC 19794-6:2005 — Iris image data
  ICAO Doc 9303 Part 10 §4.7.2 (DG2), §4.7.3 (DG3), §4.7.4 (DG4)
"""

# --- Magic bytes ------------------------------------------------------------

FAC = b"FAC\x00"   # ISO 19794-5 face
FIR = b"FIR\x00"   # ISO 19794-4 fingerprint
IIR = b"IIR\x00"   # ISO 19794-6 iris


# ============================================================================
# ISO 19794-5  (face image — DG2)
# ============================================================================

ISO19794_5_GENDER = {
    0x00: 'Unspecified',
    0x01: 'Male',
    0x02: 'Female',
    0x03: 'Unknown',
}

ISO19794_5_EYECOLOUR = {
    0x00: 'Unspecified',
    0x01: 'Black',
    0x02: 'Blue',
    0x03: 'Brown',
    0x04: 'Grey',
    0x05: 'Green',
    0x06: 'Hazel',
    0x07: 'Pink',
    0x08: 'Other',
}

ISO19794_5_HAIRCOLOUR = {
    0x00: 'Unspecified',
    0x01: 'Bald',
    0x02: 'Black',
    0x03: 'Blonde',
    0x04: 'Brown',
    0x05: 'Grey',
    0x06: 'White',
    0x07: 'Red',
    0x08: 'Green',
    0x09: 'Blue',
    0xff: 'Other',
}

ISO19794_5_FEATURE = {
    0x001: 'Specified',
    0x002: 'Glasses',
    0x004: 'Moustache',
    0x008: 'Beard',
    0x010: 'Teeth Visible',
    0x020: 'Blink',
    0x040: 'Mouth Open',
    0x080: 'Left Eyepatch',
    0x100: 'Right Eyepatch',
    0x200: 'Dark Glasses',
    0x400: 'Distorted',
}

ISO19794_5_EXPRESSION = {
    0x0000: 'Unspecified',
    0x0001: 'Neutral',
    0x0002: 'Smile Closed',
    0x0003: 'Smile Open',
    0x0004: 'Raised Eyebrow',
    0x0005: 'Looking Away',
    0x0006: 'Squinting',
    0x0007: 'Frowning',
}

ISO19794_5_IMG_TYPE = {
    0x00: 'Unspecified (Front)',
    0x01: 'Basic',
    0x02: 'Full Front',
    0x03: 'Token Front',
    0x04: 'Other',
}

ISO19794_5_IMG_DTYPE = {
    0x00: 'JPEG',
    0x01: 'JPEG 2000',
}

ISO19794_5_IMG_FTYPE = {
    0x00: 'JPG',
    0x01: 'JP2',
}

ISO19794_5_IMG_CSPACE = {
    0x00: 'Unspecified',
    0x01: 'RGB24',
    0x02: 'YUV422',
    0x03: 'GREY8BIT',
    0x04: 'Other',
}

ISO19794_5_IMG_SOURCE = {
    0x00: 'Unspecified',
    0x01: 'Static Unspecified',
    0x02: 'Static Digital',
    0x03: 'Static Scan',
    0x04: 'Video Unknown',
    0x05: 'Video Analogue',
    0x06: 'Video Digital',
    0x07: 'Unknown',
}

ISO19794_5_IMG_QUALITY = {0x0000: 'Unspecified'}


# ============================================================================
# ISO 19794-4  (fingerprint image — DG3)
# ============================================================================

ISO19794_4_COMPRESSION = {
    0x00: 'Uncompressed (no pack)',
    0x01: 'Uncompressed (pack bit)',
    0x02: 'WSQ',
    0x03: 'JPEG',
    0x04: 'JPEG 2000',
    0x05: 'PNG',
}

ISO19794_4_SCALE_UNITS = {
    0x01: 'PPI',
    0x02: 'PPCM',
}

ISO19794_4_FINGER_POSITION = {
    0x00: 'Unknown',
    0x01: 'Right Thumb',
    0x02: 'Right Index',
    0x03: 'Right Middle',
    0x04: 'Right Ring',
    0x05: 'Right Little',
    0x06: 'Left Thumb',
    0x07: 'Left Index',
    0x08: 'Left Middle',
    0x09: 'Left Ring',
    0x0A: 'Left Little',
    0x0D: 'Plain Right Four',
    0x0E: 'Plain Left Four',
    0x0F: 'Plain Thumbs',
}


# ============================================================================
# ISO 19794-6  (iris image — DG4)
# ============================================================================

ISO19794_6_EYE_LABEL = {
    0x00: 'Unspecified',
    0x01: 'Right',
    0x02: 'Left',
    0x03: 'Both',
}

ISO19794_6_IMAGE_KIND = {
    0x01: 'Uncropped',
    0x03: 'VGA',
    0x07: 'Cropped',
    0x0B: 'Cropped and Masked',
}

ISO19794_6_COMPRESSION = {
    0x02: 'Lossless (PNG)',
    0x04: 'Lossy (JPEG 2000)',
    0x06: 'Lossless (JPEG 2000)',
    0x07: 'JPEG',
}


# ============================================================================
# Shared helpers
# ============================================================================

def _translate(dictionary, index):
    try:
        return dictionary[index]
    except KeyError:
        return index


# ============================================================================
# Parser classes
# ============================================================================

class ISO19794_5:
    """ISO 19794-5 facial image CBEFF header parser (DG2)."""

    @staticmethod
    def analyse(data: bytes) -> tuple:
        """Parse the CBEFF facial image header.

        Returns (meta_dict, header_size) where data[header_size:] is the
        raw image (JPEG or JPEG 2000).
        """
        if data[0:4] != FAC:
            raise Exception(f"Missing FAC magic: {data[0:4]!r}")

        result = {}
        # Bytes 4-7: version "010\0" (4 bytes per spec; previously only 3 read)
        result['VersionNumber']        = data[4:8]
        result['LengthOfRecord']       = int.from_bytes(data[8:12], 'big')
        result['NumberOfFacialImages'] = int.from_bytes(data[12:14], 'big')
        result['FaceImageBlockLength'] = int.from_bytes(data[14:18], 'big')
        result['NumberOfFeaturePoint'] = int.from_bytes(data[18:20], 'big')
        result['Gender']               = _translate(ISO19794_5_GENDER, data[20])
        result['EyeColour']            = _translate(ISO19794_5_EYECOLOUR, data[21])
        result['HairColour']           = _translate(ISO19794_5_HAIRCOLOUR, data[22])

        feature_mask = int.from_bytes(data[23:26], 'big')
        result['FeatureMask'] = feature_mask
        result['Features'] = {v for k, v in ISO19794_5_FEATURE.items() if feature_mask & k}

        result['Expression'] = _translate(
            ISO19794_5_EXPRESSION, int.from_bytes(data[26:28], 'big')
        )
        result['PoseAngle']            = int.from_bytes(data[28:31], 'big')
        result['PoseAngleUncertainty'] = int.from_bytes(data[31:34], 'big')

        offset = 34
        result['FeaturePoint'] = []
        for _ in range(result['NumberOfFeaturePoint']):
            result['FeaturePoint'].append({
                'FeatureType':       data[offset],
                'FeaturePointCode':  data[offset + 1],
                'HorizontalPosition': data[offset + 2:offset + 4],
                'VerticalPosition':  data[offset + 4:offset + 6],
                'Reserved':          data[offset + 6:offset + 8],
            })
            offset += 8

        result['FaceImageType']    = _translate(ISO19794_5_IMG_TYPE,   data[offset]);     offset += 1
        result['ImageDataType']    = _translate(ISO19794_5_IMG_DTYPE,  data[offset]);     offset += 1
        result['ImageWidth']       = int.from_bytes(data[offset:offset + 2], 'big');      offset += 2
        result['ImageHeight']      = int.from_bytes(data[offset:offset + 2], 'big');      offset += 2
        result['ImageColourSpace'] = _translate(ISO19794_5_IMG_CSPACE, data[offset]);     offset += 1
        result['ImageSourceType']  = _translate(ISO19794_5_IMG_SOURCE, data[offset]);     offset += 1
        result['ImageDeviceType']  = int.from_bytes(data[offset:offset + 2], 'big');      offset += 2
        result['ImageQuality']     = _translate(
            ISO19794_5_IMG_QUALITY, int.from_bytes(data[offset:offset + 2], 'big')
        );                                                                                 offset += 2

        return result, offset


class ISO19794_4:
    """ISO 19794-4 fingerprint image CBEFF header parser (DG3).

    Global record header: 32 bytes.
    Per-finger-view sub-header: 14 bytes (position, view info, dimensions).
    """

    @staticmethod
    def analyse(data: bytes) -> tuple:
        """Parse the CBEFF fingerprint record header.

        Returns (meta_dict, header_size) where data[header_size:] is the
        raw fingerprint image data for the first view.
        """
        if data[0:4] != FIR:
            raise Exception(f"Missing FIR magic: {data[0:4]!r}")

        result = {}
        result['VersionNumber']    = data[4:8]
        result['LengthOfRecord']   = int.from_bytes(data[8:12], 'big')
        result['CBEFFProductID']   = int.from_bytes(data[12:14], 'big')
        result['CaptureDeviceID']  = int.from_bytes(data[14:16], 'big')
        result['AcquisitionLevel'] = data[16]
        result['NumberOfFingers']  = data[17]
        result['ScaleUnits']       = _translate(ISO19794_4_SCALE_UNITS, data[18])
        result['ScanResolutionH']  = int.from_bytes(data[19:21], 'big')
        result['ScanResolutionV']  = int.from_bytes(data[21:23], 'big')
        result['ImageResolutionH'] = int.from_bytes(data[23:25], 'big')
        result['ImageResolutionV'] = int.from_bytes(data[25:27], 'big')
        result['PixelDepth']       = data[27]
        result['Compression']      = _translate(ISO19794_4_COMPRESSION, data[28])
        result['Reserved']         = data[29:32]

        # Parse per-finger-view sub-headers (14 bytes each)
        offset = 32
        views = []
        for _ in range(result['NumberOfFingers']):
            if offset + 14 > len(data):
                break
            view = {
                'FingerPosition':  _translate(ISO19794_4_FINGER_POSITION, data[offset]),
                'CountOfViews':    data[offset + 1],
                'ViewNumber':      data[offset + 2],
                'ImageQuality':    data[offset + 3],
                'NumFeaturePoints': int.from_bytes(data[offset + 4:offset + 6], 'big'),
                'Width':           int.from_bytes(data[offset + 6:offset + 8], 'big'),
                'Height':          int.from_bytes(data[offset + 8:offset + 10], 'big'),
                'Reserved':        data[offset + 10:offset + 14],
            }
            views.append(view)
            offset += 14

        result['FingerViews'] = views
        return result, offset


class ISO19794_6:
    """ISO 19794-6 iris image CBEFF header parser (DG4).

    Global record header: 45 bytes (version 2005).
    Per-iris-image sub-header: 11 bytes.
    """

    @staticmethod
    def analyse(data: bytes) -> tuple:
        """Parse the CBEFF iris record header.

        Returns (meta_dict, header_size) where data[header_size:] is the
        raw iris image data for the first eye.
        """
        if data[0:4] != IIR:
            raise Exception(f"Missing IIR magic: {data[0:4]!r}")

        result = {}
        result['VersionNumber']   = data[4:8]
        result['LengthOfRecord']  = int.from_bytes(data[8:12], 'big')
        result['CBEFFProductID']  = int.from_bytes(data[12:14], 'big')
        result['CaptureDeviceID'] = int.from_bytes(data[14:16], 'big')
        result['CountOfEyes']     = int.from_bytes(data[16:18], 'big')
        # Image properties: roll angle (2 bytes) + uncertainty (2 bytes)
        result['RollAngle']       = int.from_bytes(data[18:20], 'big')
        result['RollAngleUncertainty'] = int.from_bytes(data[20:22], 'big')
        result['IrisPerImage']    = int.from_bytes(data[22:24], 'big')
        result['ImageWidth']      = int.from_bytes(data[24:26], 'big')
        result['ImageHeight']     = int.from_bytes(data[26:28], 'big')
        result['BitDepth']        = data[28]
        result['ImageFormat']     = _translate(ISO19794_6_COMPRESSION, data[29])
        result['ImageTransformation'] = data[30]
        result['DeviceUniqueID']  = data[31:39]

        # Parse per-iris-image sub-headers (11 bytes each)
        offset = 39
        eyes = []
        for _ in range(result['CountOfEyes']):
            if offset + 11 > len(data):
                break
            eye = {
                'EyeLabel':    _translate(ISO19794_6_EYE_LABEL, data[offset]),
                'ImageType':   _translate(ISO19794_6_IMAGE_KIND, data[offset + 1]),
                'ImageFormat': _translate(ISO19794_6_COMPRESSION, data[offset + 2]),
                'Width':       int.from_bytes(data[offset + 3:offset + 5], 'big'),
                'Height':      int.from_bytes(data[offset + 5:offset + 7], 'big'),
                'ImageLength': int.from_bytes(data[offset + 7:offset + 11], 'big'),
            }
            eyes.append(eye)
            offset += 11

        result['Eyes'] = eyes
        return result, offset


# Dispatch map used by BiometricTemplates to pick the right parser
BIOMETRIC_PARSERS = {
    FAC: ISO19794_5.analyse,
    FIR: ISO19794_4.analyse,
    IIR: ISO19794_6.analyse,
}
