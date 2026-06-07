"""ISO 19794-5 biometric facial image data format constants and parser."""

FAC = b"FAC\x00"

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


def _translate(dictionary, index):
    try:
        return dictionary[index]
    except KeyError:
        return index


class ISO19794_5:
    """Implement the ISO 19794-5 CBEFF biometric facial image header parser."""

    @staticmethod
    def analyse(data: bytes) -> tuple:
        """Parse the CBEFF header from a biometric data block.

        @param data: Image block starting with the CBEFF header.
        @type data: bytes
        @return: Tuple of (decoded_header_dict, header_size_in_bytes).
        @rtype: tuple(dict, int)
        @raise Exception: If the FAC magic bytes are missing.
        """
        offset = 0
        result = {}

        tag = data[0:4]
        if tag != FAC:
            raise Exception(f"Missing FAC magic in CBEFF block: {tag!r}")

        result['VersionNumber'] = data[4:7]
        result['LengthOfRecord'] = int.from_bytes(data[8:12], 'big')
        result['NumberOfFacialImages'] = int.from_bytes(data[12:14], 'big')
        result['FaceImageBlockLength'] = int.from_bytes(data[14:18], 'big')
        result['NumberOfFeaturePoint'] = int.from_bytes(data[18:20], 'big')
        result['Gender'] = _translate(ISO19794_5_GENDER, data[20])
        result['EyeColour'] = _translate(ISO19794_5_EYECOLOUR, data[21])
        result['HairColour'] = _translate(ISO19794_5_HAIRCOLOUR, data[22])

        feature_mask = int.from_bytes(data[23:26], 'big')
        result['FeatureMask'] = feature_mask
        result['Features'] = {
            v for k, v in ISO19794_5_FEATURE.items() if feature_mask & k
        }

        result['Expression'] = _translate(
            ISO19794_5_EXPRESSION, int.from_bytes(data[26:28], 'big')
        )
        result['PoseAngle'] = int.from_bytes(data[28:31], 'big')
        result['PoseAngleUncertainty'] = int.from_bytes(data[31:34], 'big')

        offset = 34

        result['FeaturePoint'] = []
        for _ in range(result['NumberOfFeaturePoint']):
            feature = {
                'FeatureType': data[offset],
                'FeaturePointCode': data[offset + 1],
                'HorizontalPosition': data[offset + 2:offset + 4],
                'VerticalPosition': data[offset + 4:offset + 6],
                'Reserved': data[offset + 6:offset + 8],
            }
            result['FeaturePoint'].append(feature)
            offset += 8

        result['FaceImageType'] = _translate(ISO19794_5_IMG_TYPE, data[offset])
        offset += 1
        result['ImageDataType'] = _translate(ISO19794_5_IMG_DTYPE, data[offset])
        offset += 1
        result['ImageWidth'] = int.from_bytes(data[offset:offset + 2], 'big')
        offset += 2
        result['ImageHeight'] = int.from_bytes(data[offset:offset + 2], 'big')
        offset += 2
        result['ImageColourSpace'] = _translate(ISO19794_5_IMG_CSPACE, data[offset])
        offset += 1
        result['ImageSourceType'] = _translate(ISO19794_5_IMG_SOURCE, data[offset])
        offset += 1
        result['ImageDeviceType'] = int.from_bytes(data[offset:offset + 2], 'big')
        offset += 2
        result['ImageQuality'] = _translate(
            ISO19794_5_IMG_QUALITY, int.from_bytes(data[offset:offset + 2], 'big')
        )
        offset += 2

        return result, offset
