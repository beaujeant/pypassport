from operator import and_

FAC = b"FAC\x00"

# ISO 19794_5 (Biometric identifiers)
ISO19794_5_GENDER = {
    0x00: 'Unpecified',
    0x01: 'Male',
    0x02: 'Female',
    0x03: 'Unknown'
}

ISO19794_5_EYECOLOUR = {
    0x00: 'Unspecified',
    0x01: 'Blacloggingi',
    0x07: 'Pink',
    0x08: 'Other'
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
    0xff: 'Other'
}

ISO19794_5_FEATURE = {
    0x01: 'Specified',
    0x02: 'Glasses',
    0x04: 'Moustache',
    0x08: 'Beard',
    0x10: 'Teeth Visible',
    0x20: 'Blink',
    0x40: 'Mouth Open',
    0x80: 'Left Eyepatch',
    0x100: 'Right Eyepatch',
    0x200: 'Dark Glasses',
    0x400: 'Distorted'
}

ISO19794_5_EXPRESSION = {
    0x0000: 'Unspecified',
    0x0001: 'Neutral',
    0x0002: 'Smile Closed',
    0x0003: 'Smile Open',
    0x0004: 'Raised Eyebrow',
    0x0005: 'Looking Away',
    0x0006: 'Squinting',
    0x0007: 'Frowning'
}

ISO19794_5_IMG_TYPE = {
    0x00: 'Unspecified (Front)',
    0x01: 'Basic',
    0x02: 'Full Front',
    0x03: 'Token Front',
    0x04: 'Other'
}

ISO19794_5_IMG_DTYPE = {
    0x00: 'JPEG',
    0x01: 'JPEG 2000'
}

ISO19794_5_IMG_FTYPE = {
    0x00: 'JPG',
    0x01: 'JP2'
}

ISO19794_5_IMG_CSPACE = {
    0x00: 'Unspecified',
    0x01: 'RGB24',
    0x02: 'YUV422',
    0x03: 'GREY8BIT',
    0x04: 'Other'
}

ISO19794_5_IMG_SOURCE = {
    0x00: 'Unspecified',
    0x01: 'Static Unspecified',
    0x02: 'Static Digital',
    0x03: 'Static Scan',
    0x04: 'Video Unknown',
    0x05: 'Video Analogue',
    0x06: 'Video Digital',
    0x07: 'Unknown'
}

ISO19794_5_IMG_QUALITY = {'0000': 'Unspecified'}

def translate(dictionary, index):
        try:
            return dictionary[index]
        except KeyError:
            return index


class ISO19794_5:
    """ Implement the ISO19794-5 concerning biometric Facial Pictures """

    @staticmethod
    def analyse(data):
        """ Analyze the content of the CBEFF header

            @param data: Image Block with header
            @type data: binary data

            @return: tuple composed of header size and decoded header
            @rtype: tuple(int, dict)
        """

        offset = 0
        result = {}
        tag = data[0:4]
        if tag != FAC:
            raise Exception(f"Missing FAC in CBEFF block: {tag.decode()}")

        result['VersionNumber'] = data[4:7]
        result['LengthOfRecord'] = int.from_bytes(data[8:12])
        result['NumberOfFacialImages'] = int.from_bytes(data[12:14])
        result['FaceImageBlockLength'] = int.from_bytes(data[14:18])
        result['NumberOfFeaturePoint'] = int.from_bytes(data[18:20])
        result['Gender'] = translate(ISO19794_5_GENDER, data[20])
        result['EyeColour'] = translate(ISO19794_5_EYECOLOUR, data[21])
        result['HairColour'] = translate(ISO19794_5_HAIRCOLOUR, data[22])
        result['FeatureMask'] = int.from_bytes(data[23:26])
        result['Features'] = {}
        for key, value in ISO19794_5_FEATURE.items():
            if and_(result['FeatureMask'], key):
                result['Features'][key] = value
        result['Expression'] = translate(ISO19794_5_EXPRESSION, int.from_bytes(data[26:28]))
        result['PoseAngle'] = int.from_bytes(data[28:31])
        result['PoseAngleUncertainty'] = int.from_bytes(data[31:34])

        offset = 34

        result['FeaturePoint'] = []
        for i in range(result['NumberOfFeaturePoint']):
            feature = {}

            feature['FeatureType'] = data[offset] # 1 == 2D; other RFU
            offset += 1

            feature['FeaturePointCode'] = data[offset]
            offset += 1

            feature['HorizontalPosition'] = data[offset:offset+2]
            offset += 2

            feature['VerticalPosition'] = data[offset:offset+2]
            offset += 2

            feature['Reserved'] = data[offset:offset+2]
            offset += 2

            result['FeaturePoint'][i] = feature

        result['FaceImageType'] = translate(ISO19794_5_IMG_TYPE, data[offset])
        offset += 1

        result['ImageDataType'] = translate(ISO19794_5_IMG_DTYPE, data[offset])
        offset += 1

        result['ImageWidth'] = int.from_bytes(data[offset:offset+2])
        offset += 2

        result['ImageHeight'] = int.from_bytes(data[offset:offset+2])
        offset += 2

        result['ImageColourSpace'] = translate(ISO19794_5_IMG_CSPACE, data[offset])
        offset += 1

        result['ImageSourceType'] = translate(ISO19794_5_IMG_SOURCE, data[offset])
        offset += 1

        result['ImageDeviceType'] = int.from_bytes(data[offset:offset+2])
        offset += 2

        result['ImageQuality'] = translate(ISO19794_5_IMG_QUALITY, int.from_bytes(data[offset:offset+2]))
        offset += 2

        return result, offset
