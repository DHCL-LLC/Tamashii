#!/usr/bin/env python3
from hashlib import sha1 as SHA1
from base64 import standard_b64encode as encode_base64

from .utilities import StreamStructure


class DeviceImageHeader(StreamStructure):
    FIELDS = [
        ('magic_signature', 'bytes:4'),
        ('header_size', 'uint:32'),
        ('image_size', 'uint:32'),
        ('image_sha1', 'bytes:20'),
    ]

    def to_json(self):
        json = super().to_json()

        # We touch-up some of the fields.
        del json['imageSha1']

        json.update({
            'imageSHA1': encode_base64(self.image_sha1).decode(),
        })

        return json


class DeviceImage(StreamStructure):
    def __init__(self, stream):
        self.device_image_header = DeviceImageHeader(stream)

        stream.bytepos = self.device_image_header.header_size
        self.image = stream.read(f'bytes:{self.device_image_header.image_size}')

    @property
    def is_image_valid(self):
        calculated_sha1 = SHA1(self.image).digest()
        return calculated_sha1 == self.device_image_header.image_sha1

    def to_json(self):
        json = super().to_json()

        # We touch-up some of the fields.
        json.update({
            'image': encode_base64(self.image).decode(),
            'isImageValid': self.is_image_valid
        })

        return json
