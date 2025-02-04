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
    def __init__(self, data):
        super().__init__(data)
        stream = self._stream

        self.header = DeviceImageHeader(stream)

        stream.bytepos = self.header.header_size
        self.image = stream.read(f'bytes:{self.header.image_size}')

    @property
    def is_image_valid(self):
        calculated_sha1 = SHA1(self.image).digest()
        return calculated_sha1 == self.header.image_sha1

    def to_json(self):
        json = super().to_json()

        # We touch-up some of the fields.
        json.update({
            'image': encode_base64(self.image).decode(),
            'isImageValid': self.is_image_valid
        })

        return json

    def get_flattened_device_tree(self, position):
        stream = self._stream
        stream.bytepos = position + 4
        size = stream.read('uint:32')
        stream.bytepos = position
        return stream.read(f'bytes:{size}')

    def get_fdt(self, *args, **kwargs):
        return self.get_flattened_device_tree(*args, **kwargs)

    def get_uimage(self, position):
        stream = self._stream
        stream.bytepos = position + 12
        size = stream.read('uint:32')
        stream.bytepos = position
        return stream.read(f'bytes:{size}')

    def get_kernel(self, position):
        return self.get_uimage(position)

    def get_ramdisk(self, position):
        return self.get_uimage(position)
