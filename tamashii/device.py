#!/usr/bin/env python3
from hashlib import sha1 as SHA1
from base64 import standard_b64encode as encode_base64

from bitstring import ConstBitStream

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
    def __init__(self, header, image, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.header = header
        self.image = image

    @classmethod
    def from_data(this, data):
        if isinstance(data, ConstBitStream):
            stream = data
        else:
            stream = ConstBitStream(data)

        header = DeviceImageHeader.from_data(stream)

        stream.bytepos = header.header_size
        image = stream.read(f'bytes:{header.image_size}')

        return super().from_data(
            stream,
            header=header,
            image=image
        )

    def to_bytes(self):
        return b''.join([
            self.header.to_bytes(),
            self.image
        ])

    def get_image_sha1(self):
        return SHA1(self.image).digest()

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

    def refresh_image_sha1(self):
        self.header.image_sha1 = self.get_image_sha1()

    def update_image(self, data, position):
        image_size = len(self.image)

        if position > image_size:
            raise ValueError('Updated position is larger than the current image!')

        data_size = len(data)
        end_position = data_size + position

        if end_position > image_size:
            raise ValueError('Data size is larger than the current image!')

        self.image = b''.join([
            self.image[:position],
            data,
            self.image[end_position:]
        ])

    def get_image_stream(self):
        return ConstBitStream(self.image)

    def get_flattened_device_tree(self, position):
        # We correct the position by accounting for the header size.
        position = position - self.header.header_size

        stream = self.get_image_stream()
        stream.bytepos = position + 4
        size = stream.read('uint:32')
        stream.bytepos = position
        return stream.read(f'bytes:{size}')

    def get_fdt(self, *args, **kwargs):
        return self.get_flattened_device_tree(*args, **kwargs)

    def get_uimage(self, position):
        # We correct the position by accounting for the header size.
        position = position - self.header.header_size

        stream = self.get_image_stream()
        stream.bytepos = position + 12
        size = stream.read('uint:32')
        stream.bytepos = position
        return stream.read(f'bytes:{size}')

    def get_kernel(self, *args, **kwargs):
        return self.get_uimage(*args, **kwargs)

    def get_ramdisk(self, *args, **kwargs):
        return self.get_uimage(*args, **kwargs)
