#!/usr/bin/env python3
from bitstring import ConstBitStream


class StreamStructure:
    FIELDS = []

    def __init__(self, data):
        if not isinstance(data, ConstBitStream):
            stream = ConstBitStream(data)
        else:
            stream = data

        self._stream = stream

        if not self.FIELDS:
            self._start_position = 0
            self._end_position = 0
            self._size = 0
            self._fields = b''
            return

        self._start_position = stream.bytepos

        for field, format_string in self.FIELDS:
            if not field:
                stream.read(format_string)
                continue

            setattr(self, field, stream.read(format_string))

        # We calculate the size of the fields and store it in the class.
        self._end_position = stream.bytepos
        self._size = (self._end_position - self._start_position)
        stream.bytepos = self._start_position
        self._fields = stream.read(f'bytes:{self._size}')

    def to_json(self):
        json = {}

        for field, value in self.__dict__.items():
            if field.startswith('_'):
                continue

            if isinstance(value, list):
                items = []

                for item in value:
                    if not hasattr(item, 'to_json'):
                        items.append(item)
                        continue

                    items.append(item.to_json())

                value = items
            elif hasattr(value, 'to_json'):
                value = value.to_json()

            json[to_camel_case(field)] = value

        return json

    def to_hex_dump(self, width=16):
        return to_hex_dump(self._fields, width)


def to_hex_dump(data, max_width=16):
    lines = []

    for offset in range(0, len(data), max_width):
        chunk = data[offset:offset + max_width]

        hex_bytes = ' '.join([
            f'{byte:02x}' for byte in chunk
        ])

        ascii_bytes = ''.join([
            (chr(byte) if byte > 31 and byte < 127 else '.') for byte in chunk
        ])

        lines.append(f'{offset:08x}  {hex_bytes:<{max_width * 3}}  {ascii_bytes}')

    return '\n'.join(lines)


def to_truncated_hex(data, max_width=32):
    string = data.hex()

    if len(string) <= max_width:
        return string

    keep = (max_width - 4) // 2
    return f'{string[:keep]}....{string[:-keep]}'


def to_camel_case(string):
    if '_' not in string:
        return string

    chunks = string.split('_')

    return chunks[0].lower() + ''.join([
        word.capitalize() for word in chunks[1:]
    ])


def to_readable_size(size):
    for unit in ['', 'K', 'M', 'G', 'T']:
        if abs(size) < 1024:
            return f'{size:.1f} {unit}B'

        size /= 1024

    raise ValueError('Size is too large')
