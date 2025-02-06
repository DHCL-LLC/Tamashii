#!/usr/bin/env python3
from struct import pack

from bitstring import ConstBitStream


class StreamStructure:
    FIELDS = []

    def __init__(self, **kwargs):
        field_names = [name for name, _ in self.FIELDS]

        for key, value in kwargs.items():
            if key not in field_names:
                raise ValueError(f'An unexpected keyword argument was supplied: {key}')

            setattr(self, key, value)

    @classmethod
    def from_data(this, data, **kwargs):
        # We start out by checking whether or not there are any fields to parse.
        if not this.FIELDS:
            return this(**kwargs)

        # We then read in the fields from the data as a stream.
        if isinstance(data, ConstBitStream):
            stream = data
        else:
            stream = ConstBitStream(data)

        values = {}

        for field, format_string in this.FIELDS:
            if not field:
                stream.read(format_string)
                continue

            values[field] = stream.read(format_string)

        return this(
            **values,
            **kwargs
        )

    def to_bytes(self):
        field_bytes = []

        for field, format_string in self.FIELDS:
            if not field:
                if not format_string.startswith('bytes'):
                    raise ValueError(f'Unsupported field type for unused: {format_string}')

                size = int(format_string.split(':')[1])
                field_bytes.append(b'\x00' * size)
                continue

            value = getattr(self, field)

            if format_string.startswith('bytes'):
                size = int(format_string.split(':')[1])

                if len(value) != size:
                    raise ValueError(f"{field} must be exactly {size} bytes.")

                field_bytes.append(value)

            elif format_string.startswith('uint'):
                bits = int(format_string.split(':')[1])

                if bits == 8:
                    field_bytes.append(pack('>B', value))
                elif bits == 16:
                    field_bytes.append(pack('>H', value))
                elif bits == 32:
                    field_bytes.append(pack('>I', value))
                elif bits == 64:
                    field_bytes.append(pack('>Q', value))
                else:
                    raise ValueError(f"Unsupported uint size: {bits} bits")
            else:
                raise ValueError(f"Unsupported field type: {format_string}")

        return b''.join(field_bytes)

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
