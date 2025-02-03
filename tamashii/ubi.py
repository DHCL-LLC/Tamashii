#!/usr/bin/env python3
from re import finditer, search
from enum import Enum
from zlib import crc32 as CRC32
from itertools import groupby as group_by
from base64 import standard_b64encode as encode_base64

from bitstring import ConstBitStream

from .utilities import StreamStructure, to_hex_dump


class VolumeTypeEnum(Enum):
    DYNAMIC = 1
    STATIC = 2


class EraseCounterHeader(StreamStructure):
    FIELDS = [
        ('magic_signature', 'uint:32'),
        ('ubi_version', 'uint:8'),
        (None, 'bytes:3'),
        ('erase_counter', 'uint:64'),
        ('volume_identifier_header_offset', 'uint:32'),
        ('data_offset', 'uint:32'),
        ('image_sequence', 'uint:32'),
        (None, 'bytes:32'),
        ('header_crc32', 'uint:32')
    ]

    @property
    def is_magic_valid(self):
        # The magic signature should be "UBI#".
        return self.magic_signature == 0x55424923

    @property
    def is_header_valid(self):
        calculated_crc32 = generate_crc32(self._fields[:-4])
        return calculated_crc32 == self.header_crc32

    def to_json(self):
        json = super().to_json()

        # We touch-up some of the fields.
        del json['headerCrc32']

        json.update({
            'headerCRC32': self.header_crc32,
            'isHeaderValid': self.is_header_valid,
        })

        return json


class PhysicalEraseBlock(StreamStructure):
    def __init__(self, block_id, block_size, stream):
        self.block_id = block_id

        # We use this to keep track of where the physical erase block started.
        self._start_position = stream.bytepos

        # We parse the block's erase counter header.
        self.erase_counter_header = EraseCounterHeader(stream)

        # We parse the block's volume identifier header.
        volume_identifier_header_position = (
            self._start_position +
            self.erase_counter_header.volume_identifier_header_offset
        )

        stream.bytepos = volume_identifier_header_position

        self.volume_identifier_header = VolumeIdentifierHeader(stream)

        # We store a copy of the block's remaining data.
        self.data_size = block_size - self.erase_counter_header.data_offset

        self.data_position = (
            self._start_position +
            self.erase_counter_header.data_offset
        )

        stream.bytepos = self.data_position

        self._data = stream.read(f'bytes:{self.data_size}')

        # If the block is valid and internal, then we can parse the volume
        # table records out of its data.
        is_volume_table = (
            self.volume_identifier_header.is_magic_valid and
            self.volume_identifier_header.is_internal
        )

        self.volume_table_records = []

        if is_volume_table:
            stream.bytepos = self.data_position

            # Up to 128 records are stored, but all possible spaces have a
            # volume table record.
            for index in range(128):
                record = VolumeTableRecord(index, stream)

                # If the record is all 0x00, as indicated by its checksum, we skip it.
                if record.record_crc32 == 0xF116C36B:
                    continue

                self.volume_table_records.append(record)

            stream.bytepos = self.data_position + self.data_size

    @property
    def is_data_valid(self):
        if not self.volume_identifier_header.is_magic_valid:
            return False

        calculated_crc32 = generate_crc32(self.data)
        return calculated_crc32 == self.volume_identifier_header.data_crc32

    def to_hex_dump(self, width=16):
        return to_hex_dump(self._data, width)

    def to_json(self):
        json = super().to_json()

        del json['blockId']

        json.update({
            'block': self.block_id,
            'data': encode_base64(self.data).decode()
        })

        return json

    @property
    def data(self):
        if not self.volume_identifier_header.is_magic_valid:
            return b''

        volume_type = VolumeTypeEnum(self.volume_identifier_header.volume_type)

        if volume_type == VolumeTypeEnum.DYNAMIC:
            return self._data
        elif volume_type == VolumeTypeEnum.STATIC:
            return self._data[:self.volume_identifier_header.data_size]


class VolumeIdentifierHeader(StreamStructure):
    FIELDS = [
        ('magic_signature', 'uint:32'),
        ('ubi_version', 'uint:8'),
        ('volume_type', 'uint:8'),
        ('copy_flag', 'uint:8'),
        ('compatibility', 'uint:8'),
        ('volume_id', 'uint:32'),
        ('logical_erase_block_number', 'uint:32'),
        (None, 'bytes:4'),
        ('data_size', 'uint:32'),
        ('used_erase_blocks', 'uint:32'),
        ('data_padding', 'uint:32'),
        ('data_crc32', 'uint:32'),
        (None, 'bytes:4'),
        ('sequence_number', 'uint:64'),
        (None, 'bytes:12'),
        ('header_crc32', 'uint:32')
    ]

    @property
    def is_internal(self):
        # UBI is designed to reserve 4096 volume IDs for internal volumes.
        return self.volume_id >= (0x7FFFFFFF - 4096)

    @property
    def is_magic_valid(self):
        # The magic signature should be "UBI!".
        return self.magic_signature == 0x55424921

    @property
    def is_header_valid(self):
        calculated_crc32 = generate_crc32(self._fields[:-4])
        return calculated_crc32 == self.header_crc32

    def to_json(self):
        json = super().to_json()

        # We touch-up some of the fields.
        del json['dataCrc32']
        del json['headerCrc32']
        del json['volumeId']

        json.update({
            'volume': self.volume_id,
            'dataCRC32': self.data_crc32,
            'headerCRC32': self.header_crc32,
            'isHeaderValid': self.is_header_valid,
            'isInternal': self.is_internal
        })

        return json


class VolumeTableRecord(StreamStructure):
    FIELDS = [
        ('reserved_physical_erase_blocks', 'uint:32'),
        ('alignment', 'uint:32'),
        ('data_padding', 'uint:32'),
        ('volume_type', 'uint:8'),
        ('update_marker', 'uint:8'),
        ('name_size', 'uint:16'),
        ('_name', 'bytes:128'),
        ('flags', 'uint:8'),
        (None, 'bytes:23'),
        ('record_crc32', 'uint:32')
    ]

    def __init__(self, volume_id, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.volume_id = volume_id

    @property
    def is_record_valid(self):
        calculated_crc32 = generate_crc32(self._fields[:-4])
        return calculated_crc32 == self.record_crc32

    @property
    def name(self):
        return self._name[:self.name_size].decode(errors='ignore')

    def to_json(self):
        json = super().to_json()

        # We touch-up some of the fields.
        del json['recordCrc32']
        del json['volumeId']

        json.update({
            'volume': self.volume_id,
            'name': self.name,
            'recordCRC32': self.record_crc32,
            'isRecordValid': self.is_record_valid
        })

        return json


class UnsortedBlockImages(StreamStructure):
    def __init__(self, data):
        self._data = data

        # We start out by checking whether any blocks are in the data.
        has_blocks = has_physical_erase_block(data)

        if not has_blocks:
            raise ValueError('No physical erase blocks were found!')

        # We then begin to estimate the block size.
        block_sizes = get_physical_erase_block_sizes(data)

        if len(block_sizes) == 0:
            raise ValueError('Only one physical erase block was found!')

        block_size, occurrences = block_sizes[0]
        self.block_size = block_size
        self.data_size = block_size

        # We then get the start for our desired block size, to prevent false-positives.
        block_start = get_physical_erase_block_start(data, block_size)
        self._start_position = block_start

        # We can now start reading the UBI blocks.
        stream = ConstBitStream(data)

        self.blocks = []

        for index in range(occurrences):
            offset = block_start + (block_size * index)
            stream.bytepos = offset

            block = PhysicalEraseBlock(
                block_id=index,
                block_size=block_size,
                stream=stream
            )

            if self.data_size == block_size:
                self.data_size = block.data_size

            self.blocks.append(block)

        self._end_position = stream.bytepos

    def to_hex_dump(self, width=16):
        return to_hex_dump(self._data, width)

    def get_internal_volume_blocks(self):
        blocks = []

        for block in self.blocks:
            is_internal = (
                block.volume_identifier_header.is_magic_valid and
                block.volume_identifier_header.is_internal
            )

            if not is_internal:
                continue

            blocks.append(block)

        return blocks

    def get_volume_table_records(self):
        internal_blocks = self.get_internal_volume_blocks()

        if not internal_blocks:
            raise RuntimeError('No internal blocks were found!')

        block = internal_blocks[0]

        if not block.volume_table_records:
            raise RuntimeError('No volume table records were found!')

        return block.volume_table_records

    def get_logical_erase_blocks(self, volume_id):
        volume_blocks = []

        for block in self.blocks:
            in_volume = (
                block.volume_identifier_header.is_magic_valid and
                block.volume_identifier_header.volume_id == volume_id
            )

            if not in_volume:
                continue

            volume_blocks.append(block)

        return prepare_physical_erase_blocks(volume_blocks)

    def read_volume(self, volume_table_record):
        logical_erase_blocks = self.get_logical_erase_blocks(volume_table_record.volume_id)
        volume = b''

        for block_id in range(volume_table_record.reserved_physical_erase_blocks):
            block = logical_erase_blocks.get(block_id)

            if not block:
                volume += b'\xFF' * self.data_size
                continue

            volume += block.data

        return volume

    def extract_volumes(self, path='.'):
        volume_table_records = self.get_volume_table_records()

        for record in volume_table_records:
            volume = self.read_volume(record)

            with open(f'{path}/volume-{record.volume_id}-{record.name}.bin', 'wb') as file:
                file.write(volume)


def generate_crc32(data):
    return ~CRC32(data) & 0xFFFFFFFF


def get_physical_erase_block_sizes(data):
    matches = [match.start() for match in finditer(b'UBI#', data)]

    offsets = {}

    for index in range(len(matches) - 1):
        offset = matches[index + 1] - matches[index]
        offsets[offset] = offsets.get(offset, 0) + 1

    return sorted(offsets.items(), key=lambda item: item[1], reverse=True)


def has_physical_erase_block(data):
    return search(b'UBI#', data) is not None


def get_physical_erase_block_start(data, size):
    matches = [match.start() for match in finditer(b'UBI#', data)]

    for index in range(len(matches) - 1):
        offset = matches[index + 1] - matches[index]

        if offset == size:
            return matches[index]

    return None


def prepare_physical_erase_blocks(blocks):
    # We only keep blocks that have the latest image sequence.
    max_image_sequence = max([
        block.erase_counter_header.image_sequence for block in blocks
    ])

    filtered_blocks = [
        block for block in blocks
        if block.erase_counter_header.image_sequence == max_image_sequence
    ]

    # We sort the blocks by their logical erase block number and then their
    # sequence number in descending order.
    sorted_blocks = sorted(
        filtered_blocks,
        key=lambda block: (
            block.volume_identifier_header.logical_erase_block_number,
            -block.volume_identifier_header.sequence_number
        )
    )

    # We then keep only the first block from each group since it will be the
    # latest updated (because we sorted secondarily on the sequence number).
    unique_blocks = {}

    for logical_erase_block_number, grouped_blocks in group_by(
        sorted_blocks,
        key=lambda block: block.volume_identifier_header.logical_erase_block_number
    ):
        grouped_blocks = list(grouped_blocks)
        unique_blocks[logical_erase_block_number] = grouped_blocks[0]

    return {
        logical_erase_block_number: unique_blocks[logical_erase_block_number]
        for logical_erase_block_number in sorted(unique_blocks)
    }
