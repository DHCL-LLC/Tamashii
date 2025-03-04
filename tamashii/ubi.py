#!/usr/bin/env python3
from re import finditer, search
from enum import Enum
from zlib import crc32 as CRC32
from itertools import groupby as group_by
from base64 import standard_b64encode as encode_base64
from math import ceil

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

    def __init__(
        self,
        magic_signature=0x55424923,
        ubi_version=1,
        erase_counter=0,
        volume_identifier_header_offset=512,
        data_offset=2048,
        image_sequence=0,
        header_crc32=None,
        **kwargs
    ):
        super().__init__(**kwargs)
        self.magic_signature = magic_signature
        self.ubi_version = ubi_version
        self.erase_counter = erase_counter
        self.volume_identifier_header_offset = volume_identifier_header_offset
        self.data_offset = data_offset
        self.image_sequence = image_sequence

        if header_crc32 is None:
            self.header_crc32 = 0
            self.refresh_header_crc32()
        else:
            self.header_crc32 = header_crc32

    @property
    def vid_offset(self):
        return self.volume_identifier_header_offset

    @property
    def is_magic_valid(self):
        # The magic signature should be "UBI#".
        return self.magic_signature == 0x55424923

    @property
    def is_header_valid(self):
        return self.header_crc32 == self.get_header_crc32()

    def refresh_header_crc32(self):
        self.header_crc32 = self.get_header_crc32()

    def get_header_crc32(self):
        return generate_crc32(self.to_bytes()[:-4])

    def to_json(self):
        json = super().to_json()

        # We touch-up some of the fields.
        del json['headerCrc32']

        json.update({
            'headerCRC32': self.header_crc32,
            'isHeaderValid': self.is_header_valid,
        })

        return json


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

    def __init__(
        self,
        volume_id,
        logical_erase_block_number,
        magic_signature=0x55424921,
        ubi_version=1,
        volume_type=VolumeTypeEnum.DYNAMIC,
        copy_flag=0,
        compatibility=0,
        data_size=0,
        used_erase_blocks=0,
        data_padding=0,
        data_crc32=0,
        sequence_number=0,
        header_crc32=None,
        **kwargs
    ):
        super().__init__(**kwargs)
        self.volume_id = volume_id
        self.logical_erase_block_number = logical_erase_block_number
        self.magic_signature = magic_signature
        self.ubi_version = ubi_version
        self.volume_type = volume_type.value if isinstance(volume_type, VolumeTypeEnum) else volume_type
        self.copy_flag = copy_flag
        self.compatibility = compatibility
        self.data_size = data_size
        self.used_erase_blocks = used_erase_blocks
        self.data_padding = data_padding
        self.data_crc32 = data_crc32
        self.sequence_number = sequence_number

        if header_crc32 is None:
            self.header_crc32 = 0
            self.refresh_header_crc32()
        else:
            self.header_crc32 = header_crc32

    @property
    def leb_number(self):
        return self.logical_erase_block_number

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
        return self.header_crc32 == self.get_header_crc32()

    def refresh_header_crc32(self):
        self.header_crc32 = self.get_header_crc32()

    def get_header_crc32(self):
        return generate_crc32(self.to_bytes()[:-4])

    def to_json(self):
        json = super().to_json()

        # We touch-up some of the fields.
        del json['dataCrc32']
        del json['headerCrc32']

        json.update({
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

    def __init__(
        self,
        volume_id,
        reserved_physical_erase_blocks=0,
        alignment=1,
        data_padding=0,
        volume_type=VolumeTypeEnum.DYNAMIC,
        update_marker=0,
        name_size=0,
        _name=(b'\x00' * 128),
        flags=0,
        record_crc32=None,
        **kwargs
    ):
        super().__init__(**kwargs)
        self.volume_id = volume_id
        self.reserved_physical_erase_blocks = reserved_physical_erase_blocks
        self.alignment = alignment
        self.data_padding = data_padding

        if isinstance(volume_type, VolumeTypeEnum):
            volume_type = volume_type.value

        self.volume_type = volume_type
        self.update_marker = update_marker

        if len(_name) < 128:
            _name += b'\x00' * (128 - len(_name))

        self.name_size = name_size
        self._name = _name
        self.flags = flags

        if record_crc32 is None:
            self.record_crc32 = 0
            self.refresh_record_crc32()
        else:
            self.record_crc32 = record_crc32

    @classmethod
    def from_data(this, data, volume_id, **kwargs):
        return super().from_data(data, volume_id=volume_id, **kwargs)

    @property
    def reserved_pebs(self):
        return self.reserved_physical_erase_blocks

    @property
    def is_record_valid(self):
        return self.record_crc32 == self.get_record_crc32()

    def refresh_record_crc32(self):
        self.record_crc32 = self.get_record_crc32()

    def get_record_crc32(self):
        return generate_crc32(self.to_bytes()[:-4])

    @property
    def name(self):
        return self._name[:self.name_size].decode(errors='ignore')

    def to_json(self):
        json = super().to_json()

        # We touch-up some of the fields.
        del json['recordCrc32']

        json.update({
            'name': self.name,
            'recordCRC32': self.record_crc32,
            'isRecordValid': self.is_record_valid
        })

        return json


class PhysicalEraseBlock(StreamStructure):
    def __init__(
        self,
        block_id,
        erase_counter_header,
        volume_identifier_header=None,
        volume_table_records=None,
        data=b'',
        data_size=(126 * 1024),
        block_size=(128 * 1024),
        **kwargs
    ):
        super().__init__(**kwargs)
        self.block_id = block_id
        self.erase_counter_header = erase_counter_header
        self.volume_identifier_header = volume_identifier_header
        self.volume_table_records = volume_table_records or []
        self._data = data
        self.data_size = data_size
        self.block_size = block_size

    @classmethod
    def from_data(this, data, block_id, block_size=(128 * 1024), **kwargs):
        if isinstance(data, ConstBitStream):
            stream = data
        else:
            stream = ConstBitStream(data)

        start_position = stream.bytepos

        # We start by reading the erase counter header.
        ec_header = EraseCounterHeader.from_data(stream)

        # We then use that header to calculate the volume identifier header
        # position and parse it.
        stream.bytepos = start_position + ec_header.vid_offset
        vid_header = VolumeIdentifierHeader.from_data(stream)

        # We then calculate the block data size and its position.
        data_size = block_size - ec_header.data_offset
        data_position = start_position + ec_header.data_offset

        # We then read the data from the block.
        data = b''

        if ec_header.is_header_valid:
            stream.bytepos = data_position
            data = stream.read(f'bytes:{data_size}')

        # If the block is valid and internal, then we can parse some volume
        # table records out of its data.
        volume_table_records = []

        if vid_header.is_magic_valid:
            if vid_header.is_internal:
                stream.bytepos = data_position

                # Up to 128 records are stored, but all possible spaces have a
                # volume table record.
                for index in range(128):
                    record = VolumeTableRecord.from_data(stream, index)

                    # If the record is all 0x00, as indicated by its checksum, we skip it.
                    if record.record_crc32 == 0xF116C36B:
                        continue

                    volume_table_records.append(record)

                stream.bytepos = data_position + data_size
        else:
            vid_header = None

        return this(
            block_id=block_id,
            erase_counter_header=ec_header,
            volume_identifier_header=vid_header,
            volume_table_records=volume_table_records,
            data=data,
            data_size=data_size,
            block_size=block_size,
            **kwargs
        )

    @property
    def ec_header(self):
        return self.erase_counter_header

    @property
    def vid_header(self):
        return self.volume_identifier_header

    @property
    def is_data_valid(self):
        if not self.vid_header:
            return False

        return self.vid_header.data_crc32 == self.get_data_crc32()

    def refresh_data_crc32(self):
        if not self.vid_header:
            return False

        self.vid_header.data_crc32 = self.get_data_crc32()
        return True

    def get_data_crc32(self):
        return generate_crc32(self.data)

    @property
    def data(self):
        if not self.vid_header:
            return b''

        volume_type = VolumeTypeEnum(self.vid_header.volume_type)

        if volume_type == VolumeTypeEnum.DYNAMIC:
            return self._data
        elif volume_type == VolumeTypeEnum.STATIC:
            return self._data[:self.vid_header.data_size]

    def to_json(self):
        json = super().to_json()

        json.update({
            'data': encode_base64(self.data).decode()
        })

        return json

    def to_bytes(self):
        result = b''

        # We add the erase counter header and its padding.
        result += self.ec_header.to_bytes()
        result += b'\xFF' * (self.ec_header.vid_offset - len(result))

        # We add the volume identifier header and its padding, but only if
        # it's valid. If invalid, the header area will be filled with 0xFF.
        if self.vid_header:
            result += self.vid_header.to_bytes()

        result += b'\xFF' * (self.ec_header.data_offset - len(result))

        # We finally add the data and its padding.
        result += self.data
        result += b'\xFF' * (self.block_size - len(result))

        return result


class UnsortedBlockImages(StreamStructure):
    def __init__(
        self,
        blocks=None,
        start_position=0,
        end_position=None,
        data_size=(126 * 1024),
        block_size=(128 * 1024),
        **kwargs
    ):
        super().__init__(**kwargs)
        self.blocks = blocks or []
        self.start_position = start_position

        if end_position is None:
            self.end_position = start_position + (len(blocks) * block_size)
        else:
            self.end_position = end_position

        self.data_size = data_size
        self.block_size = block_size

    @classmethod
    def from_data(this, data, **kwargs):
        # We start out by checking whether any blocks are in the data.
        has_blocks = has_peb(data)

        if not has_blocks:
            raise ValueError('No physical erase blocks were found!')

        # We then begin to estimate the block size.
        block_sizes = get_peb_sizes(data)

        if len(block_sizes) == 0:
            raise ValueError('No physical erase blocks were found!')

        block_size, occurrences = block_sizes[0]

        # We're short one block since the last block can't be used for size estimation.
        block_count = occurrences + 1

        # We then get the start for our desired block size, to prevent false-positives.
        start_position = get_peb_start(data, block_size)

        # We can now start reading the UBI blocks.
        stream = ConstBitStream(data)

        blocks = []

        data_size = None

        for index in range(block_count):
            offset = start_position + (block_size * index)
            stream.bytepos = offset

            block = PhysicalEraseBlock.from_data(
                stream,
                block_id=index,
                block_size=block_size
            )

            if data_size is None:
                data_size = block.data_size

            blocks.append(block)

        end_position = start_position + (block_size * block_count)

        return super().from_data(
            stream,
            start_position=start_position,
            end_position=end_position,
            blocks=blocks,
            data_size=data_size,
            block_size=block_size,
            **kwargs
        )

    def get_internal_volume_blocks(self):
        blocks = []

        for block in self.blocks:
            is_internal = (
                block.vid_header and
                block.vid_header.is_internal
            )

            if not is_internal:
                continue

            blocks.append(block)

        return blocks

    def get_volume_table_records(self):
        internal_blocks = self.get_internal_volume_blocks()

        if not internal_blocks:
            raise RuntimeError('No internal blocks were found!')

        # All internal volumes treat their blocks as if they contain volume
        # table records, so we pick the first internal block and work with it.
        block = internal_blocks[0]

        if not block.volume_table_records:
            raise RuntimeError('No volume table records were found!')

        return block.volume_table_records

    def get_free_blocks(self):
        free_blocks = {}

        for block_id, block in enumerate(self.blocks):
            if block.vid_header:
                continue

            free_blocks[block_id] = block

        return free_blocks

    def delete_volume_blocks(self, volume_id):
        for block_id in range(len(self.blocks)):
            block = self.blocks[block_id]

            in_volume = (
                block.vid_header and
                block.vid_header.volume_id == volume_id
            )

            if not in_volume:
                continue

            self.blocks[block_id] = PhysicalEraseBlock(
                block_id=block_id,
                erase_counter_header=EraseCounterHeader(),
                data_size=block.data_size,
                block_size=block.block_size
            )

    def put_volume_blocks(self, volume_id, data):
        lebs = calculate_lebs(data, self.data_size)
        free_blocks = list(self.get_free_blocks().items())

        if len(free_blocks) < len(lebs):
            return False

        for leb, block_data in lebs.items():
            block_id, block = free_blocks[0]

            self.blocks[block_id] = PhysicalEraseBlock(
                block_id=block_id,
                erase_counter_header=EraseCounterHeader(),
                volume_identifier_header=VolumeIdentifierHeader(
                    volume_id=volume_id,
                    logical_erase_block_number=leb,
                ),
                data=block_data,
                data_size=block.data_size,
                block_size=block.block_size
            )

            del free_blocks[0]

        return True

    def get_logical_erase_blocks(self, volume_id):
        volume_blocks = []

        for block in self.blocks:
            in_volume = (
                block.vid_header and
                block.vid_header.volume_id == volume_id
            )

            if not in_volume:
                continue

            volume_blocks.append(block)

        return prepare_physical_erase_blocks(volume_blocks)

    def get_lebs(self, *args, **kwargs):
        return self.get_logical_erase_blocks(*args, **kwargs)

    def get_volume(self, volume_table_record):
        logical_erase_blocks = self.get_logical_erase_blocks(volume_table_record.volume_id)
        volume = b''

        for block_id in range(volume_table_record.reserved_pebs):
            block = logical_erase_blocks.get(block_id)

            if not block:
                volume += b'\xFF' * self.data_size
                continue

            volume += block.data

        return volume

    def to_bytes(self):
        result = []

        for block in self.blocks:
            result.append(block.to_bytes())

        return b''.join(result)


def generate_crc32(data):
    return ~CRC32(data) & 0xFFFFFFFF


def get_physical_erase_block_sizes(data):
    matches = [match.start() for match in finditer(b'UBI#', data)]

    offsets = {}

    for index in range(len(matches) - 1):
        offset = matches[index + 1] - matches[index]
        offsets[offset] = offsets.get(offset, 0) + 1

    return sorted(offsets.items(), key=lambda item: item[1], reverse=True)


get_peb_sizes = get_physical_erase_block_sizes


def has_physical_erase_block(data):
    return search(b'UBI#', data) is not None


has_peb = has_physical_erase_block


def get_physical_erase_block_start(data, size):
    matches = [match.start() for match in finditer(b'UBI#', data)]

    for index in range(len(matches) - 1):
        offset = matches[index + 1] - matches[index]

        if offset == size:
            return matches[index]

    return None


get_peb_start = get_physical_erase_block_start


def prepare_physical_erase_blocks(blocks):
    # We only keep blocks that have the latest image sequence.
    max_image_sequence = max([
        block.ec_header.image_sequence for block in blocks
    ])

    filtered_blocks = [
        block for block in blocks
        if block.ec_header.image_sequence == max_image_sequence
    ]

    # We sort the blocks by their logical erase block number and then their
    # sequence number in descending order.
    sorted_blocks = sorted(
        filtered_blocks,
        key=lambda block: (
            block.vid_header.logical_erase_block_number,
            -block.vid_header.sequence_number
        )
    )

    # We then keep only the first block from each group since it will be the
    # latest updated (because we sorted secondarily on the sequence number).
    unique_blocks = {}

    for leb_number, grouped_blocks in group_by(
        sorted_blocks,
        key=lambda block: block.vid_header.leb_number
    ):
        grouped_blocks = list(grouped_blocks)
        unique_blocks[leb_number] = grouped_blocks[0]

    return {
        leb_number: unique_blocks[leb_number]
        for leb_number in sorted(unique_blocks)
    }


prepare_pebs = prepare_physical_erase_blocks


def calculate_logical_erase_blocks(image, data_size):
    lebs = {}

    blocks = ceil(len(image) / data_size)
    empty_data = b'\xFF' * data_size

    for index in range(blocks):
        start_position = index * data_size
        end_position = start_position + data_size

        block_data = image[start_position:end_position]

        if block_data != empty_data:
            lebs[index] = block_data

    return lebs


calculate_lebs = calculate_logical_erase_blocks
