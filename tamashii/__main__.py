from argparse import ArgumentParser
from os import path, makedirs
from sys import stdout, stderr

from bitstring import ConstBitStream
from loguru import logger

from .utilities import to_readable_size
from .ubi import UnsortedBlockImages, calculate_lebs
from .device import DeviceImage, DeviceImageHeader
from .boot import get_boot_arguments, get_fdt_position, get_kernel_position, get_ramdisk_position


logger.remove()


LEVEL_ICONS = {
    'DEBUG': '[ii]',
    'INFO': '[i]',
    'SUCCESS': '[+]',
    'WARNING': '[-]',
    'ERROR': '[!]',
    'CRITICAL': '[!!]'
}


def format_log_message(record):
    icon = LEVEL_ICONS.get(record['level'].name, '[ ]')
    return f'{record['time']:YYYY-MM-DD HH:mm:ss} - {icon} {record['message']}\n'


def extract_start_and_end(extract_path, ubi, data):
    start_data = data[:ubi.start_position]

    if len(start_data) > 0:
        logger.info(f'Extracting start data: 0x{0:08X}-0x{ubi.start_position:08X}')

        data_path = path.join(extract_path, f'data-0x{0:08X}-0x{ubi.start_position:08X}.bin')

        with open(data_path, 'wb') as file:
            file.write(start_data)
    else:
        logger.info('No start data in the image.')

    end_data = data[ubi.end_position:]

    if len(end_data) > 0:
        logger.info(f'Extracting end data: 0x{ubi.end_position:08X}-0x{len(data):08X}')

        data_path = path.join(extract_path, f'data-0x{ubi.end_position:08X}-0x{len(data):08X}.bin')

        with open(data_path, 'wb') as file:
            file.write(end_data)
    else:
        logger.info('No end data in the image.')


def extract_volumes(extract_path, ubi, volume_table_records):
    if volume_table_records:
        makedirs(path.join(extract_path, 'ubi'), exist_ok=True)

    for record in volume_table_records:
        parent_path = path.join(extract_path, f'ubi/volume-{record.volume_id}-{record.name}')
        makedirs(parent_path, exist_ok=True)

        output_path = path.join(parent_path, 'data.bin')
        logger.info(f'Extracting UBI volume to: {output_path}')

        volume = ubi.get_volume(record)

        with open(output_path, 'wb') as file:
            file.write(volume)


def extract_device_images(extract_path, ubi, volume_table_records, boot_arguments):
    for record in volume_table_records:
        volume = ubi.get_volume(record)
        header = DeviceImageHeader.from_data(volume)

        if not header.is_magic_valid:
            continue

        # We make the folder for the device image's contents.
        device_image = DeviceImage.from_data(volume)
        logger.info(f'Extracting device image: 0x{device_image.header.image_sha1.hex().upper()}')

        parent_path = path.join(extract_path, f'ubi/volume-{record.volume_id}-{record.name}/image-0x{device_image.header.image_sha1.hex().upper()}')
        makedirs(parent_path, exist_ok=True)

        fdt_position = get_fdt_position(boot_arguments)
        kernel_position = get_kernel_position(boot_arguments)
        ramdisk_position = get_ramdisk_position(boot_arguments)

        fdt = device_image.get_fdt(fdt_position)
        kernel = device_image.get_kernel(kernel_position)
        ramdisk = device_image.get_ramdisk(ramdisk_position)

        for name, content in [
            ('FDT', fdt),
            ('kernel', kernel),
            ('RAMdisk', ramdisk)
        ]:
            output_path = path.join(parent_path, f'{name.lower()}.bin')
            logger.info(f'Extracting {name} to: {output_path}')

            with open(output_path, 'wb') as file:
                file.write(content)


def read_image(image_path, extract_path):
    makedirs(extract_path, exist_ok=True)

    logger.info(f'Reading image from: {image_path}')

    with open(image_path, 'rb') as file:
        data = file.read()

    ubi = UnsortedBlockImages.from_data(data)
    logger.success(f'Detected UBI at: 0x{ubi.start_position:08X}-0x{ubi.end_position:08X} ({len(ubi.blocks)} blocks / {to_readable_size(ubi.block_size)} each)')

    volume_table_records = ubi.get_volume_table_records()
    boot_arguments = get_boot_arguments(data)

    extract_start_and_end(extract_path, ubi, data)
    extract_volumes(extract_path, ubi, volume_table_records)
    extract_device_images(extract_path, ubi, volume_table_records, boot_arguments)


def get_volume_table_record(ubi, volume_id):
    volume_table_records = ubi.get_volume_table_records()

    for record in volume_table_records:
        if record.volume_id != volume_id:
            continue

        return record


def write_image(image_path, volume_id, target, update_path, output_path):
    logger.info(f'Reading image from: {image_path}')

    with open(image_path, 'rb') as file:
        data = file.read()

    ubi = UnsortedBlockImages.from_data(data)
    logger.success(f'Detected UBI at: 0x{ubi.start_position:08X}-0x{ubi.end_position:08X} ({len(ubi.blocks)} blocks / {to_readable_size(ubi.block_size)} each)')

    target_record = get_volume_table_record(ubi, volume_id)

    if not target_record:
        logger.error(f'Could not find volume: {volume_id}')
        return

    volume = ubi.get_volume(target_record)
    device_image = DeviceImage.from_data(volume)
    boot_arguments = get_boot_arguments(data)

    if target == 'fdt':
        target_position = get_fdt_position(boot_arguments)
    elif target == 'kernel':
        target_position = get_kernel_position(boot_arguments)
    elif target == 'ramdisk':
        target_position = get_ramdisk_position(boot_arguments)

    # TODO: Update uImage headers to have valid CRC32 for both data and header values.

    with open(update_path, 'rb') as file:
        update_data = file.read()

    device_image.put(update_data, target_position)
    device_image.refresh_image_sha1()

    ubi.delete_volume_blocks(volume_id)
    ubi.put_volume_blocks(volume_id, device_image.to_bytes())

    with open(output_path, 'wb') as file:
        start_data = data[:ubi.start_position]
        end_data = data[ubi.end_position:]
        file.write(start_data)
        file.write(ubi.to_bytes())
        file.write(end_data)


def parse_arguments():
    parser = ArgumentParser(description='Process device NAND images')

    shared_parser = ArgumentParser(add_help=False)
    shared_parser.add_argument('-v', '--verbose', action='store_true', help='Whether verbose messages should be enabled')
    shared_parser.add_argument('image_path', help='A path to the image to work with')

    subparsers = parser.add_subparsers(dest='command', required=True)

    read_parser = subparsers.add_parser('read', parents=[shared_parser], help='Read from (and optionally extract from) the image')
    read_parser.add_argument('extract_path', help='The directory to extract into')

    write_parser = subparsers.add_parser('write', parents=[shared_parser], help='Write to the image')
    write_parser.add_argument('volume_id', type=int, help='The ID of the target\'s volume')
    write_parser.add_argument('target', choices=['fdt', 'kernel', 'ramdisk'], help='The target of the update')
    write_parser.add_argument('update_path', help='A path to the updated target')
    write_parser.add_argument('output_path', help='A path to the output image')

    return parser.parse_args()


def main():
    arguments = parse_arguments()

    if arguments.verbose:
        logger.add(stdout, format=format_log_message)
    else:
        logger.add(stderr, level='ERROR', format=format_log_message)

    if arguments.command == 'read':
        read_image(
            image_path=arguments.image_path,
            extract_path=arguments.extract_path
        )
    elif arguments.command == 'write':
        write_image(
            image_path=arguments.image_path,
            volume_id=arguments.volume_id,
            target=arguments.target,
            update_path=arguments.update_path,
            output_path=arguments.output_path
        )


if __name__ == '__main__':
    main()
