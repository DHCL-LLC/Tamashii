from argparse import ArgumentParser
from os import path, makedirs
from json import dumps as to_json

from bitstring import ConstBitStream
from loguru import logger

from .utilities import to_readable_size
from .ubi import UnsortedBlockImages, calculate_lebs
from .device import DeviceImage
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


logger.add(lambda msg: print(msg, end=''), format=format_log_message)


def read_image(image_path, extract_path=None, is_verbose=False):
    if extract_path:
        makedirs(extract_path, exist_ok=True)

    logger.info(f'Reading image: {image_path}')

    with open(image_path, 'rb') as file:
        data = file.read()

    ubi = UnsortedBlockImages.from_data(data)

    if is_verbose:
        logger.success(f'Parsed UBI and found: {len(ubi.blocks)} blocks ({to_readable_size(ubi.block_size)} each)')

    volume_table_records = ubi.get_volume_table_records()

    for record in volume_table_records:
        if is_verbose:
            logger.success(f'Found volume: {record.volume_id} ({record.name})')

        if extract_path:
            volume = ubi.get_volume(record)
            output_path = path.join(extract_path, f'volume-{record.volume_id}-{record.name}.bin')

            with open(output_path, 'wb') as file:
                file.write(volume)
                logger.success(f'Extracted volume: {output_path}')

    for record in volume_table_records:
        if 'part' not in record.name:
            continue

        volume = ConstBitStream(ubi.get_volume(record))
        device_image = DeviceImage.from_data(volume)

        if is_verbose:
            logger.success(f'Found device image on volume {record.volume_id} with checksum: {device_image.header.image_sha1.hex()}')

        if extract_path:
            logger.info(f'Extracting device image from volume: {record.name}')
            boot_arguments = get_boot_arguments(data)
            fdt_position = get_fdt_position(boot_arguments)
            kernel_position = get_kernel_position(boot_arguments)
            ramdisk_position = get_ramdisk_position(boot_arguments)

            fdt = device_image.get_fdt(fdt_position)
            kernel = device_image.get_kernel(kernel_position)
            ramdisk = device_image.get_ramdisk(ramdisk_position)

            for name, file_name, content in [
                ('FDT', 'image-fdt.bin', fdt),
                ('kernel', 'image-kernel.bin', kernel),
                ('RAMdisk', 'image-ramdisk.bin', ramdisk)
            ]:
                output_path = path.join(extract_path, file_name)

                with open(output_path, 'wb') as file:
                    file.write(content)
                    logger.success(f'Extracted {name} to: {output_path}')


def write_image(image_path, volume_id, target, update_path, is_verbose=False):
    logger.info(f'Reading image: {image_path}')

    with open(image_path, 'rb') as file:
        data = file.read()

    ubi = UnsortedBlockImages.from_data(data)

    if is_verbose:
        logger.success(f'Parsed UBI and found: {len(ubi.blocks)} blocks ({to_readable_size(ubi.block_size)} each)')

    volume_table_records = ubi.get_volume_table_records()

    target_record = None

    for record in volume_table_records:
        if record.volume_id != volume_id:
            continue

        if is_verbose:
            logger.success(f'Found volume: {record.volume_id} ({record.name})')

        target_record = record
        break

    if not target_record:
        logger.error(f'Could not find volume: {volume_id}')
        return

    volume = ConstBitStream(ubi.get_volume(record))
    device_image = DeviceImage.from_data(volume)

    if is_verbose:
        logger.success(f'Found device image on volume {record.volume_id} with checksum: {device_image.header.image_sha1.hex()}')

    logger.info(f'Extracting device image from volume: {record.name}')
    boot_arguments = get_boot_arguments(data)

    if target == 'fdt':
        fdt_position = get_fdt_position(boot_arguments)
        fdt = device_image.get_fdt(fdt_position)
    elif target == 'kernel':
        kernel_position = get_kernel_position(boot_arguments)
        kernel = device_image.get_kernel(kernel_position)
    elif target == 'ramdisk':
        ramdisk_position = get_ramdisk_position(boot_arguments)

        with open(update_path, 'rb') as file:
            update_data = file.read()

        device_image.update_image(update_data, ramdisk_position)
        device_image.refresh_image_sha1()

        lebs = calculate_lebs(device_image.to_bytes(), ubi.data_size)
        # TODO: Finish write implementation.


def parse_arguments():
    parser = ArgumentParser(description='Process device NAND images')

    shared_parser = ArgumentParser(add_help=False)
    shared_parser.add_argument('-v', '--verbose', action='store_true', help='Whether verbose messages should be enabled')
    shared_parser.add_argument('image', help='A path to the image to work with')

    subparsers = parser.add_subparsers(dest='command', required=True)

    read_parser = subparsers.add_parser('read', parents=[shared_parser], help='Read from (and optionally extract from) the image')
    read_parser.add_argument('-e', '--extract', metavar='directory', help='The target directory to extract into')

    write_parser = subparsers.add_parser('write', parents=[shared_parser], help='Write to the image')
    write_parser.add_argument('volume', type=int, help='The ID of the target\'s volume')
    write_parser.add_argument('target', choices=['fdt', 'kernel', 'ramdisk'], help='The target of the update')
    write_parser.add_argument('update', help='A path to the updated target')

    return parser.parse_args()


def main():
    arguments = parse_arguments()

    if arguments.command == 'read':
        read_image(
            image_path=arguments.image,
            extract_path=arguments.extract,
            is_verbose=arguments.verbose
        )
    elif arguments.command == 'write':
        write_image(
            image_path=arguments.image,
            volume_id=arguments.volume,
            target=arguments.target,
            update_path=arguments.update,
            is_verbose=arguments.verbose
        )


if __name__ == '__main__':
    main()
