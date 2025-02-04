from argparse import ArgumentParser
from os import path, makedirs

from bitstring import ConstBitStream
from loguru import logger

from .ubi import UnsortedBlockImages
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


def read_image(file_path, extract_path=None):
    if extract_path:
        makedirs(extract_path, exist_ok=True)

    logger.info(f'Reading file: {file_path}')

    with open(file_path, 'rb') as file:
        data = file.read()

    ubi = UnsortedBlockImages(data)
    volume_table_records = ubi.get_volume_table_records()

    for record in volume_table_records:
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
        device_image = DeviceImage(volume)

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
                ('FDT', 'fdt.bin', fdt),
                ('kernel', 'kernel.bin', kernel),
                ('RAMdisk', 'ramdisk.bin', ramdisk)
            ]:
                output_path = path.join(extract_path, file_name)

                with open(output_path, 'wb') as file:
                    file.write(content)
                    logger.success(f'Extracted {name} to: {output_path}')


def write_image(file_path):
    logger.error('Write functionality not yet implemented!')


def parse_arguments():
    parser = ArgumentParser(description='Process device NAND images')

    subparsers = parser.add_subparsers(dest='command', required=True)

    read_parser = subparsers.add_parser('read', help='Read (and optionally extract) data from the image')
    read_parser.add_argument('path', help='Path to the image')
    read_parser.add_argument('-e', '--extract', metavar='DIR', help='Target directory to extract data')

    write_parser = subparsers.add_parser('write', help='Write data to the image')
    write_parser.add_argument('path', help='Path to the image')

    return parser.parse_args()


def main():
    arguments = parse_arguments()

    if arguments.command == 'read':
        read_image(arguments.path, extract_path=arguments.extract)
    elif arguments.command == 'write':
        write_image(arguments.path)


if __name__ == '__main__':
    main()
