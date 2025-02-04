#!/usr/bin/env python3
def get_boot_arguments(data):
    start_position = data.index(b'bootargs=')
    end_position = data.index(b'\x00\x00', start_position)

    boot_arguments = []

    for chunk in data[start_position:end_position].split(b'\x00'):
        boot_arguments.append(chunk.decode(errors='ignore').split('=', 1))

    return boot_arguments


def get_boot_argument(boot_arguments, end):
    result = None

    for key, value in boot_arguments:
        if key.endswith(end):
            result = value
            break

    return result


def get_base_position(boot_arguments):
    return int(get_boot_argument(boot_arguments, '_loadaddr'), 16)


def get_flattened_device_tree_position(boot_arguments):
    base_position = get_base_position(boot_arguments)
    return int(get_boot_argument(boot_arguments, '_loadaddr_fdt'), 16) - base_position


get_fdt_position = get_flattened_device_tree_position


def get_kernel_position(boot_arguments):
    base_position = get_base_position(boot_arguments)
    return int(get_boot_argument(boot_arguments, '_loadaddr_kernel'), 16) - base_position


def get_ramdisk_position(boot_arguments):
    base_position = get_base_position(boot_arguments)
    return int(get_boot_argument(boot_arguments, '_loadaddr_ramdisk'), 16) - base_position
