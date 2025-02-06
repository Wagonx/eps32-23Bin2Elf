import json
from esp32_firmware_reader import *
from esptool.bin_image import *
from read_nvs import *

# Added ESP32-23 specific memory mappings
ESP32_23_MEMORY_MAP = {
    'DROM': (0x3F400000, 0x3F800000, 'DROM'),
    'EXTRAM': (0x3F800000, 0x3FC00000, 'BYTE_ACCESSIBLE, DRAM, DMA'),
    'IRAM': (0x40000000, 0x40400000, 'IRAM'),
    'IROM': (0x42000000, 0x42800000, 'IROM'),
    'RTC': (0x50000000, 0x50400000, 'RTC_IRAM')
}


def print_verbose(verbose, message):
    """Print message only if verbose flag is True"""
    if verbose:
        print(message)


def dump_bytes(fh, offset, size, output_file):
    """Dump bytes from file to output file"""
    fh.seek(offset)
    with open(output_file, 'wb') as out_fh:
        bytes_remaining = size
        while bytes_remaining > 0:
            chunk_size = min(bytes_remaining, 4096)  # Read in 4KB chunks
            out_fh.write(fh.read(chunk_size))
            bytes_remaining -= chunk_size


def read_partition_table(fh, verbose=False):
    """Read and parse the partition table from a firmware file"""
    # Standard ESP32 partition table offset
    PARTITION_TABLE_OFFSET = 0x8000

    # Partition table entry format
    PARTITION_ENTRY_SIZE = 32
    MAX_PARTITION_ENTRIES = 95

    partitions = {}

    if verbose:
        print("\nReading partition table...")
        print("{:<12} {:<8} {:<8} {:<8} {:<12} {:<8}".format(
            "Name", "Type", "SubType", "Offset", "Size", "Flags"))
        print("-" * 60)

    fh.seek(PARTITION_TABLE_OFFSET)

    for i in range(MAX_PARTITION_ENTRIES):
        entry = fh.read(PARTITION_ENTRY_SIZE)
        if len(entry) != PARTITION_ENTRY_SIZE:
            break

        # Check if entry is empty (all zeros)
        if all(b == 0 for b in entry):
            break

        # Parse partition entry
        name = entry[:16].strip(b'\x00').decode('utf-8')
        type_id = int.from_bytes(entry[16:17], byteorder='little')
        subtype = int.from_bytes(entry[17:18], byteorder='little')
        offset = int.from_bytes(entry[18:22], byteorder='little')
        size = int.from_bytes(entry[22:26], byteorder='little')
        flags = int.from_bytes(entry[26:28], byteorder='little')

        partitions[name] = {
            'type': type_id,
            'subtype': subtype,
            'offset': offset,
            'size': size,
            'flags': flags
        }

        if verbose:
            print("{:<12} {:<8d} {:<8d} {:<8x} {:<12d} {:<8d}".format(
                name, type_id, subtype, offset, size, flags))

    return partitions


def dump_partition(fh, part_name, offset, size, dump_file):
    """Dump a partition to a file"""
    print("Dumping partition '" + part_name + "' to " + dump_file)
    dump_bytes(fh, offset, size, dump_file)


def image_base_name(path):
    filename_w_ext = os.path.basename(path)
    filename, ext = os.path.splitext(filename_w_ext)
    return filename


def calcShFlg(flags):
    mask = 0
    if 'W' in flags:
        mask |= SHF.SHF_WRITE
    if 'A' in flags:
        mask |= SHF.SHF_ALLOC
    if 'X' in flags:
        mask |= SHF.SHF_EXECINSTR

    return mask


def calcPhFlg(flags):
    p_flags = 0
    if 'r' in flags:
        p_flags |= PF.PF_R
    if 'w' in flags:
        p_flags |= PF.PF_W
    if 'x' in flags:
        p_flags |= PF.PF_X
    return p_flags


def add_elf_symbols(elf):
    """Add symbols to the ELF file from symbols_dump.txt"""
    try:
        with open("symbols_dump.txt", "r") as fh:
            lines = fh.readlines()

            bind_map = {
                "LOCAL": STB.STB_LOCAL,
                "GLOBAL": STB.STB_GLOBAL
            }

            type_map = {
                "NOTYPE": STT.STT_NOTYPE,
                "OBJECT": STT.STT_OBJECT,
                "FUNC": STT.STT_FUNC,
                "FILE": STT.STT_FILE
            }

            for line in lines:
                try:
                    # Parse symbol line
                    line = line.split()
                    sym_binding = line[4]
                    sym_type = line[3]
                    sym_size = int(line[2])
                    sym_val = int(line[1], 16)
                    sym_name = line[7]

                    # Add symbol to ELF
                    elf.append_symbol(
                        sym_name,
                        0xfff1,  # ABS section index
                        sym_val,
                        sym_size,
                        sym_binding=bind_map[sym_binding],
                        sym_type=type_map[sym_type]
                    )
                except (IndexError, ValueError) as e:
                    print(f"Warning: Failed to parse symbol line: {line}")
                    continue
    except FileNotFoundError:
        print(
            "Warning: symbols_dump.txt not found - skipping symbol addition")
    except Exception as e:
        print(f"Warning: Error reading symbols: {str(e)}")

def image2elf(filename, output_file, chip_type='esp32', verbose=False):
    # Modified to support different chip types
    image = LoadFirmwareImage(chip_type, filename)

    image_name = image_base_name(filename)

    elf = ELF(e_machine=EM.EM_XTENSA, e_data=ELFDATA.ELFDATA2LSB)
    elf.Elf.Ehdr.e_entry = image.entrypoint

    print_verbose(verbose, "Entrypoint " + str(hex(image.entrypoint)))

    # Updated section map with ESP32-23 specific sections
    section_map = {
        'DROM': '.flash.rodata',
        'BYTE_ACCESSIBLE, DRAM, DMA': '.dram0.data',
        'IROM': '.flash.text',
        'RTC_IRAM': '.rtc.text',
        'EXTRAM': '.extram.data'  # New section for ESP32-23
    }

    # Updated section attributes map
    sect_attr_map = {
        '.flash.rodata': {'ES': 0x00, 'Flg': 'WA', 'Lk': 0, 'Inf': 0,
                          'Al': 16},
        '.dram0.data': {'ES': 0x00, 'Flg': 'WA', 'Lk': 0, 'Inf': 0, 'Al': 16},
        '.iram0.vectors': {'ES': 0x00, 'Flg': 'AX', 'Lk': 0, 'Inf': 0,
                           'Al': 4},
        '.iram0.text': {'ES': 0x00, 'Flg': 'AX', 'Lk': 0, 'Inf': 0, 'Al': 4},
        '.flash.text': {'ES': 0x00, 'Flg': 'AX', 'Lk': 0, 'Inf': 0, 'Al': 4},
        '.rtc.text': {'ES': 0x00, 'Flg': 'AX', 'Lk': 0, 'Inf': 0, 'Al': 4},
        '.extram.data': {'ES': 0x00, 'Flg': 'WA', 'Lk': 0, 'Inf': 0, 'Al': 16}
    }

    section_data = {}

    # Modified segment processing to handle ESP32-23 memory map
    iram_seen = False
    memory_map = ESP32_23_MEMORY_MAP if chip_type == 'esp32-23' else image.ROM_LOADER.MEMORY_MAP

    for seg in sorted(image.segments, key=lambda s: s.addr):
        segment_name = ", ".join(
            [seg_range[2] for seg_range in memory_map.values()
             if seg_range[0] <= seg.addr < seg_range[1]])

        if segment_name == '':
            continue

        section_name = ''
        if segment_name == 'IRAM':
            if not iram_seen:
                section_name = '.iram0.vectors'
            else:
                section_name = '.iram0.text'
            iram_seen = True
        else:
            if segment_name in section_map:
                section_name = section_map[segment_name]
            else:
                print("Unsure what to do with segment: " + segment_name)

        if section_name != '':
            if section_name in section_data:
                section_data[section_name]['data'] += seg.data
            else:
                section_data[section_name] = {'addr': seg.addr,
                                              'data': seg.data}

    # Add sections to ELF
    for name in section_data.keys():
        data = section_data[name]['data']
        addr = section_data[name]['addr']
        if name in sect_attr_map:
            sect = sect_attr_map[name]
            flg = calcShFlg(sect['Flg'])
            elf._append_section(name, data, addr, SHT.SHT_PROGBITS, flg,
                                sect['Lk'], sect['Inf'], sect['Al'],
                                sect['ES'])
        else:
            elf.append_section(name, data, addr)

    elf.append_special_section('.strtab')
    elf.append_special_section('.symtab')
    add_elf_symbols(elf)

    # Updated segment flags including ESP32-23 specific segments
    segments = {
        '.flash.rodata': 'rw',
        '.dram0.data': 'rw',
        '.iram0.vectors': 'rwx',
        '.flash.text': 'rx',
        '.rtc.text': 'rwx',
        '.extram.data': 'rw'
    }

    elf.Elf.Phdr_table.pop()
    bytes(elf)

    size_of_phdrs = len(Elf32_Phdr()) * len(segments)

    print_verbose(verbose, "\nAdding program headers")
    for (name, flags) in segments.items():
        if name not in section_data:
            continue

        if (name == '.iram0.vectors'):
            size = len(section_data['.iram0.vectors']['data'])
            if '.iram0.text' in section_data:
                size += len(section_data['.iram0.text']['data'])
        else:
            size = len(section_data[name]['data'])

        p_flags = calcPhFlg(flags)
        addr = section_data[name]['addr']
        align = 0x1000
        p_type = PT.PT_LOAD

        shstrtab_hdr, shstrtab = elf.get_section_by_name(name)
        offset = shstrtab_hdr.sh_offset + size_of_phdrs

        Phdr = Elf32_Phdr(PT.PT_LOAD, p_offset=offset, p_vaddr=addr,
                          p_paddr=addr, p_filesz=size, p_memsz=size,
                          p_flags=p_flags, p_align=align, little=elf.little)

        print_verbose(verbose, name + ": " + str(Phdr))
        elf.Elf.Phdr_table.append(Phdr)

    if output_file is not None:
        out_file = output_file
    else:
        out_file = image_name + '.elf'
    print("\nWriting ELF to " + out_file + "...")
    fd = os.open(out_file, os.O_WRONLY | os.O_CREAT | os.O_TRUNC)
    os.write(fd, bytes(elf))
    os.close(fd)


# Update main() to handle ESP32-23
def main():
    desc = 'ESP32 Firmware Image Parser Utility'
    arg_parser = argparse.ArgumentParser(description=desc)
    arg_parser.add_argument('action',
                            choices=['show_partitions', 'dump_partition',
                                     'create_elf', 'dump_nvs'],
                            help='Action to take')
    arg_parser.add_argument('input', help='Firmware image input file')
    arg_parser.add_argument('-output', help='Output file name')
    arg_parser.add_argument('-nvs_output_type',
                            help='output type for nvs dump',
                            type=str, choices=["text", "json"],
                            default="text")
    arg_parser.add_argument('-partition', help='Partition name (e.g. ota_0)')
    arg_parser.add_argument('-chip_type',
                            help='Chip type (esp32 or esp32-23)',
                            choices=['esp32', 'esp32-23'], default='esp32')
    arg_parser.add_argument('-v', default=False, help='Verbose output',
                            action='store_true')

    args = arg_parser.parse_args()

    with open(args.input, 'rb') as fh:
        verbose = False
        if args.action == 'show_partitions' or args.v is True:
            verbose = True

        part_table = read_partition_table(fh, verbose)

        if args.action in ['dump_partition', 'create_elf', 'dump_nvs']:
            if (args.partition is None):
                print("Need partition name")
                return

            part_name = args.partition

            if args.action == 'dump_partition' and args.output is not None:
                dump_file = args.output
            else:
                dump_file = part_name + '_out.bin'

            if part_name in part_table:
                part = part_table[part_name]

                if args.action == 'dump_partition':
                    dump_partition(fh, part_name, part['offset'],
                                   part['size'], dump_file)
                if args.action == 'create_elf':
                    if part['type'] != 0:
                        print(
                            "Uh oh... bad partition type. Can't convert to ELF")
                    else:
                        if args.output is None:
                            print("Need output file name")
                        else:
                            dump_partition(fh, part_name, part['offset'],
                                           part['size'], dump_file)
                            output_file = args.output
                            image2elf(dump_file, output_file, args.chip_type,
                                      verbose)
                elif args.action == 'dump_nvs':
                    if part['type'] != 1 or part['subtype'] != 2:
                        print(
                            "Uh oh... bad partition type. Can only dump NVS partition type.")
                    else:
                        dump_partition(fh, part_name, part['offset'],
                                       part['size'], dump_file)
                        with open(dump_file, 'rb') as fh:
                            if (args.nvs_output_type != "text"):
                                sys.stdout = open(os.devnull, 'w')
                            pages = read_nvs_pages(fh)
                            sys.stdout = sys.stdout = sys.__stdout__
                            if (args.nvs_output_type == "json"):
                                print(json.dumps(pages))
            else:
                print("Partition '" + part_name + "' not found.")


if __name__ == '__main__':
    main()