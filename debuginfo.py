#!/usr/bin/env python3

import argparse
import sys
import math
from babeltrace import TraceCollection
from collections import namedtuple
from elftools.elf.elffile import ELFFile
from elftools.common.py3compat import bytes2str

_DESC = 'Map events from userspace trace to symbols'
_VERSION = '0.1.0'

SourceLocation = namedtuple('SourceLocation', 'filename, line')

class DebugInfoAnalysis():
    def __init__(self, args):
        self._open_trace(args.trace_path)
        # SO info indexed by base address
        self._shared_objects = {}
        # Memoized function names and SourceLocations, indexed by
        # address
        self._function_names = {}
        self._source_locations = {}

    def _open_trace(self, path):
        traces = TraceCollection()
        handles = traces.add_traces_recursive(path, 'ctf')
        if not handles:
            print('Failed to open ' + path, file=sys.stderr)
            sys.exit(-1)

        self._handles = handles
        self._traces = traces

    def _close_trace(self):
        for handle in self._handles.values():
            self._traces.remove_trace(handle)

    def _lookup_function_name(self, address):
        so = self.get_so_by_address(address)

        # Addresses in DWARF are relative to base address for PIC, so
        # make the address argument relative too if needed
        if so.is_pic:
            address -= so.low_addr

        for compile_unit in so.dwarf_info.iter_CUs():
            for die in compile_unit.iter_DIEs():
                try:
                    if die.tag == 'DW_TAG_subprogram':
                        func_name = bytes2str(
                            die.attributes['DW_AT_name'].value)
                        low_pc = die.attributes['DW_AT_low_pc'].value
                        high_pc_attr = die.attributes['DW_AT_high_pc']
                        if high_pc_attr.form == 'DW_FORM_addr':
                            high_pc = high_pc_attr.value
                        else:
                            # high_pc relative to low_pc
                            high_pc = low_pc + high_pc_attr.value

                        if low_pc <= address <= high_pc:
                            self._function_names[address] = func_name
                            return self._function_names[address]
                except KeyError:
                    continue

        return None

    def _lookup_source_location(self, address):
        so = self.get_so_by_address(address)

        # Addresses in DWARF are relative to base address for PIC, so
        # make the address argument relative too if needed
        if so.is_pic:
            address -= so.low_addr

        for compile_unit in so.dwarf_info.iter_CUs():
            line_program = so.dwarf_info.line_program_for_CU(compile_unit)
            prev_state = None

            for entry in line_program.get_entries():
                cur_state = entry.state
                if cur_state is None or cur_state.end_sequence:
                    continue

                if prev_state:
                    file_entry = line_program['file_entry']
                    filename = file_entry[prev_state.file - 1].name
                    filename = bytes2str(filename)
                    line = prev_state.line
                    low_pc = prev_state.address
                    high_pc = cur_state.address

                    if low_pc > high_pc:
                        low_pc, high_pc = high_pc, low_pc

                    if low_pc <= address <= high_pc:
                        self._source_locations[address] = SourceLocation(
                            filename, line)
                        return self._source_locations[address]

                prev_state = cur_state

        return SourceLocation(None, None)

    def get_so_by_address(self, address):
        for so in self._shared_objects.values():
            if so.low_addr <= address <= so.high_addr:
                return so

        return None

    def get_function_name(self, address):
        if address in self._function_names:
            return self._function_names[address]
        else:
            return self._lookup_function_name(address)

    def get_source_location(self, address):
        if address in self._source_locations:
            return self._source_locations[address]
        else:
            return self._lookup_source_location(address)

    def _handle_baddr_event(self, event):
        # Size will be 0 for VDSO
        if event['size'] == 0:
            return

        path = event['sopath']
        baddr = event['baddr']
        self._shared_objects[baddr] = SharedObjectInfo(path, baddr)

    def _print_debug_info(self, event):
        address = event['ip']
        func_name = self.get_function_name(address)
        source_location = self.get_source_location(address)

        if func_name is not None:
            print(func_name)
        if source_location.filename is not None:
            print(source_location)

    def run(self):
        for event in self._traces.events:
            if event.name in ['lttng_ust_statedump:soinfo', 'lttng_ust_dl:dlopen']:
                self._handle_baddr_event(event)
            elif event.name.startswith('lttng_ust'):
                # TODO handle dlclose and state dump start/end
                continue
            else:
                self._print_debug_info(event)

        self._close_trace()


class SharedObjectInfo():
    def __init__(self, path, baddr):
        self.path = path
        self._set_elf_file()

        self.low_addr = baddr
        self.high_addr = baddr + self._get_mem_size()

        # Check whether the ELF file is position independent code
        self.is_pic = self.elf_file.header['e_type'] == 'ET_DYN'

        # Don't set the so info's dwarf_info initially, only when
        # symbol lookup is first required
        self._dwarf_info = None

    @property
    def dwarf_info(self):
        if self._dwarf_info is None:
            self._set_dwarf_info()

        return self._dwarf_info

    def _set_elf_file(self):
        try:
            binary_file = open(self.path, 'rb')
            self.elf_file = ELFFile(binary_file)
        except IOError:
            print('Failed to open ' + self.path, file=sys.stderr)
            sys.exit(-1)

    def _set_dwarf_info(self):
        if not self.elf_file.has_dwarf_info():
            print('Binary ' + self.path + ' has no DWARF info',
                  file=sys.stderr)
            sys.exit(-1)

        self._dwarf_info = self.elf_file.get_dwarf_info()

    def _get_mem_size(self):
        mem_size = 0
        for segment in self.elf_file.iter_segments():
            if segment['p_type'] == 'PT_LOAD':
                alignment = segment['p_align']
                segment_size = segment['p_memsz']
                aligned_size = math.ceil(segment_size / alignment) * alignment
                mem_size += aligned_size

        return mem_size


if __name__ == '__main__':
    arg_parser = argparse.ArgumentParser(description=_DESC)

    arg_parser.add_argument('trace_path', metavar='<path/to/trace>',
                            help='trace path')
    arg_parser.add_argument('-V', '--version', action='version',
                            version='pydebuginfo v' + _VERSION)

    args = arg_parser.parse_args()

    debug_info_analysis = DebugInfoAnalysis(args)
    debug_info_analysis.run()
