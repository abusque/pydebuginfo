#!/usr/bin/env python3

import argparse
import sys
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
        self._open_binary(args.binary_path)
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

    def _open_binary(self, path):
        try:
            binary_file = open(path, 'rb')
            self._elf_file = ELFFile(binary_file)
        except IOError:
            print('Failed to open ' + path, file=sys.stderr)
            sys.exit(-1)

        if not self._elf_file.has_dwarf_info():
            print('Binary has no DWARF info', file=sys.stderr)
            sys.exit(-1)

        self._dwarf_info = self._elf_file.get_dwarf_info()

    def _close_trace(self):
        for handle in self._handles.values():
            self._traces.remove_trace(handle)

    def _lookup_function_name(self, address):
        for compile_unit in self._dwarf_info.iter_CUs():
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
                            # high_pc relative to lowpc
                            high_pc = low_pc + high_pc_attr.value

                        if low_pc <= address <= high_pc:
                            self._function_names[address] = func_name
                            return self._function_names[address]
                except KeyError:
                    continue

        return None

    def _lookup_source_location(self, address):
        for compile_unit in self._dwarf_info.iter_CUs():
            line_program = self._dwarf_info.line_program_for_CU(compile_unit)
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

    def run(self):
        for event in self._traces.events:
            address = event['ip']
            func_name = self.get_function_name(address)
            source_location = self.get_source_location(address)
            if func_name is not None:
                print(func_name)
            if source_location.filename is not None:
                print(source_location)

        self._close_trace()


if __name__ == '__main__':
    arg_parser = argparse.ArgumentParser(description=_DESC)

    arg_parser.add_argument('trace_path', metavar='<path/to/trace>',
                            help='trace path')
    arg_parser.add_argument('binary_path', metavar='<path/to/binary>',
                            help='binary path')
    arg_parser.add_argument('-V', '--version', action='version',
                            version='pydebuginfo v' + _VERSION)

    args = arg_parser.parse_args()

    debug_info_analysis = DebugInfoAnalysis(args)
    debug_info_analysis.run()
