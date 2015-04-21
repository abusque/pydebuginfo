#!/usr/bin/env python3

import argparse
import sys
from babeltrace import TraceCollection
from elftools.elf.elffile import ELFFile
from elftools.common.py3compat import bytes2str

_DESC = 'Map events from userspace trace to symbols'
_VERSION = '0.1.0'

class DebugInfoAnalysis():
    def __init__(self, args):
        # dict of adress ranges for functions, indexed by name. The
        # range is given as a tuple (low_pc, high_pc)
        self.function_ranges = {}
        self._open_trace(args.trace_path)
        self._open_binary(args.binary_path)
        self._generate_function_mapping()

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

    def _generate_function_mapping(self):
        for compile_unit in self._dwarf_info.iter_CUs():
            for die in compile_unit.iter_DIEs():
                try:
                    if die.tag == 'DW_TAG_subprogram':
                        func_name = bytes2str(die.attributes['DW_AT_name'].value)
                        low_pc = die.attributes['DW_AT_low_pc'].value
                        high_pc_attr = die.attributes['DW_AT_high_pc']
                        if high_pc_attr.form == 'DW_FORM_addr':
                            high_pc = high_pc_attr.value
                        else:
                            # high_pc relative to lowpc
                            high_pc = low_pc + high_pc_attr.value

                        self.function_ranges[func_name] = (low_pc, high_pc)
                except KeyError:
                    continue

    def run(self):
        for func in self.function_ranges:
            print(func, self.function_ranges[func])

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
