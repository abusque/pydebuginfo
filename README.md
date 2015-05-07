# pydebuginfo
Python prototype to map trace events to code via debug info

## Requirements
You will need babeltrace with python bindings installed, as well as
the following python packages:

* [pyelftools](https://github.com/eliben/pyelftools)

The processed trace needs to be of userspace domain, with instruction
pointer context enabled. This context can be enabled with the
following command prior to the start of the trace:

    $ lttng add-context -u -t ip

The trace binary also has to be compiled in debug mode if you want to
have source file/function information, extracted from the DWARF info.

## Usage
Once your trace has been recorded, you can perform the analysis as follows:

    $ ./debuginfo /path/to/trace
