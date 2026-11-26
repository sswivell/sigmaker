# sigmaker

byte signature generator. c++. by swivel (@emptyworth on discord)

given a symbol name or address, emits a masked byte pattern
(with ?? for relocatable bytes) that you can paste into
cheat engine, ida, ghidra, x64dbg.

build:
    make

use:
    ./sigmaker <binary> --name <symbol> [opts]
    ./sigmaker <binary> --addr 0x<addr> [opts]

opts:
    --len N        initial signature length (default 32)
    --wild-zero    wildcard 0x00 bytes
    --ctx N        context bytes prepended (default 0)
    --json         JSON output
    --credits      credits
    --help         help

credits:
    swivel (@emptyworth on discord). say hi.
