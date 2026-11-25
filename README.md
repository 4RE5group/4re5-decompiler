# 4re5 decompiler

A simple executable decompiler.

## Desktop GUI

Build the self-contained GTK 3 desktop application with:

```sh
make
```

Launch the graphical interface with:

```sh
./4re5-decompiler
```

You can also pass a binary path to open it on startup. The GUI lists ELF sections
with addresses, sizes, file offsets, and flags. Selecting a section shows its
raw bytes and disassembly. The Strings, Symbols, and Functions tabs expose
printable strings, ELF symbol records, and executable-section function
candidates. Edit menu
actions search strings and wildcard byte patterns across the file and navigate
to ELF virtual addresses. The disassembly view shows instruction addresses and
colors register widths separately. Both ELF32 and ELF64 x86 binaries are parsed
and decoded by the project's native ELF and x86 code; no external disassembler
is required. GTK 3 development files and `pkg-config` are required to build the
GUI. The resulting executable contains the GUI, ELF reader, and x86 decoder;
no second helper executable or external disassembler is needed.

The GUI defaults to a pastel dark Gruvbox palette and the View menu switches to
the matching light palette. Text uses Lilex when installed, then falls back to
a monospace system font. Toolbar actions use symbolic folder and save icons
from the desktop icon theme.

The assembly view highlights hexadecimal constants in green, resolves
addresses that point into printable ELF data as inline string annotations, and
shows ELF header fields in the same highlighted metadata style above the
disassembly. The native decoder handles common 32-bit and 64-bit prefixes,
REX-extended registers, grouped operations, branches, calls, `lea`, `push`,
`endbr`, and syscall instructions; unsupported encodings remain explicit data
records until their opcode metadata is added.

## Handled Executable Formats
- ELF32 and ELF64 x86/x86-64

## Source layout

- `gui/app.c`: GTK actions, binary loading, and application wiring
- `gui/gui.h`: shared GUI state and section model declarations
- `gui/model.c`: section model lifetime helpers
- `types/type_detector.c`: native ELF32/ELF64 reader
- `arch/x86/x86.c`: native x86 instruction decoder

`main.c` is retained as a small command-line reference entry point, but it is
not part of the default build. `make` creates only `4re5-decompiler`.
