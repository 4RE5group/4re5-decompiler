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
