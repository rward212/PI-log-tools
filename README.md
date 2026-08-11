# PI Log Tools — Notepad++ Plugin

A native **C++** Notepad++ plugin for analysing PI Message Logs:

1. **Find time ranges when an interface was in Primary state**
2. **Separate log messages for separate interface instances**

It runs on the **currently open document** in Notepad++ and writes its results
into **new documents**.

## Features / Usage

From the **Plugins ▸ PI Log Tools** menu:

| Command | Behaviour |
|---------|-----------|
| **Find primary time ranges...** | Prompts for a *point source* and *interface ID*, scans the current document, and opens a new tab named `PS_<id>_primary_periods` with the primary-state time ranges. |
| **Separate log messages by interface instance** | Scans the current document and opens one new tab per interface instance (named `PS_<id>.txt`), each containing that instance's messages plus any global messages, sorted by timestamp. |

The parsing logic is a faithful port of the Python original, verified to produce
identical output on the same input.

To use it, open a PI Message log in Notepad++ and pick a command from the menu.

## Layout

```
├── include/          Notepad++ / Scintilla plugin API headers (from the NPP repo)
├── src/
│   ├── PILogTools.cpp   plugin entry point, menu, dialog, document I/O
│   ├── LogParser.h/.cpp ported parsing logic (features 1 & 2)
│   ├── dialog.rc        resource script for the point-source dialog
│   ├── resource.h       dialog resource IDs
│   ├── build.bat        build script (add "install" argument to deploy)
│   ├── test_main.cpp    small console harness used to validate the parser
│   └── sample.log       sample PI log used for validation
└── README.md
```

## Building

Requires a MinGW-w64 / GCC toolchain. [w64devkit](https://github.com/skeeto/w64devkit)
is a convenient standalone option (no admin rights or installer needed) — just
extract it and point `src/build.bat` at its `bin` folder.

At the top of `src/build.bat`, set the `KIT` variable to your toolchain's `bin`
directory (or add it to your `PATH`), then run:

```
src\build.bat            # build PILogTools.dll only
src\build.bat install    # build and install into Notepad++
```

The build produces a **self-contained** DLL (C++ runtime statically linked), so
no extra DLLs are needed.

## Installing / Reinstalling

The plugin is installed to:

```
C:\Program Files\Notepad++\plugins\PILogTools\PILogTools.dll
```

Because that is under `Program Files`, the copy needs administrator rights
(UAC). You can either run `build.bat install` from an elevated prompt, or copy
`PILogTools.dll` into the `plugins\PILogTools\` folder yourself.

After installing, restart Notepad++ (close it completely and reopen). The plugin
appears under **Plugins ▸ PI Log Tools**.

## Validating

`test_main.cpp` runs both features on `sample.log`. Rebuild/run it the same way
the plugin's logic was confirmed to match the original `pi_log_tools.py`.
