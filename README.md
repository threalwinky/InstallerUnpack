# InstallerUnpack

A Python CLI for offline extraction of supported **InstallAnywhere Unix** and **InstallShield** installers, including nested archives and Java libraries. Requires Python 3.9+. [MIT license](LICENSE).

## Installation

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install .
```

External dependencies:

- **7z** — ZIP and 7-Zip/SFX extraction.
- **unshield** — InstallShield CAB extraction.
- **Pack200 decoder** — `unpack200` from JDK 8–13, or JDK 11+ with the optional Glavo library:

```sh
installerunpack setup-pack200
```

The setup command downloads and verifies the decoder once. Extraction runs offline and never executes installers or application code.

## Usage

```sh
installerunpack inspect setup.exe
installerunpack unpack setup.exe -o output/windows
installerunpack unpack installer.bin -o output/linux
installerunpack unpack data1.cab -o output/cab
```

Output must be a new directory. Keep related CAB volumes and headers alongside the input. From a source checkout, use `python3 src/main.py` instead of `installerunpack`.

Useful options:

- `--no-recursive` — extract only the installer layer.
- `--archives-only` — carve embedded archives without expanding them.
- `--pack200-jar PATH` or `--unpack200 PATH` — select a Pack200 decoder.
- `--max-depth N` / `--max-archives N` — adjust recursion limits (defaults: 16 / 10000).

## Output

Recursive extraction is enabled by default for JAR/ZIP/WAR/EAR, Pack200, TAR, gzip, and 7-Zip/SFX archives. Original files are preserved; archive contents appear in sibling `.contents` directories. Pack200 files are restored to JARs before expansion. Java classes remain compiled bytecode.

`extraction-report.json` lists extracted archives, duplicate references, empty placeholders, and failures. Incomplete extraction returns a nonzero exit code; partial output is retained.

## Limitations

Supported installer layers are InstallAnywhere Unix shell, InstallShield ANSI/UTF-16 EXE tables, and InstallShield CAB/HDR. InstallAnywhere Windows, ISSetupStream, encrypted or unknown InstallShield layouts, MSI, and Inno Setup are currently unsupported.
