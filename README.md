# Ghidra bFLT loader

Loader module for Ghidra to import bFLT files.

bFLT files are commonly found in uclinux images, and are greatly documented here :

 * http://www.devttys0.com/2012/03/writing-a-bflt-loader-for-ida/
 * https://blog.tangrs.id.au/2012/04/07/bflt-format-implementation-notes/

## Features

 * Parses and loads sections according to the file header
 * Extracts GZip data section if GZDATA flag is set
 * Patches GOT entries if GOTPIC flag is set, and sets pointers for further analysis

## Installation

Copy the ZIP file from the [Releases](https://github.com/Baldanos/ghidra-bflt-loader/releases) to the GHIDRA_INSTALL_DIR/Extensions/Ghidra directory and install the module from the File > Install extensions... menu on the main screen.

Based on the [MCLFLoader](https://github.com/NeatMonster/mclf-ghidra-loader) from [NeatMonster](https://github.com/NeatMonster)
