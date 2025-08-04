Building Your First Windows Malware Loader
-------------------------------------------

> OVERVIEW

Learn the basics of building a Windows loader, with a focus on process injection.

From memory allocation to remote process injection, this is an intro to maldev,  
built to get you started and self-sufficient.


> DIRECTORY STRUCTURE

src/
  memory/      - memory allocation example
  v0/          - simple process injection
  v1/          - refinement
  v2/          - native apc syscall injection

additions/
  commands.txt     - one-liners & workshop commands
  filebloat.ps1    - file bloating script in PowerShell
  resources.txt    - additional resources


> REQUIREMENTS

Core:
  - Visual Studio 2022
  - Windows 11 VM

Optional:
  - PE-bear         https://github.com/hasherezade/pe-bear
  - x64dbg          https://x64dbg.com/
  - System Informer https://github.com/winsiderss/systeminformer


> LEGAL DISCLAIMER

This project is licensed under the MIT License.

You're free to use, modify, and distribute this code as you like.
That said, this is for educational and research purposes only.

Use responsibly.  
Author takes no liability for misuse, damage, or unintended consequences.
You break it, you buy it.
