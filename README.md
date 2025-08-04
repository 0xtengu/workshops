# Building Your First Windows Malware Loader

---

> ### OVERVIEW
> Red Team Village workshop at DEF CON 33.
> Learn the basics of building a Windows loader, focusing on process injection.  

---

> ### DIRECTORY STRUCTURE  
```
src/
  memory/      - memory allocation example
  v0/          - simple process injection
  v1/          - refinement
  v2/          - native APC syscall injection
  xor/         - XOR encoding & obfuscation 

additions/
  commands.txt     - relevant commands
  filebloat.ps1    - file bloating PowerShell script
  resources.txt    - additional resources
```

---

> ### REQUIREMENTS  
> **Core:**  
> - Visual Studio 2022  
> - Windows 11 VM  

> **Optional:**  
> - [PE-bear](https://github.com/hasherezade/pe-bear)  
> - [x64dbg](https://x64dbg.com/)  
> - [System Informer](https://github.com/winsiderss/systeminformer)

---

> ### LEGAL DISCLAIMER  
> This project is licensed under the [MIT License](./LICENSE).  
> You’re free to use, modify, and distribute this code as you like.  
> That said, this is for educational and research purposes only.  
> Use responsibly.  
> The author takes no liability for misuse, damage, or unintended consequences.
