# Tools/scripts for Reverse Engineering & Binary Exploitation
Tools/scripts For OSED / Reverse engineering / Binary exploitation

Most of the Scripts based on https://github.com/epi052/osed-scripts .
Thanks to epi052

# Scripts Content
|File Name|Description|
|---|---|
| osed-start-env.sh | This is the preparation script before any lab starts |
| generate-egghunter-32.py | The script used to generate egghunter script for Win 10, --seh for SEH-based egghunter, -b for bad characters check |
| generate-shellcode-32.py | The script used to generate shellcode for Win 10, -bp for adding breakpoint, -b for bad characters check, -l for attacker ip, -p for attacker port |
| windbg-dark-green-x64.wew | WinDbg Theme original from https://github.com/0xbad53c/osed-tools/blob/main/dark-green-x64.wew |
| find-ppr-32.py | Find pop; pop; ret instruction. Original from https://github.com/epi052/osed-scripts/blob/main/find-ppr.py |
| filter-ropfile.py | It used to filter out rops instruction from rop file with bug fixing. Original from https://github.com/epi052/osed-scripts/blob/main/find-ppr.py |

# Usage
## filter-ropfile.py
```
# With bad chars
python filter-ropfile.py rop.txt --aslr 1 --image-base 10100000 --bad-bytes "\x00"

# --aslr 1 = Remove the first digit of the rop address
# --image-base = Default base image address of this dll, you can check it manually 
```
