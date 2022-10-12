#!/bin/sh

# For RDP to lab machine
# xfreerdp +clipboard /size:1920x1080 /bpp:16 /network:modem /compression /audio-mode:1 /auto-reconnect /drive:share,./ -fonts -wallpaper -themes /u:offsec /p:lab /v:192.168.66.10

myip=$1

if [ -z $myip ]; 
then 
    echo "You should set your ip first"
    exit 1
fi

wget https://github.com/0vercl0k/rp/releases/download/v1/rp-win-x86.exe -O rp-win-x86.exe
wget https://github.com/sebastian93921/OSED-Code-Snippets/raw/main/generate-shellcode-32.py -O generate-shellcode-32.py
wget https://github.com/sebastian93921/OSED-Code-Snippets/raw/main/generate-egghunter-32.py -O generate-egghunter-32.py
wget https://github.com/sebastian93921/OSED-Code-Snippets/raw/main/find-ppr-32.py -O find-ppr-32.py
wget https://github.com/sebastian93921/OSED-Code-Snippets/raw/main/windbg-dark-green-x64.wew -O windbg.wew 
wget https://download.sysinternals.com/files/SysinternalsSuite.zip -O SysinternalsSuite.zip
wget https://github.com/sebastian93921/OSED-Code-Snippets/raw/main/filter-ropfile.py -O filter-ropfile.py

printf "bitsadmin /Transfer myJob1 http://$myip:8080/windbg.wew"' C:\\windows\\temp\\windbg.wew' > start-win-debugenv.bat
printf '\n' >> start-win-debugenv.bat # Newline
printf "bitsadmin /Transfer myJob2 http://$myip:8080/find-ppr-32.py"' C:\\windows\\temp\\find-ppr-32.py' >> start-win-debugenv.bat
printf '\n' >> start-win-debugenv.bat # Newline
printf "bitsadmin /Transfer myJob3 http://$myip:8080/rp-win-x86.exe"' C:\\windows\\temp\\rp-win-x86.exe' >> start-win-debugenv.bat
printf '\n' >> start-win-debugenv.bat # Newline

# Add shortcut
printf 'echo "C:\Program Files\Windows Kits\\10\Debuggers\x86\windbg.exe" -WF C:\\windows\\temp\\windbg.wew > WinDbg.bat' >> start-win-debugenv.bat
printf '\n' >> start-win-debugenv.bat # Newline
printf 'echo "C:\Program Files (x86)\Windows Kits\\10\Debuggers\x86\windbg.exe" -WF C:\\windows\\temp\\windbg.wew > WinDbgx86.bat' >> start-win-debugenv.bat
printf '\n' >> start-win-debugenv.bat # Newline
printf 'echo @cmd /k "echo Navigate to temp folder.. && cd C:\\windows\\temp" > Cmd-Nav-Temp.bat' >> start-win-debugenv.bat
printf '\n' >> start-win-debugenv.bat # Newline
# Please execute `start-win-debugenv.bat` manually 

echo "Start httpd from Busybox..."
busybox httpd -f -vv -p 8080
