#!/bin/sh

# For RDP to lab machine
# xfreerdp +clipboard /size:1920x1080 /bpp:16 /network:modem /compression /audio-mode:1 /auto-reconnect /drive:share,./ -fonts -wallpaper -themes /u:offsec /p:lab /v:192.168.66.10

myip=$1

if [ -z $myip ]; 
then 
    echo "You should set your ip first"
    exit 1
fi

wget https://github.com/sebastian93921/OSED-Code-Snippets/raw/main/rp-win-x86.exe -O rp-win-x86.exe
wget https://github.com/sebastian93921/OSED-Code-Snippets/raw/main/generate-shellcode-32.py -O generate-shellcode-32.py
wget https://github.com/sebastian93921/OSED-Code-Snippets/blob/main/generate-egghunter-32.py -O generate-egghunter-32.py
wget https://github.com/sebastian93921/OSED-Code-Snippets/raw/main/find-ppr-32.py -O find-ppr-32.py
wget https://github.com/sebastian93921/OSED-Code-Snippets/raw/main/windbg-dark-green-x64.wew -O windbg.wew 
wget https://github.com/corelan/windbglib/raw/master/pykd/pykd.zip -O pykd.zip


printf "bitsadmin /Transfer myJob http://$myip:8080/windbg.wew"' C:\\windows\\temp\\windbg.wew \n' > start-win-debugenv.bat
printf "bitsadmin /Transfer myJob http://$myip:8080/find-ppr-32.py"' C:\\windows\\temp\\find-ppr-32.py \n' >> start-win-debugenv.bat
printf "bitsadmin /Transfer myJob http://$myip:8080/rp-win-x86.exe"' .\rp-win-x86.exe \n' >> start-win-debugenv.bat
printf 'echo "C:\Program Files\Windows Kits\\10\Debuggers\x86\windbg.exe" -WF C:\\windows\\temp\\windbg.wew > WinDbg.bat' >> start-win-debugenv.bat
# Please execute `start-win-debugenv.bat` manually 

busybox httpd -f -vv -p 8080
