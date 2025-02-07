@echo off
cls
title AV-Lookup by DebtlessFlea
echo Scanning for Antivirus Programs...
echo.

set "defenderFound="
set "nortonFound="
set "mcafeeFound="
set "kasperskyFound="
set "avastFound="
set "avgFound="
set "bitdefenderFound="
set "sophosFound="
set "trendMicroFound="
set "eSetFound="
set "windowsDefenderFound="
set "webrootFound="
set "comodoFound="
set "aviraFound="
set "fSecureFound="
set "pandaFound="
set "malwarebytesFound="
set "totalDefenseFound="
set "fortinetFound="
set "zonealarmFound="

reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender" >nul 2>&1 && set defenderFound=1

if exist "C:\Program Files\Norton" set nortonFound=1
if exist "C:\Program Files (x86)\Norton" set nortonFound=1

if exist "C:\Program Files\McAfee" set mcafeeFound=1
if exist "C:\Program Files (x86)\McAfee" set mcafeeFound=1

if exist "C:\Program Files\Kaspersky Lab" set kasperskyFound=1
if exist "C:\Program Files (x86)\Kaspersky Lab" set kasperskyFound=1

if exist "C:\Program Files\Avast Software" set avastFound=1
if exist "C:\Program Files (x86)\Avast Software" set avastFound=1

if exist "C:\Program Files\AVG" set avgFound=1
if exist "C:\Program Files (x86)\AVG" set avgFound=1

if exist "C:\Program Files\Bitdefender" set bitdefenderFound=1
if exist "C:\Program Files (x86)\Bitdefender" set bitdefenderFound=1

if exist "C:\Program Files\Sophos" set sophosFound=1
if exist "C:\Program Files (x86)\Sophos" set sophosFound=1

if exist "C:\Program Files\Trend Micro" set trendMicroFound=1
if exist "C:\Program Files (x86)\Trend Micro" set trendMicroFound=1

if exist "C:\Program Files\ESET" set eSetFound=1
if exist "C:\Program Files (x86)\ESET" set eSetFound=1

if exist "C:\Program Files\Webroot" set webrootFound=1
if exist "C:\Program Files (x86)\Webroot" set webrootFound=1

if exist "C:\Program Files\COMODO" set comodoFound=1
if exist "C:\Program Files (x86)\COMODO" set comodoFound=1

if exist "C:\Program Files\Avira" set aviraFound=1
if exist "C:\Program Files (x86)\Avira" set aviraFound=1

if exist "C:\Program Files\F-Secure" set fSecureFound=1
if exist "C:\Program Files (x86)\F-Secure" set fSecureFound=1

if exist "C:\Program Files\Panda Security" set pandaFound=1
if exist "C:\Program Files (x86)\Panda Security" set pandaFound=1

if exist "C:\Program Files\Malwarebytes" set malwarebytesFound=1
if exist "C:\Program Files (x86)\Malwarebytes" set malwarebytesFound=1

if exist "C:\Program Files\Total Defense" set totalDefenseFound=1
if exist "C:\Program Files (x86)\Total Defense" set totalDefenseFound=1

if exist "C:\Program Files\Fortinet" set fortinetFound=1
if exist "C:\Program Files (x86)\Fortinet" set fortinetFound=1

if exist "C:\Program Files\ZoneAlarm" set zonealarmFound=1
if exist "C:\Program Files (x86)\ZoneAlarm" set zonealarmFound=1

echo Antivirus programs found:
echo.

if defined defenderFound echo  - Windows Defender
if defined nortonFound echo  - Norton Antivirus
if defined mcafeeFound echo  - McAfee Antivirus
if defined kasperskyFound echo  - Kaspersky Antivirus
if defined avastFound echo  - Avast Antivirus
if defined avgFound echo  - AVG Antivirus
if defined bitdefenderFound echo  - Bitdefender Antivirus
if defined sophosFound echo  - Sophos Antivirus
if defined trendMicroFound echo  - Trend Micro Antivirus
if defined eSetFound echo  - ESET Antivirus
if defined webrootFound echo  - Webroot Antivirus
if defined comodoFound echo  - Comodo Antivirus
if defined aviraFound echo  - Avira Antivirus
if defined fSecureFound echo  - F-Secure Antivirus
if defined pandaFound echo  - Panda Antivirus
if defined malwarebytesFound echo  - Malwarebytes Antivirus
if defined totalDefenseFound echo  - Total Defense Antivirus
if defined fortinetFound echo  - Fortinet Antivirus
if defined zonealarmFound echo  - ZoneAlarm Antivirus

if not defined defenderFound if not defined nortonFound if not defined mcafeeFound if not defined kasperskyFound if not defined avastFound if not defined avgFound if not defined bitdefenderFound if not defined sophosFound if not defined trendMicroFound if not defined eSetFound if not defined webrootFound if not defined comodoFound if not defined aviraFound if not defined fSecureFound if not defined pandaFound if not defined malwarebytesFound if not defined totalDefenseFound if not defined fortinetFound if not defined zonealarmFound (
    echo No Antivirus programs found.
)

echo.
echo Scan complete.
pause
