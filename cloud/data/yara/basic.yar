/*
 * Copyright (c) 2026, redmoon200
 * All rights reserved.
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Small set of signatures written for os-layer7security. They look for
 * well-known, high-signal patterns (test files, droppers, web shells, miners,
 * credential tools). They do not replace a full antivirus product.
 */

rule L7_EICAR_Test_File
{
    meta:
        description = "EICAR antivirus test file"
        severity = "test"
    strings:
        $e = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    condition:
        $e at 0 or ($e and filesize < 1024)
}

rule L7_PowerShell_Download_Cradle
{
    meta:
        description = "PowerShell that downloads and runs code from the internet"
        severity = "high"
    strings:
        $a1 = "Net.WebClient" nocase
        $a2 = "DownloadString" nocase
        $a3 = "DownloadFile" nocase
        $a4 = "Invoke-WebRequest" nocase
        $a5 = "Start-BitsTransfer" nocase
        $b1 = "IEX" nocase
        $b2 = "Invoke-Expression" nocase
        $b3 = "-EncodedCommand" nocase
        $b4 = "FromBase64String" nocase
        $h  = "-WindowStyle Hidden" nocase
        $n  = "-nop" nocase
    condition:
        filesize < 2MB and (1 of ($a*)) and (1 of ($b*)) and ($h or $n or $b3)
}

rule L7_PHP_Webshell_Generic
{
    meta:
        description = "PHP web shell: evaluates input from the request"
        severity = "high"
    strings:
        $php = "<?php"
        $e1 = /eval\s*\(\s*(base64_decode|gzinflate|str_rot13|gzuncompress)\s*\(/ nocase
        $e2 = /(eval|assert|system|passthru|shell_exec)\s*\(\s*\$_(POST|GET|REQUEST|COOKIE)\s*\[/ nocase
        $e3 = /preg_replace\s*\(\s*["']\/.*\/e["']/ nocase
    condition:
        $php and filesize < 500KB and any of ($e*)
}

rule L7_Bash_Reverse_Shell
{
    meta:
        description = "Reverse shell one-liner"
        severity = "high"
    strings:
        $a = "bash -i >& /dev/tcp/"
        $b = /\/bin\/(ba)?sh\s+-i\s+<&\d\s+>&\d/
        $c = "nc -e /bin/sh" nocase
        $d = "mkfifo /tmp/" nocase
        $e = /python\d?\s+-c\s+["']import socket,subprocess,os/
    condition:
        filesize < 1MB and any of them
}

rule L7_Mimikatz_Strings
{
    meta:
        description = "Mimikatz credential theft tool"
        severity = "critical"
    strings:
        $a = "sekurlsa::logonpasswords" nocase
        $b = "gentilkiwi" nocase
        $c = "mimikatz" nocase
        $d = "lsadump::sam" nocase
        $e = "kerberos::golden" nocase
    condition:
        filesize < 20MB and 2 of them
}

rule L7_Cryptominer_Stratum
{
    meta:
        description = "Cryptocurrency miner (Stratum pool address with a miner name)"
        severity = "medium"
    strings:
        $s1 = "stratum+tcp://" nocase
        $s2 = "stratum+ssl://" nocase
        $m1 = "xmrig" nocase
        $m2 = "cryptonight" nocase
        $m3 = "randomx" nocase
        $m4 = "minerd" nocase
    condition:
        filesize < 30MB and 1 of ($s*) and 1 of ($m*)
}

rule L7_Ransom_Note_Text
{
    meta:
        description = "Text typical for ransomware notes"
        severity = "high"
    strings:
        $a = "your files have been encrypted" nocase
        $b = "all your files are encrypted" nocase
        $c = "to decrypt your files" nocase
        $d = "send bitcoin" nocase
        $e = "private key" nocase
        $f = "do not try to recover" nocase
    condition:
        filesize < 200KB and 2 of ($a, $b, $c, $d, $f) and $e
}

rule L7_Office_Macro_Auto_Execute
{
    meta:
        description = "Legacy Office document with an auto-run macro that starts programs"
        severity = "medium"
    strings:
        $auto1 = "AutoOpen" nocase
        $auto2 = "Document_Open" nocase
        $auto3 = "Workbook_Open" nocase
        $auto4 = "Auto_Open" nocase
        $run1 = "WScript.Shell" nocase
        $run2 = "Shell(" nocase
        $run3 = "powershell" nocase
        $run4 = "CreateObject" nocase
        $run5 = "URLDownloadToFile" nocase
    condition:
        uint32be(0) == 0xD0CF11E0 and 1 of ($auto*) and 2 of ($run*)
}

rule L7_VBScript_Downloader
{
    meta:
        description = "VBScript or JScript that downloads a file and runs it"
        severity = "high"
    strings:
        $x1 = "MSXML2.XMLHTTP" nocase
        $x2 = "WinHttp.WinHttpRequest" nocase
        $x3 = "Microsoft.XMLHTTP" nocase
        $s1 = "ADODB.Stream" nocase
        $r1 = "WScript.Shell" nocase
        $r2 = ".Run" nocase
        $r3 = "Shell.Application" nocase
    condition:
        filesize < 1MB and 1 of ($x*) and $s1 and 1 of ($r*)
}

rule L7_Linux_Botnet_Dropper_Script
{
    meta:
        description = "Shell script that fetches and starts architecture specific binaries (Mirai-style loader)"
        severity = "high"
    strings:
        $a = "wget http" nocase
        $b = "tftp -g" nocase
        $c = "chmod 777" nocase
        $d = /\.(mips|mpsl|arm[0-9]?|x86|sh4|ppc|m68k|spc)\b/
    condition:
        filesize < 100KB and ($a or $b) and $c and #d >= 3
}

rule L7_Metasploit_Meterpreter
{
    meta:
        description = "Meterpreter or reflective loader strings"
        severity = "critical"
    strings:
        $a = "metsrv" nocase
        $b = "ReflectiveLoader"
        $c = "meterpreter" nocase
        $d = "stdapi_" nocase
    condition:
        filesize < 10MB and 2 of them
}

rule L7_Suspicious_HTML_Smuggling
{
    meta:
        description = "HTML page that builds a file from an embedded blob and saves it (HTML smuggling)"
        severity = "medium"
    strings:
        $h = "<html" nocase
        $a = "new Blob(" nocase
        $b = "createObjectURL" nocase
        $c = "msSaveOrOpenBlob" nocase
        $d = "atob(" nocase
        $e = ".download =" nocase
    condition:
        $h and filesize < 5MB and $a and ($b or $c) and $d and $e
}
