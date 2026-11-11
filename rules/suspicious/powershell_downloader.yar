rule PowerShell_Download_Cradle
{
    meta:
        description = "PowerShell code that downloads and executes remote content."
        severity = "high"
        author = "maltriage"
    strings:
        $download1 = "DownloadString" ascii wide nocase
        $download2 = "DownloadFile" ascii wide nocase
        $download3 = "Invoke-WebRequest" ascii nocase
        $download4 = "Start-BitsTransfer" ascii nocase
        $exec1 = "Invoke-Expression" ascii wide nocase
        $exec2 = "IEX " ascii wide nocase
        $enc = "-EncodedCommand" ascii wide nocase
        $b64 = "FromBase64String" ascii wide nocase
        $bypass = "ExecutionPolicy Bypass" ascii wide nocase
    condition:
        (1 of ($download*)) and (1 of ($exec1, $exec2, $enc, $b64, $bypass))
}

rule Base64_Encoded_PowerShell
{
    meta:
        description = "Encoded PowerShell command line, typical of droppers and loaders."
        severity = "medium"
        author = "maltriage"
    strings:
        $a = /powershell(\.exe)?\s+.*-e(nc|ncodedcommand)?\s+[A-Za-z0-9+\/]{40,}/ ascii wide nocase
    condition:
        $a
}
