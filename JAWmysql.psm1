function Invoke-MySqlCommand {
    [CmdletBinding(DefaultParameterSetName="Command")]    
    param (
    [parameter(Mandatory=$true, ParameterSetName="Command", ValueFromPipeline=$True, Position = 0)] 
    [String]$Command,
    [parameter(Mandatory=$False, ParameterSetName="Command")]
    [string]$ServerUser, 
    [parameter(Mandatory=$False, ParameterSetName="Command")]
    [string]$ServerPassword, 
    [parameter(Mandatory=$False, ParameterSetName="Command")]
    [string]$ServerHost, 
    [parameter(Mandatory=$False, ParameterSetName="Command")]
    [string]$ServerPort, 
    [switch]$Xml,
    [switch]$TableOutput,
    [switch]$AsObject,
    [switch]$GenerateSql,
    [switch]$GenerateCommand,
    [parameter(Mandatory=$true, ParameterSetName="InvocationObject")]
    [Hashtable]$InvocationObject
    )
if ($Command) {
    "Converting command to Invocation Object" | Write-Debug
    $InvocationObject = @{
        ServerUser = $ServerUser
        ServerPassword = $ServerPassword 
        ServerHost = $ServerHostname
        ServerPort = $ServerPort
        Xml = $Xml
        Table = $TableOutput
        AsObject = $AsObject
        Command = $Command
        }
    } #end if command
 

if ($InvocationObject) {
    [string]$Options = ''
    "Processing invocation object parisng" | Write-Debug

    if ($InvocationObject['AsObject']) {
        "AsObject is requested, make sure xml output is enabled" | Write-Debug
        $InvocationObject['Xml'] = $true
        }

    switch ($InvocationObject.Keys | ? {$InvocationObject[$_]} ) {
            'Command' {
                "Performing unnecessary command normalization" | Write-Debug
                $InvocationObject[$_] = $InvocationObject[$_] -replace '(^[ ]*"[ ]*)(.+)([ ]*"+[ ]*$)','$2' -replace '[ ]*;*[ ]*$'
                if ($InvocationObject[$_] -notmatch ';[ ]*$') {
                    "Adding trailing semicolon" | Write-Debug 
                    $InvocationObject[$_] = $InvocationObject[$_] -replace '(.+)([ ]*$)','$1;'
                    }
                if ($InvocationObject[$_] -notmatch '^[ ]*".+"[ ]*$') {
                    "Escaping with quotation marks" | Write-Debug
                    $InvocationObject[$_] = '"' + $InvocationObject[$_] + '"'
                    }
                }
            'ServerUser' {
                $Options += ' --user=' + $InvocationObject[$_]                
                }
            'ServerPassword' {
                $Options += ' --password=' + $InvocationObject[$_]
                }
            'ServerHost' {
                $Options += ' --host=' + $InvocationObject[$_]
                }
            'ServerPort' {
                $Options += ' --port=' + $InvocationObject[$_]
                }
            'Xml' {
                $Options += ' --xml'
                }
            'Table' {#xml output overrides table internally in mysql, so don't bother with parameter validation
                $Options += ' --table'
                }
        } #end switch

    [string]$InvokeString = $Options + ' -e ' + $($InvocationObject['Command'])
    
    if ($InvocationObject.GenerateSql) {
        $InvocationObject['Command']
        }
    elseif ($InvocationObject.GenerateCommand) {
        $InvokeString
        }
    else {
        "Invoking mysql " + $InvokeString | Write-Verbose
        $InvokeResult = Invoke-Expression -Command "mysql $InvokeString 2>&1" 

        "Checking LASTEXITCODE" | Write-Debug
        if ($LASTEXITCODE -ne 0) {
            'Something awful happened, examine stderr output, LASTEXITCODE was ' + $LASTEXITCODE | Write-Verbose

            $RegexError = 'ERROR\s(\d+)\s\((.{5})\).+\:\s(.+)'
            if ($InvokeResult -match $RegexError) {
                Write-Error -Message $InvokeResult -ErrorId $Matches[1] 
                } 
                else {
                Write-Error -Message $InvokeResult 
                }
            } 
            else {
                if ($InvocationObject['AsObject']) {
                    "Invocation was requested to output as object, calling parser" | Write-Debug
                    $InvokeResult | Parse-MySqlXmlOutput
                    }
                    else {
                    $InvokeResult
                    }
            }
        }#end if elseif else
    }#end invocation object

}#end Invoke-MySqlCommand



function Parse-MySqlXmlOutput {[cmdletbinding(DefaultParameterSetName="Object")]
    param (
    [parameter(Mandatory=$true, ParameterSetName="Object", ValueFromPipeline=$True, ValueFromRemainingArguments=$true)] 
    $InputObjectData
    )
    begin {
        "Parse-MySqlXmlOutput begin block" | Write-Debug
        $ShouldConvert = $true
        $String = ""
        }
    process {
        #$PSItem.Gettype().name | Write-Verbose
        if ($PSItem.GetType().Name -eq 'XmlDocument' ) {
            "Incoming object is XmlDocument type" | Write-Debug
            $InputXmlData = $PSItem
            $ShouldConvert = $false
            } else {
            #"Append string" | Write-Debug
            $String += $PSItem
            }
        }
    end {
        if ($ShouldConvert) {
            [xml]$InputXmlData = $String
            }
        
        foreach ($row in $InputXmlData.resultset.row) {
            "row in inputxmldata" | Write-Debug
            "filed count: " + @($row.field).Count | Write-Debug
            #$obj = New-Object PSCustomObject
            #$obj = "" | select Name, Value
            $obj = New-Object System.Object
            foreach ($field in @($row.field)) {
                "adding field with name " + $field.name + " and value " + $field.'#text' | Write-Debug
                #$obj.Name  = ([string]($field.name))
                #$obj.Value = ([string]($field.'#text'))
                Add-Member -InputObject $obj -MemberType NoteProperty -Name $field.name -Value $field.'#text'
                #Add-Member -InputObject $obj -NotePropertyName ([string]($field.name)) -NotePropertyValue ([string]($field.'#text'))
                }
            "returning obj" | Write-Debug
            $obj
            }
        
        }#End of end
} #end of Parse-MySqlXmlOutput
#end Parse-MySqlXmlOutput


<# TEMPLATE COMMON PARAMETER SET FOR specfic commandlets

function TemplateFunction {
$TemplateVariable
[string]$ServerUser, [string]$ServerPassword, [string]$ServerHost, [string]$ServerPort, [switch]$Xml, [switch]$TableOutput, [switch]$AsObject = $true,
[switch]$GenerateSql,
    [switch]$GenerateCommand
)
    $InvokeParam = @{
        ServerUser = $ServerUser
        ServerPassword = $ServerPassword 
        ServerHost = $ServerHostname
        ServerPort = $ServerPort
        Xml = $Xml
        Table = $TableOutput
        AsObject = $AsObject
        GenerateSql = $GenerateSql
        GenerateCommand = $GenerateCommand
    
        Command = 'SOMESQLCOMMAND ' + $TempalateVariable
        }
#>
function New-MySqlDatabase {[cmdletbinding()]
param (
[Parameter(Mandatory=$True)]
[alias('Name')]
[string]$Database,
[string]$ServerUser, [string]$ServerPassword, [string]$ServerHost, [string]$ServerPort, [switch]$Xml,
[switch]$GenerateSql,
    [switch]$GenerateCommand
)
    $InvokeParam = @{
        ServerUser = $ServerUser
        ServerPassword = $ServerPassword 
        ServerHost = $ServerHostname
        ServerPort = $ServerPort
        Xml = $Xml
        GenerateSql = $GenerateSql
        GenerateCommand = $GenerateCommand

        Command = 'CREATE DATABASE ' + $Database
        }
    Invoke-MySqlCommand -InvocationObject $InvokeParam
}

function New-MySqlUser {[cmdletbinding()]
    param (
        [Parameter(Mandatory=$True)][string]$Username, 
        [Parameter(Mandatory=$True)][string]$Password,
        [string]$Hostname = 'localhost',
        [string]$ServerUser, [string]$ServerPassword, [string]$ServerHost, [string]$ServerPort, [switch]$Xml,
[switch]$GenerateSql,
    [switch]$GenerateCommand
    )
    $InvokeParam = @{
        ServerUser = $ServerUser
        ServerPassword = $ServerPassword 
        ServerHost = $ServerHostname
        ServerPort = $ServerPort
        Xml = $Xml
        GenerateSql = $GenerateSql
        GenerateCommand = $GenerateCommand

        Command = "CREATE USER '" + $Username + "'@'" + $Hostname + "' IDENTIFIED BY '" + $Password + "'"
        }

Invoke-MySqlCommand -InvocationObject $InvokeParam
}

function Set-MySqlPrivilege {
<#
.SYNOPSIS
Set Privilege on MySQL database

.Example
Set-MySqlPrivilege -Database TestingDB2 -Username Vasya -Grant -Verbose
#>
[cmdletbinding()]
    param (
        [string[]]$Privilege = "ALL",
            [Parameter(Mandatory=$True)]
        [string]$Database,
            [Parameter(Mandatory=$false)]
        [string]$Table = '*',
            [Parameter(Mandatory=$True)]
        [string]$Username,
        [string]$Hostname = 'localhost',
        [switch]$Grant,
        [string]$ServerUser, [string]$ServerPassword, [string]$ServerHost, [string]$ServerPort, [switch]$Xml,
        [switch]$GenerateSql, [switch]$GenerateCommand
        )

    $InvokeParam = @{
        ServerUser = $ServerUser
        ServerPassword = $ServerPassword 
        ServerHost = $ServerHostname
        ServerPort = $ServerPort
        Xml = $Xml
        GenerateSql = $GenerateSql
        GenerateCommand = $GenerateCommand
        #command will be constructed further
        Command = ''
        }
    if ($Table -ne '*') {
        $Table = "``" + $Table + "``"
        }

    [int]$PrivCount = @($Privilege).Length
        if ($PrivCount -gt 1) {
            [string]$NewPrivString = ''
            for ($i = 0; $i -lt $PrivCount; $i++) {
                $NewPrivString += $Privilege[$i]
                if ($i -ne ($PrivCount - 1)) {
                    $NewPrivString += ', ' 
                    }
                }#end for
            $Privilege = $NewPrivString
            }#end if
    $InvokeParam['Command'] = "GRANT " + $Privilege + " on ``"+$Database+"``." + $Table + " TO '" +$Username+"'@'"+$Hostname+ "'" + $(if ($Grant) {" WITH GRANT OPTION"})
        
Invoke-MySqlCommand -InvocationObject $InvokeParam
}

function Get-MySqlUser {
[cmdletbinding()]
param(
[string]$ServerUser, [string]$ServerPassword, [string]$ServerHost, [string]$ServerPort, [switch]$Xml, [switch]$TableOutput, [switch]$AsObject = $true
)
    $InvokeParam = @{
        ServerUser = $ServerUser
        ServerPassword = $ServerPassword 
        ServerHost = $ServerHostname
        ServerPort = $ServerPort
        Xml = $Xml
        Table = $TableOutput
        AsObject = $AsObject
        GenerateSql = $GenerateSql
        GenerateCommand = $GenerateCommand

        Command = "SELECT User, Host, Password FROM mysql.user"
        }
        Invoke-MySqlCommand -InvocationObject $InvokeParam 
}

function Get-MySqlDatabase {[cmdletbinding()]
param(
[string]$ServerUser, [string]$ServerPassword, [string]$ServerHost, [string]$ServerPort, [switch]$Xml, [switch]$TableOutput, [switch]$AsObject = $true,
[switch]$GenerateSql,
    [switch]$GenerateCommand
    
)
    $InvokeParam = @{
        ServerUser = $ServerUser
        ServerPassword = $ServerPassword 
        ServerHost = $ServerHostname
        ServerPort = $ServerPort
        Xml = $Xml
        Table = $TableOutput
        AsObject = $AsObject
        GenerateSql = $GenerateSql
        GenerateCommand = $GenerateCommand

        Command =  "SHOW DATABASES"
        }
        Invoke-MySqlCommand -InvocationObject $InvokeParam
}


function Get-MySqlTable {
[cmdletbinding()]
param(
[parameter(Mandatory=$true, ValueFromPipeline=$True,Position=0)]
[alias('Name')]
[string]$TableName,
[string]$ServerUser, [string]$ServerPassword, [string]$ServerHost, [string]$ServerPort, [switch]$Xml, [switch]$TableOutput, [switch]$AsObject = $true,
[switch]$GenerateSql,
    [switch]$GenerateCommand
)
    $InvokeParam = @{
        ServerUser = $ServerUser
        ServerPassword = $ServerPassword 
        ServerHost = $ServerHostname
        ServerPort = $ServerPort
        Xml = $Xml
        Table = $TableOutput
        AsObject = $AsObject
        GenerateSql = $GenerateSql
        GenerateCommand = $GenerateCommand

        Command = [string]"show full tables from " + $Name
        }
        Invoke-MySqlCommand  -InvocationObject $InvokeParam  
}#end get-mysqltable

function Get-MySqlColumn {
[cmdletbinding()]
param(
[parameter(Mandatory=$true, ParameterSetName="Object", ValueFromPipeline=$True, Position = 0)]
[string]$Table,
[parameter(Mandatory=$false, ParameterSetName="Object", ValueFromPipeline=$false, Position = 1)]
[string]$Database,
[string]$ServerUser, [string]$ServerPassword, [string]$ServerHost, [string]$ServerPort, [switch]$Xml, [switch]$TableOutput, [switch]$AsObject = $true,
[switch]$GenerateSql,
    [switch]$GenerateCommand
    )
if ($Database) {
    $Command = [string]"SHOW FULL COLUMNS FROM " + $Table + " FROM " + $Database
    }
    else {
    $Command = [string]"SHOW FULL COLUMNS FROM " + $Table 
    }

    $InvokeParam = @{
        ServerUser = $ServerUser
        ServerPassword = $ServerPassword 
        ServerHost = $ServerHostname
        ServerPort = $ServerPort
        Xml = $Xml
        TableOutput = $TableOutput
        AsObject = $AsObject
        GenerateSql = $GenerateSql
        GenerateCommand = $GenerateCommand

        Command = $Command
        }
        Invoke-MySqlCommand  -InvocationObject $InvokeParam  
}#end get-mysqltable

function Remove-MySqlDatabase {[cmdletbinding()]
param (
[Parameter(Mandatory=$True)][string]$Database,
[string]$ServerUser, [string]$ServerPassword, [string]$ServerHost, [string]$ServerPort, [switch]$Xml,
[switch]$GenerateSql,
    [switch]$GenerateCommand
)
    $InvokeParam = @{
        ServerUser = $ServerUser
        ServerPassword = $ServerPassword 
        ServerHost = $ServerHostname
        ServerPort = $ServerPort
        Xml = $Xml
        Command = "DROP DATABASE ``" + $Database + "``"
        }
Invoke-MySqlCommand -InvocationObject $InvokeParam
}

function Remove-MySqlUser {[cmdletbinding()]
    param (
        [Parameter(Mandatory=$True)][string]$Username, 
        [string]$ServerUser, [string]$ServerPassword, [string]$ServerHost, [string]$ServerPort, [switch]$Xml,
[switch]$GenerateSql,
    [switch]$GenerateCommand
    )
    $InvokeParam = @{
        ServerUser = $ServerUser
        ServerPassword = $ServerPassword 
        ServerHost = $ServerHostname
        ServerPort = $ServerPort
        Xml = $Xml
        GenerateSql = $GenerateSql
        GenerateCommand = $GenerateCommand

        Command = "DROP USER " + $Username + ""
        }
Invoke-MySqlCommand -InvocationObject $InvokeParam
}

function Get-MySqlGrants {
[CmdletBinding(DefaultParameterSetName="Command")]
param (
    [string]$ServerUser, [string]$ServerPassword, [string]$ServerHost, [string]$ServerPort
    )
    $InvokeParam = @{
        ServerUser = $ServerUser
        ServerPassword = $ServerPassword 
        ServerHost = $ServerHostname
        ServerPort = $ServerPort
        }
  $MySqlUsers = @(Get-MySqlUser @InvokeParam) 
  $nameRegex = 'Grants\sfor\s(?<user>\S+)@(?<host>\S+)'
  
  foreach ($User in $MySqlUsers) {   
    [xml]$Grant = Invoke-MySqlCommand -xml "show grants for '$($User.user)'@'$($User.host)'" @InvokeParam
 
    foreach ($field in @($Grant.resultset.row.field)) {
        $obj = New-Object System.Object
        "Parsing entry named " + $field.name + " with value " + $field.'#text' | Write-Debug
        $PerformRegex = $field.name -match $nameRegex
        Add-Member -InputObject $obj -Type NoteProperty -Name "User" -Value ([string]($Matches['user']))
        Add-Member -InputObject $obj -Type NoteProperty -Name "Host" -Value ([string]($Matches['host']))
        Add-Member -InputObject $obj -Type NoteProperty -Name 'Grant' -Value ([string]($field.'#text'))
        $obj
        } #end foreach field
    } #end foreach User
}#ned function Get-MySqlGrant

function Clear-MySqlPrivilegesCache {[cmdletbinding()]
param(
[string]$ServerUser, [string]$ServerPassword, [string]$ServerHost, [string]$ServerPort, [switch]$Xml,
[switch]$GenerateSql,
    [switch]$GenerateCommand
)
    $InvokeParam = @{
        ServerUser = $ServerUser
        ServerPassword = $ServerPassword 
        ServerHost = $ServerHostname
        ServerPort = $ServerPort
        Xml = $Xml
        Command =  "FLUSH PRIVILEGES"
        }
Invoke-MySqlCommand -InvocationObject $InvokeParam
}


function Remove-MySqlPrivilege {
<#
.SYNOPSIS
Remove Privilege on MySQL database

.Example
Renive-MySqlPrivilege -Database TestingDB2 -Username Vasya 
#>
[cmdletbinding()]
    param (
        [string[]]$Privilege = "ALL PRIVILEGES",
            [Parameter(Mandatory=$True)]
        [string]$Database,
            [Parameter(Mandatory=$false)]
        [string]$Table = '*',
            [Parameter(Mandatory=$True)]
        [string]$Username,
        [string]$Hostname = 'localhost',
        [string]$ServerUser, [string]$ServerPassword, [string]$ServerHost, [string]$ServerPort, [switch]$Xml,
        [switch]$GenerateSql, [switch]$GenerateCommand
        )

    $InvokeParam = @{
        ServerUser = $ServerUser
        ServerPassword = $ServerPassword 
        ServerHost = $ServerHostname
        ServerPort = $ServerPort
        Xml = $Xml
        GenerateSql = $GenerateSql
        GenerateCommand = $GenerateCommand
        #command will be constructed further
        Command = ''
        }
    if ($Table -ne '*') {
        $Table = "``" + $Table + "``"
        }

    [int]$PrivCount = @($Privilege).Length
        if ($PrivCount -gt 1) {
            [string]$NewPrivString = ''
            for ($i = 0; $i -lt $PrivCount; $i++) {
                $NewPrivString += $Privilege[$i]
                if ($i -ne ($PrivCount - 1)) {
                    $NewPrivString += ', ' 
                    }
                }#end for
            $Privilege = $NewPrivString
            }#end if
    $InvokeParam['Command'] = "REVOKE " + $Privilege + " ON ``"+$Database+"``." + $Table + " FROM '" +$Username+"'@'"+$Hostname+ "'" 
        
Invoke-MySqlCommand -InvocationObject $InvokeParam
}


Set-Alias Flush-MySqlPrivileges Clear-MySqlPrivilegesCache
Set-Alias Revoke-MySqlPrivilege Remove-MySqlPrivilege
