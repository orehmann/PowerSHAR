
<#
.SYNOPSIS
    Processes input objects, creates a ShellArchive, and optionally applies hashing and encryption.

.DESCRIPTION
    This script accepts one or more input objects, archives them into a specified ShellArchive, and allows for optional hashing using a selectable algorithm and encryption with a provided key.

.PARAMETER InputObject
    The input objects to be processed and archived.

.PARAMETER ArchiveName
    The name of the output archive file. Defaults to 'PowerSharOut'.

.PARAMETER Destination
    The destination directory where the archive will be saved. Defaults to the current directory.

.PARAMETER HashAlgorithm
    The hashing algorithm to use for processing. Valid values are 'SHA1', 'SHA256', 'SHA384', and 'SHA512'. Defaults to 'SHA256'.

.PARAMETER EncryptionKey
    The key to use for encrypting the archive. If not specified, encryption is not applied.

.EXAMPLE
    The following example adds two files to the ShellArchive MyArchive and encrypts them with the key "MyKey123". It uses a HashAlgorith of SHA256 and outputs the file to Folder C:\Archives

    .\PowerShar.ps1 -InputObject "C:\Path\To\File1.txt", "C:\Path\To\File2.txt" -ArchiveName "MyArchive" -Destination "C:\Archives" -HashAlgorithm "SHA256" -EncryptionKey "MyKey123"    
.EXAMPLE
    The following example adds Folder1 and a file called File2.txt to the ShellArchive MyArchive. It uses a HashAlgorith of SHA512 and outputs the file to Folder C:\Archives

    .\PowerShar.ps1 -InputObject "C:\Path\To\Folder1", "C:\Path\To\File2.txt" -ArchiveName "MyArchive" -Destination "C:\Archives" -HashAlgorithm "SHA512"
.EXAMPLE 
    The following example uses Pipeline-Input and adds the files and/or folders to the ShellArchive WiredDriver. Do not use -Recursive for Get-ChildItem as this would multiply the output.
    The recursion is done by zipping folders and storing them as simple files. When running the ShellArchive on the destination host they will be unzipped and the structure restored.

    Get-ChildItem -Path C:\temp\Wired_driver_30.0.1_x64 | .\PowerShar.ps1 -ArchiveName WiredDriver2    
#>
[CmdletBinding()]
param (
    [Parameter(ValueFromPipeline=$true)]
    [string[]]$InputObject,
    [string]$ArchiveName = "PowerSharOut" ,   
    [string]$Destination = ".",
    [ValidateSet('SHA1', 'SHA256', 'SHA384', 'SHA512')]
    [string]$HashAlgorithm = 'SHA256',
    [string]$EncryptionKey
)

Begin 
{
# -------------------------------------------------------
# FUNCTIONS
# -------------------------------------------------------

<#
.SYNOPSIS
    Resolves a given path to its absolute form, ensuring it is safe for use.

.PARAMETER Path
    The path to resolve.    
#>
function Resolve-PathSafe
{
    param
    (
        [string] $Path
    )
      
    $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path)
}

<#
.SYNOPSIS
    Converts a file to Base64 encoding and writes the output to a specified target file.
.PARAMETER SourceFilePath
    The path to the source file to be converted.
.PARAMETER TargetFilePath
    The path where the Base64 encoded output will be written.
#>
function ConvertTo-Base64
{
    param
    (
        [string] $SourceFilePath,
        [string] $TargetFilePath
    )
 
    $SourceFilePath = Resolve-PathSafe $SourceFilePath
    $TargetFilePath = Resolve-PathSafe $TargetFilePath
     
    $bufferSize = 9000 # should be a multiplier of 3
    $buffer = New-Object byte[] $bufferSize
     
    $reader = [System.IO.File]::OpenRead($SourceFilePath)
    $writer = [System.IO.File]::CreateText($TargetFilePath)
     
    $bytesRead = 0
    do
    {
        $bytesRead = $reader.Read($buffer, 0, $bufferSize);
        $writer.Write([Convert]::ToBase64String($buffer, 0, $bytesRead));
    } while ($bytesRead -eq $bufferSize);
     
    $reader.Dispose()
    $writer.Dispose()
}

<#
.SYNOPSIS
    Encrypts or decrypts text or files using AES encryption.
.DESCRIPTION
    This function can encrypt or decrypt text or files using AES encryption with a specified key. It supports both encryption and decryption modes, and can handle input as either text or file paths.
.PARAMETER Mode
    Specifies whether to encrypt or decrypt. Valid values are 'Encrypt' and 'Decrypt'.
.PARAMETER Key
    The encryption key to use for AES encryption. It should be a string.
.PARAMETER Text
    The text to encrypt or decrypt. This parameter is mandatory when using the 'CryptText'
    parameter set.
.PARAMETER Path
    The file path to encrypt or decrypt. This parameter is mandatory when using the 'CryptFile'
    parameter set.    
#>
function Invoke-AESEncryption
{
    [CmdletBinding()]
    [OutputType([string])]
    Param
    (
        [Parameter(Mandatory = $true)]
        [ValidateSet('Encrypt', 'Decrypt')]
        [String]$Mode,
        [Parameter(Mandatory = $true)]
        [String]$Key,
        [Parameter(Mandatory = $true, ParameterSetName = "CryptText")]
        [String]$Text,
        [Parameter(Mandatory = $true, ParameterSetName = "CryptFile")]
        [String]$Path
    )
    
    Begin
    {
        $shaManaged = New-Object System.Security.Cryptography.SHA256Managed
        $aesManaged = New-Object System.Security.Cryptography.AesManaged
        $aesManaged.Mode      = [System.Security.Cryptography.CipherMode]::CBC
        $aesManaged.Padding   = [System.Security.Cryptography.PaddingMode]::Zeros
        $aesManaged.BlockSize = 128
        $aesManaged.KeySize   = 256
    }
    
    Process
    {
        $aesManaged.Key = $shaManaged.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($Key))
        
        switch ($Mode)
        {
            'Encrypt' {
                if ($Text) { $plainBytes = [System.Text.Encoding]::UTF8.GetBytes($Text) }
                
                if ($Path)
                {
                    $File = Get-Item -Path $Path -ErrorAction SilentlyContinue
                    if (!$File.FullName)
                    {
                        Write-Error -Message "File not found!"
                        break
                    }
                    $plainBytes = [System.IO.File]::ReadAllBytes($File.FullName)
                    $outPath = $File.FullName + ".aes"
                }
                
                $encryptor = $aesManaged.CreateEncryptor()
                $encryptedBytes = $encryptor.TransformFinalBlock($plainBytes, 0, $plainBytes.Length)
                $encryptedBytes = $aesManaged.IV + $encryptedBytes
                $aesManaged.Dispose()
                
                if ($Text) { return [System.Convert]::ToBase64String($encryptedBytes) }
                
                if ($Path)
                {
                    [System.IO.File]::WriteAllBytes($outPath, $encryptedBytes)
                    (Get-Item $outPath).LastWriteTime = $File.LastWriteTime
                    return "File encrypted to $outPath"
                }
            }
            
            'Decrypt' {
                if ($Text) { $cipherBytes = [System.Convert]::FromBase64String($Text) }
                
                if ($Path)
                {
                    $File = Get-Item -Path $Path -ErrorAction SilentlyContinue
                    if (!$File.FullName)
                    {
                        Write-Error -Message "File not found!"
                        break
                    }
                    $cipherBytes = [System.IO.File]::ReadAllBytes($File.FullName)
                    $outPath = $File.FullName -replace ".aes"
                }
                
                $aesManaged.IV = $cipherBytes[0 .. 15]
                $decryptor = $aesManaged.CreateDecryptor()
                $decryptedBytes = $decryptor.TransformFinalBlock($cipherBytes, 16, $cipherBytes.Length - 16)
                $aesManaged.Dispose()
                
                if ($Text) { return [System.Text.Encoding]::UTF8.GetString($decryptedBytes).Trim([char]0) }
                
                if ($Path)
                {
                    [System.IO.File]::WriteAllBytes($outPath, $decryptedBytes)
                    (Get-Item $outPath).LastWriteTime = $File.LastWriteTime
                    return "File decrypted to $outPath"
                }
            }
        }
    }
    
    End
    {
        $shaManaged.Dispose()
        $aesManaged.Dispose()
    }
}

# -------------------------------------------------------
# Output Declarations
# -------------------------------------------------------
$payloadJson = @"
{
    "Version": "1.1",
    "HashAlgorithm" : "",
    "Encrypted" : false,
    "Date" : "",
    "Items": [
      {
        "id": 0,
        "name" : "[ROOT]",
        "type" : "[NULL]",
        "hash" : "[NULL]",
        "data" : "[NULL]"
      }
    ]
  }
"@

$payloadCode = @'
# -----> BEGIN PowerShar Output-File <------------------------------------------------------------
# -----> Save Output to ASCII file ending into SomeFilename.ps1
# -----> Run SomeFilename.ps1 in PowerShell : PS> .\SomeFilename.ps1

[CmdletBinding()]
param (
    [Parameter()]
    [string]$Destination = ".",
    [string]$EncryptionKey,
    [ValidateSet('All', 'FoldersOnly', 'FilesOnly')]
    [string]$ExtractMode = 'All',
    [string]$Filter,
    [switch]$List
)

# -------------------------------------------------------
# Init
# -------------------------------------------------------
$Host.UI.RawUI.ForegroundColor = 'White'
$ScriptVersion = "1.1"
$ScriptAuthor  = "github@solar-imperium.com"
$Verbose = $PSBoundParameters.ContainsKey('Verbose')

# -------------------------------------------------------
# Functions
# -------------------------------------------------------
function Resolve-PathSafe
{
    param
    (
        [string] $Path
    )
      
    $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path)
}

function ConvertFrom-Base64
{
    param
    (
        [string] $SourceFilePath,
        [string] $TargetFilePath
    )
 
    $SourceFilePath = Resolve-PathSafe $SourceFilePath
    $TargetFilePath = Resolve-PathSafe $TargetFilePath
 
    $bufferSize = 9000 # should be a multiplier of 4
    $buffer = New-Object char[] $bufferSize
     
    $reader = [System.IO.File]::OpenText($SourceFilePath)
    $writer = [System.IO.File]::OpenWrite($TargetFilePath)
     
    $bytesRead = 0
    do
    {
        $bytesRead = $reader.Read($buffer, 0, $bufferSize);
        $bytes = [Convert]::FromBase64CharArray($buffer, 0, $bytesRead);
        $writer.Write($bytes, 0, $bytes.Length);
    } while ($bytesRead -eq $bufferSize);
     
    $reader.Dispose()
    $writer.Dispose()
}

function Invoke-AESEncryption
{
    [CmdletBinding()]
    [OutputType([string])]
    Param
    (
        [Parameter(Mandatory = $true)]
        [ValidateSet('Encrypt', 'Decrypt')]
        [String]$Mode,
        [Parameter(Mandatory = $true)]
        [String]$Key,
        [Parameter(Mandatory = $true, ParameterSetName = "CryptText")]
        [String]$Text,
        [Parameter(Mandatory = $true, ParameterSetName = "CryptFile")]
        [String]$Path
    )
    
    Begin
    {
        $shaManaged = New-Object System.Security.Cryptography.SHA256Managed
        $aesManaged = New-Object System.Security.Cryptography.AesManaged
        $aesManaged.Mode      = [System.Security.Cryptography.CipherMode]::CBC
        $aesManaged.Padding   = [System.Security.Cryptography.PaddingMode]::Zeros
        $aesManaged.BlockSize = 128
        $aesManaged.KeySize   = 256
    }
    
    Process
    {
        $aesManaged.Key = $shaManaged.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($Key))
        
        switch ($Mode)
        {
            'Encrypt' {
                if ($Text) { $plainBytes = [System.Text.Encoding]::UTF8.GetBytes($Text) }
                
                if ($Path)
                {
                    $File = Get-Item -Path $Path -ErrorAction SilentlyContinue
                    if (!$File.FullName)
                    {
                        Write-Error -Message "File not found!"
                        break
                    }
                    $plainBytes = [System.IO.File]::ReadAllBytes($File.FullName)
                    $outPath = $File.FullName + ".aes"
                }
                
                $encryptor = $aesManaged.CreateEncryptor()
                $encryptedBytes = $encryptor.TransformFinalBlock($plainBytes, 0, $plainBytes.Length)
                $encryptedBytes = $aesManaged.IV + $encryptedBytes
                $aesManaged.Dispose()
                
                if ($Text) { return [System.Convert]::ToBase64String($encryptedBytes) }
                
                if ($Path)
                {
                    [System.IO.File]::WriteAllBytes($outPath, $encryptedBytes)
                    (Get-Item $outPath).LastWriteTime = $File.LastWriteTime
                    return "File encrypted to $outPath"
                }
            }
            
            'Decrypt' {
                if ($Text) { $cipherBytes = [System.Convert]::FromBase64String($Text) }
                
                if ($Path)
                {
                    $File = Get-Item -Path $Path -ErrorAction SilentlyContinue
                    if (!$File.FullName)
                    {
                        Write-Error -Message "File not found!"
                        break
                    }
                    $cipherBytes = [System.IO.File]::ReadAllBytes($File.FullName)
                    $outPath = $File.FullName -replace ".aes"
                }
                
                $aesManaged.IV = $cipherBytes[0 .. 15]
                $decryptor = $aesManaged.CreateDecryptor()
                $decryptedBytes = $decryptor.TransformFinalBlock($cipherBytes, 16, $cipherBytes.Length - 16)
                $aesManaged.Dispose()
                
                if ($Text) { return [System.Text.Encoding]::UTF8.GetString($decryptedBytes).Trim([char]0) }
                
                if ($Path)
                {
                    [System.IO.File]::WriteAllBytes($outPath, $decryptedBytes)
                    (Get-Item $outPath).LastWriteTime = $File.LastWriteTime
                    return "File decrypted to $outPath"
                }
            }
        }
    }
    
    End
    {
        $shaManaged.Dispose()
        $aesManaged.Dispose()
    }
}

# -------------------------------------------------------
# PAYLOAD
# -------------------------------------------------------
$payloadJsonData = @"
[PAYLOADJSONDATA]
"@
$payload = $payloadJsonData | ConvertFrom-Json

# -------------------------------------------------------
# MAIN
# -------------------------------------------------------
Write-Host "----------------------------------------------------------------------"
Write-Host " PowerShell Archive - $ScriptVersion                                  "
Write-Host " Author : $ScriptAuthor                                               "
Write-Host "----------------------------------------------------------------------"
Write-Host ""
Write-Host "Creation Date   : $($payload.Date)"
Write-Host "Destination     : $Destination"
Write-Host "Number of items : $($payload.Items.Count - 1)"
Write-Host "Hash Algorithm  : $($payload.HashAlgorithm)"
Write-Host "Use Encryption  : $($payload.Encrypted)"
Write-Host ""

if ($payload.Encrypted -and (-not $EncryptionKey))
{
    Write-Host -ForegroundColor Red "PowerShell Archive is encrypted. Please provide an encryption key using the -EncryptionKey parameter."
    Exit 1
}

ForEach ($item in $payload.Items)
{
    if ($List -and ($item.Id -gt 0))
    {
        Write-Host -ForegroundColor Yellow ("[{0,2}] [{1,6}] Hash:{2} : {3}" -f $item.id, $item.type, $item.hash, $item.name)
        continue
    }

    if ($item.Id -eq 0) { continue } # Skip Header
    if (($item.type -eq 'folder') -and ($ExtractMode -eq 'FilesOnly'))   { continue } # Skip all folders if ExtractMethod is FilesOnly
    if (($item.type -eq 'file')   -and ($ExtractMode -eq 'FoldersOnly')) { continue } # Skip all files if ExtractMethod is FoldersOnly
    if ($Filter -and ($item.name -notlike "*$Filter*")) { continue } # Filter specified. Skip not matching items
    
    try
    { 
        $OutputFilename = Join-Path -Path $Destination -ChildPath $item.name
        $tmpFileB64     = Join-Path -Path $env:Temp -ChildPath ($item.Name + ".b64")
        
        # Decrypt if needed
        if ($payload.Encrypted)
        {
            $data = Invoke-AESEncryption -Mode Decrypt -Key $EncryptionKey -Text $item.data
        }
        else
        {
            $data = $item.data
        }

        [System.IO.File]::WriteAllText($tmpFileB64,$data)
        ConvertFrom-Base64 -SourceFilePath $tmpFileB64 -TargetFilePath $OutputFilename
        $hash = (Get-FileHash -Path $OutputFilename -Algorithm $payload.HashAlgorithm).Hash

        if ($hash -eq $item.hash)
        {
            if ($item.Type -eq "file")
            {
                Write-Host -ForegroundColor Green ("[{0}] File : {1} => Successfully created. [Hash (VALID): {2}]" -f $item.id, $item.name, $hash)
            }

            if ($item.Type -eq "folder")
            {
                if ($Verbose)
                {
                    Write-Host -ForegroundColor Green ("[{0}] Folder : {1} => Successfully created folder archive file. [Hash (VALID): {2}]" -f $item.id, $item.name, $hash)
                }

                try
                {
                    Expand-Archive -Path $OutputFilename -Destination $Destination -Force | Out-Null
                    Write-Host -ForegroundColor Green ("[{0}] Folder : {1} => Successfully expanded folder archive." -f $item.id, $item.name)
                    Remove-Item -Path $OutputFilename -Force -Confirm: $false | Out-Null
                }
                catch
                {
                    Write-Host -ForegroundColor Red ("[{0}] File   : {1} => Error expanding archive." -f $item.id, $item.name)
                }
            }    
        }
        else
        {
            Write-Host -ForegroundColor Red ("[{0}] File : {1} => Failed to create. [Hash (INVALID): {2} != {3}]" -f $item.id, $item.name, $hash, $item.hash)
        }
    }
    catch
    {
        Write-Host -ForegroundColor Red ("[{0}] File : {1} => Error creating destination file." -f $item.id, $item.name)
    }    
}

Write-Host ""
Write-Host -ForegroundColor Green "Finished..."    

# -----> END PowerShar Output-File <--------------------------------------------------------------
'@

# -------------------------------------------------------
# Main
# -------------------------------------------------------
    $Host.UI.RawUI.ForegroundColor = 'White'
    $ScriptVersion    = "1.0"
    $ScriptAuthor     = "github@solar-imperium.com"
    $Verbose          = $PSBoundParameters.ContainsKey('Verbose')
    $Encryption       = $PSBoundParameters.ContainsKey('EncryptionKey')
    $ItemCountFiles   = 0
    $ItemCountFolders = 0

    # Prepare PayLoad Header
    $payload               = $payloadJson | ConvertFrom-Json 
    $payload.HashAlgorithm = $HashAlgorithm
    $payload.Encrypted     = $Encryption
    $payload.Date          = [DateTime]::Now.ToString("yyyy-MM-dd HH:mm:ss")

    Write-Host "----------------------------------------------------------------------"
    Write-Host " PowerShell Archive - $ScriptVersion                                  "
    Write-Host " Author : $ScriptAuthor                                               "
    Write-Host "----------------------------------------------------------------------"
    Write-Host ""
    Write-Host "ArchiveName     : $ArchiveName"
    Write-Host "Destination     : $Destination"
    Write-Host "Hash Algorithm  : $HashAlgorithm"
    Write-Host "Use Encryption  : $Encryption"
    Write-Host ""
}

Process 
{
# Process all Items
    ForEach($obj in $InputObject)
    {
        try 
        {
            $item = Get-Item -Path $obj     
        }
        catch 
        {
            Write-Host -Red "Error reading item [$obj]. Skipping..."
            continue
        }
            
        if ($item.PSiSContainer)
        {
            # Folder: Compress bevor adding
            $tmpFileZip = Join-Path -Path $env:Temp -ChildPath ($item.Name + ".zip")
            $tmpFileB64 = Join-Path -Path $env:Temp -ChildPath ($item.Name + ".zip.b64")

            Compress-Archive -Path $item.Fullname -DestinationPath $tmpFileZip -Force
            ConvertTo-Base64 -SourceFilepath $tmpFileZip -TargetFilePath $tmpFileB64
            
            $payloaddata = [System.IO.File]::ReadAllText($tmpFileB64)
            
            # Encrypt if needed
            if ($Encryption)
            {
                $payloaddata = Invoke-AESEncryption -Mode Encrypt -Key $EncryptionKey -Text $payloaddata
            }

            # Create output item
            $outItem = [PSCustomObject]@{
                id   = $payload.Items.Count
                name = ($item.Name + ".zip")
                type = "folder"
                hash = (Get-FileHash -Path $tmpFileZip -Algorithm $HashAlgorithm).Hash
                data = $payloaddata
            }
            
            $payload.Items += $outItem
            $ItemCountFolders++

            Remove-Item -Path $tmpFileZip -Force -ErrorAction SilentlyContinue        
            Remove-Item -Path $tmpFileB64 -Force -ErrorAction SilentlyContinue                
        }
        else
        {   # File : Base64-Encode
            $tmpFileB64 = Join-Path -Path $env:Temp -ChildPath ($item.Name + ".b64")       
            ConvertTo-Base64 -SourceFilepath $item.Fullname -TargetFilePath $tmpFileB64
            
            $payloaddata = [System.IO.File]::ReadAllText($tmpFileB64)

            # Encrypt if needed
            if ($Encryption)
            {
                $payloaddata = Invoke-AESEncryption -Mode Encrypt -Key $EncryptionKey -Text $payloaddata
            }
            
            # Create output item
            $outItem = [PSCustomObject]@{
                id = $payload.Items.Count
                name = $item.Name
                type = "file"
                hash = (Get-FileHash -Path $item.FullName -Algorithm $HashAlgorithm).Hash
                data = $payloaddata
            }
            $payload.Items += $outItem
            $ItemCountFiles++

            Remove-Item -Path $tmpFileB64 -Force -ErrorAction SilentlyContinue        
        }

        if (-not $Verbose)
        {
            Write-Host -ForegroundColor Yellow ("[{0,2}] Added item [{1,6}] : {2}" -f $outItem.id,$outItem.type,$item.FullName)   
        }
        else 
        {
            Write-Host -ForegroundColor Yellow ("[{0,2}] Added item [{1,6}] [Hash:{2}] : {3}" -f $outItem.id,$outItem.type,$outItem.hash,$item.FullName)   
        }
    }
}

End 
{
    if ($payload.Items.Count -gt 1)
    {
        $outputFilename = Join-Path -Path $Destination -ChildPath ($ArchiveName + ".ps1")    

        Write-Host ""
        Write-Host "Writing PowerShell Archive : $outputFilename"

        $payloadJsonData = $payload | ConvertTo-Json 
        $payloadCode     = $payloadCode.Replace("[PAYLOADJSONDATA]",$payloadJsonData)
        $payloadCode | Out-File -FilePath $outputFilename -Encoding UTF8 -Force

        Write-Host ""
        Write-Host ("Processed {0} folders and {1} files" -f $ItemCountFolders,$ItemCountFiles)
        Write-Host -ForegroundColor Green "Finished..."    
    }
}
