# PowerSHAR
A PowerShell variant for the *nix shar command.

Sometimes it is hard to transfer binary files (e.g. zip, exe, ... ) to another destination. This because of the lack of file transfer solution or blocking of file types in email solutions.
PowerSHAR acts like the *NIX shar command. It takes a file or folder as input and converts it into a selfcontained powershell script. This script holds the converted files as well as the logic 
to extract/restore the files/folders by simply running the script on the destination system inside a Powershell.

## Examples
PS> .\PowerShar.ps1 -ArchiveName "TestArchive" -Destination C:\Temp -InputObject C:\Temp\file.bin,C:\temp\filename.extension,C:\temp\inputfile.json,C:\temp\directory1.txt,C:\temp\Test

This results in a file C:\Temp\TestArchive.ps1 containing four files (file.bin,filename.extension,inputfile.json,directory1.txt) and a folder (C:\Temp\Test) as a ZIP-File.

```
----------------------------------------------------------------------
 PowerShell Archive - 1.0
 Author : github@solar-imperium.com
----------------------------------------------------------------------

ArchiveName     : TestArchive
Destination     : C:\Temp

[1] Added item : C:\Temp\file.bin
[2] Added item : C:\temp\filename.extension
[3] Added item : C:\temp\inputfile.json
[4] Added item : C:\temp\directory1.txt
[5] Added item : C:\Temp\Test

Writing PowerShell Archive : C:\Temp\TestArchive.ps1

Finished...
```

