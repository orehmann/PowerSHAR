# PowerSHAR
A PowerShell variant for the *nix shar command.

Sometimes it is hard to transfer binary files (e.g. zip, exe, ... ) to another destination. This because of the lack of file transfer solution or blocking of file types in email solutions.
PowerSHAR acts like the *NIX shar command. It takes a file or folder as input and converts it into a selfcontained powershell script. This script holds the converted files as well as the logic 
to extract/restore the files/folders by simply running the script on the destination system inside a Powershell.

## Usage

NAME
    PowerShar.ps1

SYNOPSIS
    Processes input objects, creates a ShellArchive, and optionally applies hashing and encryption.

SYNTAX
    **E:\PROJECTS\PowerShar\PowerShar.ps1 [[-InputObject] <String[]>] [[-ArchiveName] <String>] [[-Destination]
    <String>] [[-HashAlgorithm] <String>] [[-EncryptionKey] <String>] [<CommonParameters>]**

DESCRIPTION
    This script accepts one or more input objects, archives them into a specified ShellArchive, and allows for
    optional hashing using a selectable algorithm and encryption with a provided key.


## Examples - Creating Archives
PS> **.\PowerShar.ps1 -ArchiveName "TestArchive" -Destination C:\Temp -InputObject C:\Temp\file.bin,C:\temp\filename.extension,C:\temp\inputfile.json,C:\temp\directory1.txt,C:\temp\Test**

This results in a file C:\Temp\TestArchive.ps1 containing four files (file.bin,filename.extension,inputfile.json,directory1.txt) and a folder (C:\Temp\Test) as a ZIP-File.

```powershell
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
PS> **Get-ChildItem -Path C:\temp\Wired_driver_30.0.1_x64 | .\PowerShar.ps1 -ArchiveName WiredDriver**

PowerShar accepts input from pipeline as well. 
(!!! Do not use -Recurse for Get-ChildItem as this results in double packing. PowerShar itself already does a recurse)

```powershell
----------------------------------------------------------------------
 PowerShell Archive - 1.0
 Author : github@solar-imperium.com
----------------------------------------------------------------------

ArchiveName     : WiredDriver
Destination     : .
Hash Algorithm  : SHA256
Use Encryption  : False

[1] Added item [folder] : C:\Temp\Wired_driver_30.0.1_x64\DOCS
[2] Added item [folder] : C:\Temp\Wired_driver_30.0.1_x64\PRO1000
[3] Added item [folder] : C:\Temp\Wired_driver_30.0.1_x64\PRO2500
[4] Added item [folder] : C:\Temp\Wired_driver_30.0.1_x64\PRO40GB
[5] Added item [folder] : C:\Temp\Wired_driver_30.0.1_x64\PROAVF
[6] Added item [folder] : C:\Temp\Wired_driver_30.0.1_x64\PROCGB
[7] Added item [folder] : C:\Temp\Wired_driver_30.0.1_x64\PROXGB
[8] Added item [folder] : C:\Temp\Wired_driver_30.0.1_x64\Resource
[9] Added item [  file] : C:\Temp\Wired_driver_30.0.1_x64\3rd_party_licenses.txt
[10] Added item [  file] : C:\Temp\Wired_driver_30.0.1_x64\license.pdf
[11] Added item [  file] : C:\Temp\Wired_driver_30.0.1_x64\license.txt
[12] Added item [  file] : C:\Temp\Wired_driver_30.0.1_x64\readme.txt
[13] Added item [  file] : C:\Temp\Wired_driver_30.0.1_x64\SetupBD.exe
[14] Added item [  file] : C:\Temp\Wired_driver_30.0.1_x64\verfile.tic

Writing PowerShell Archive : .\WiredDriver.ps1

Processed 8 folders and 6 files
Finished...
```

PS> **gci -Path C:\temp\Wired_driver_30.0.1_x64 | .\PowerShar.ps1 -ArchiveName WiredDriver -Verbose**

Same as above but with more Verbose output.
```powershell
----------------------------------------------------------------------
 PowerShell Archive - 1.0
 Author : github@solar-imperium.com
----------------------------------------------------------------------

ArchiveName     : WiredDriver
Destination     : .
Hash Algorithm  : SHA256
Use Encryption  : False

[1] Added item [folder] [Hash:4B55F832A741027E04596B9177C8DEFD73D3499265BA4BD931D71CFB1019750A] : C:\Temp\Wired_driver_30.0.1_x64\DOCS
[2] Added item [folder] [Hash:A61072D41A675097D5DBDA64530DF52802BF1F938D4B7295D3C3F274478B7BBF] : C:\Temp\Wired_driver_30.0.1_x64\PRO1000
[3] Added item [folder] [Hash:D1EB0B91B70777E10BF6516671524F35B8635878EB258F668D0DB8DBC57E0ED9] : C:\Temp\Wired_driver_30.0.1_x64\PRO2500
[4] Added item [folder] [Hash:B68130C3D619773CC34F636229643D3A44221F97E728D6D3949C1671563781BF] : C:\Temp\Wired_driver_30.0.1_x64\PRO40GB
[5] Added item [folder] [Hash:C59C351F9688D3F91117C98F7135985B82DD40F78F2A88B78C1620D9C62EA344] : C:\Temp\Wired_driver_30.0.1_x64\PROAVF
[6] Added item [folder] [Hash:ED05FD117FA52DD3BAEB526CD852C8AEA40DA209900E2CE576B82AEA781BF546] : C:\Temp\Wired_driver_30.0.1_x64\PROCGB
[7] Added item [folder] [Hash:BBDDC9D216FB3A1E6CC2DD740EF74E0FFE337AA430F4C2066755153E75773A8B] : C:\Temp\Wired_driver_30.0.1_x64\PROXGB
[8] Added item [folder] [Hash:BF41E0558C14CA3A50F5E336CE3B40FAA1600FB71FF8ADAA3E41F82DE2964A42] : C:\Temp\Wired_driver_30.0.1_x64\Resource
[9] Added item [  file] [Hash:A132E03690709A191BF600FCE2DA94BC5D1C1A262219C7B8633D409B9DCA1156] : C:\Temp\Wired_driver_30.0.1_x64\3rd_party_licenses.txt
[10] Added item [  file] [Hash:2C9471CDFE808C96EE7F2E3979B3ACE9EB29F398D07F2985BAAD312DEFC1F5EB] : C:\Temp\Wired_driver_30.0.1_x64\license.pdf
[11] Added item [  file] [Hash:568A7F0F8596656B3F38DBC06706FFF8730E2C3742A7790D1F983AA7F5B98E28] : C:\Temp\Wired_driver_30.0.1_x64\license.txt
[12] Added item [  file] [Hash:F69F76866509B18CDF1135FEF1C65B387C1A7ECD4F5FC7C94A886315F3873512] : C:\Temp\Wired_driver_30.0.1_x64\readme.txt
[13] Added item [  file] [Hash:29CE78052A9D0661142E2CFABA4EE336656DF31B0C762D52A4257AE37B249769] : C:\Temp\Wired_driver_30.0.1_x64\SetupBD.exe
[14] Added item [  file] [Hash:177B2426B4FF41D4940E209277070246631DCA81ED1ACFA4768BDB0DB67FA04D] : C:\Temp\Wired_driver_30.0.1_x64\verfile.tic

Writing PowerShell Archive : .\WiredDriver.ps1

Processed 8 folders and 6 files
Finished...
```

## Examples - Extracting Archives
On the target system simply save the file to a temporary directory (e.g. C:\Temp) and rename (if you had to rename it for transport purposes) the file back to *.ps1 (e.g. WiredDrive.ps1). 
Open a PowerShell and step into the temporary diretory.

PS> cd C:\temp

Extract the PowerShar Archive by simply running it.

PS> .\WiredDriver.ps1

```powershell
---------------------------------------------------------------------
 PowerShell Archive - 1.1
 Author : github@solar-imperium.com
----------------------------------------------------------------------

Creation Date   : 2025-11-14 17:42:58
Destination     : .
Number of items : 14
Hash Algorithm  : SHA256
Use Encryption  : False

[1] Folder : DOCS.zip => Successfully expanded folder archive.
[2] Folder : PRO1000.zip => Successfully expanded folder archive.
[3] Folder : PRO2500.zip => Successfully expanded folder archive.
[4] Folder : PRO40GB.zip => Successfully expanded folder archive.
[5] Folder : PROAVF.zip => Successfully expanded folder archive.
[6] Folder : PROCGB.zip => Successfully expanded folder archive.
[7] Folder : PROXGB.zip => Successfully expanded folder archive.
[8] Folder : Resource.zip => Successfully expanded folder archive.
[9] File : 3rd_party_licenses.txt => Successfully created. [Hash (VALID): A132E03690709A191BF600FCE2DA94BC5D1C1A262219C7B8633D409B9DCA1156]
[10] File : license.pdf => Successfully created. [Hash (VALID): 2C9471CDFE808C96EE7F2E3979B3ACE9EB29F398D07F2985BAAD312DEFC1F5EB]
[11] File : license.txt => Successfully created. [Hash (VALID): 568A7F0F8596656B3F38DBC06706FFF8730E2C3742A7790D1F983AA7F5B98E28]
[12] File : readme.txt => Successfully created. [Hash (VALID): F69F76866509B18CDF1135FEF1C65B387C1A7ECD4F5FC7C94A886315F3873512]
[13] File : SetupBD.exe => Successfully created. [Hash (VALID): 29CE78052A9D0661142E2CFABA4EE336656DF31B0C762D52A4257AE37B249769]
[14] File : verfile.tic => Successfully created. [Hash (VALID): 177B2426B4FF41D4940E209277070246631DCA81ED1ACFA4768BDB0DB67FA04D]

Finished...
```

PS> .\WiredDriver.ps -List 

Simply List Content of archive.

```powershell
----------------------------------------------------------------------
 PowerShell Archive - 1.1
 Author : github@solar-imperium.com
----------------------------------------------------------------------

Creation Date   : 2025-11-14 17:42:58
Destination     : .
Number of items : 14
Hash Algorithm  : SHA256
Use Encryption  : False

[ 1] [folder] Hash:4B55F832A741027E04596B9177C8DEFD73D3499265BA4BD931D71CFB1019750A : DOCS.zip
[ 2] [folder] Hash:D05FF68C6B65200F9BE5D3D601625D0E7BDC08B0721923BDBD856D6E90A307CD : PRO1000.zip
[ 3] [folder] Hash:AF6E05ADA4CD3A3E9BE8DFC5AD059B9CACAC343705020E37971CBA5A947CFE7D : PRO2500.zip
[ 4] [folder] Hash:C9B8E9376DC11AEB0EA7FA9F7276A104DB8F75B9321DED9565BA2BC27C12E9AF : PRO40GB.zip
[ 5] [folder] Hash:E3973C23214A937DB217D16C98FB80BCF99A7070EC425AB6C6E3266DF3F25120 : PROAVF.zip
[ 6] [folder] Hash:D64EDB4EE0C7B2FE6AEC83222B139C560831E2321496D80EFB942505C6CFD414 : PROCGB.zip
[ 7] [folder] Hash:FF8529A92FFC56E7212FF1846E3952C974802DC0D97D9670ACD4DAFCF358447A : PROXGB.zip
[ 8] [folder] Hash:BF41E0558C14CA3A50F5E336CE3B40FAA1600FB71FF8ADAA3E41F82DE2964A42 : Resource.zip
[ 9] [  file] Hash:A132E03690709A191BF600FCE2DA94BC5D1C1A262219C7B8633D409B9DCA1156 : 3rd_party_licenses.txt
[10] [  file] Hash:2C9471CDFE808C96EE7F2E3979B3ACE9EB29F398D07F2985BAAD312DEFC1F5EB : license.pdf
[11] [  file] Hash:568A7F0F8596656B3F38DBC06706FFF8730E2C3742A7790D1F983AA7F5B98E28 : license.txt
[12] [  file] Hash:F69F76866509B18CDF1135FEF1C65B387C1A7ECD4F5FC7C94A886315F3873512 : readme.txt
[13] [  file] Hash:29CE78052A9D0661142E2CFABA4EE336656DF31B0C762D52A4257AE37B249769 : SetupBD.exe
[14] [  file] Hash:177B2426B4FF41D4940E209277070246631DCA81ED1ACFA4768BDB0DB67FA04D : verfile.tic

Finished...
```

PS> .\WiredDriver.ps1 -Filter PRO

Only extraxt itmes that match the filter criteria (e.g. files ontaining **PRO**)

```powershell
----------------------------------------------------------------------
 PowerShell Archive - 1.1
 Author : github@solar-imperium.com
----------------------------------------------------------------------

Creation Date   : 2025-11-14 17:42:58
Destination     : .
Number of items : 14
Hash Algorithm  : SHA256
Use Encryption  : False

[2] Folder : PRO1000.zip => Successfully expanded folder archive.
[3] Folder : PRO2500.zip => Successfully expanded folder archive.
[4] Folder : PRO40GB.zip => Successfully expanded folder archive.
[5] Folder : PROAVF.zip => Successfully expanded folder archive.
[6] Folder : PROCGB.zip => Successfully expanded folder archive.
[7] Folder : PROXGB.zip => Successfully expanded folder archive.

Finished...
```

## Tips

- Use **-EncryptionKey** to AES encrypt the payload (not the resulting script).

PS> **Get-ChildItem -Path C:\temp\Wired_driver_30.0.1_x64 | .\PowerShar.ps1 -ArchiveName WiredDriver -EncryptionKey MySecret**

- To decrypt specify the EncryptionKey as well

PS> **.\WiredDriver.ps1 -EncryptionKey MySecret**

Do not use **-Recurse** when using Get-ChildItem to pass files by pipeline input. PowerShar creates ZIP from every top-level folder found.
Specifying **-Recurse** bloats the resulting archive by multiply archving the same content.

- Some email systems block certain type of files by extensions such as __*.ps1__. Rename the file to something else like __*.txt, *.dat, *.jpg__
  
