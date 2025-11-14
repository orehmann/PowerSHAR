# PowerSHAR
A PowerShell variant for the *nix shar command.

Sometimes it is hard to transfer binary files (e.g. zip, exe, ... ) to another destination. This because of the lack of file transfer solution or blocking of file types in email solutions.
PowerSHAR acts like the *NIX shar command. It takes a file or folder as input and converts it into a selfcontained powershell script. This script holds the converted files as well as the logic 
to extract/restore the files/folders by simply running the script on the destination system inside a Powershell.

## Examples - Creating Archives
PS> **.\PowerShar.ps1 -ArchiveName "TestArchive" -Destination C:\Temp -InputObject C:\Temp\file.bin,C:\temp\filename.extension,C:\temp\inputfile.json,C:\temp\directory1.txt,C:\temp\Test**

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
PS> **Get-ChildItem -Path C:\temp\Wired_driver_30.0.1_x64 | .\PowerShar.ps1 -ArchiveName WiredDriver2**

PowerShar accepts input from pipeline as well. 

!!! Do nut use -Recurse for Get-ChildItem as this results in double packing. PowerShar itself already does a recurse)
```
----------------------------------------------------------------------
 PowerShell Archive - 1.0
 Author : github@solar-imperium.com
----------------------------------------------------------------------

ArchiveName     : WiredDriver2
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

Writing PowerShell Archive : .\WiredDriver2.ps1

Finished...
```

PS> **gci -Path C:\temp\Wired_driver_30.0.1_x64 | .\PowerShar.ps1 -ArchiveName WiredDriver -Verbose**

Same as above but with more Verbose output.
```
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

Finished...
```
