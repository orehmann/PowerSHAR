# PowerSHAR
A PowerShell variant for the *nix shar command.

Sometimes it is hard to transfer binary files (e.g. zip, exe, ... ) to another destination. This because of the lack of file transfer solution or blocking of file types in email solutions.
PowerSHAR acts like the *NIX shar command. It takes a file or folder as input and converts it into a selfcontained powershell script. This script holds the converted files as well as the logic 
to extract/restore the files/folders by simply running the script on the destination system inside a Powershell.

## Examples
PS> PowerShar 
