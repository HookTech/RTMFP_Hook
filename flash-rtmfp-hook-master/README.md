flash-rtmfp-hook
================
WARNING: This project only work with flash player "11.9.900.170" win32 version!

This is a hook dll for analysis the Real-Time Media Flow Protocol(RTMFP) of Adobe Flash Player. If you inject this dll into a flash player, it will log the AES key and all RTMFP packets into a log file named "flash.log" in the current working directory. 

The flash player must be the version of "11.9.900.170 standalone debug". You can download it from http://helpx.adobe.com/flash-player/kb/archived-flash-player-versions.html . 


If you are using Vista or Windows 7, you must disable ASLR(Address Space Load Randomization) first !!!
In order to disable ASLR, you need take one the following actions:

1. Modify the PE Header of that exe file. Take a look at http://www.sunchangming.com/blog/post/4148.html

2. download "Enhanced Mitigation Experience Toolkit" from http://www.microsoft.com/download/, use that tool to disable ASLR globally.

To compile the source code, you should have the "visual studio 2010" installed , and the "Detours Express 3.0" library which can be downloaded from http://research.microsoft.com/en-us/projects/detours/ .

Precompiled binary : http://www.sunchangming.com/files/soft/flashplayer.zip 

