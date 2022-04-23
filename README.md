# Conti-Ransomware
Full source of the Conti Ransomware Including the Locker Files, Will be uploading English Translated Documentation In the future

Have fixed the Queue header file as it was (likely purposefully) corrupted, and was missing several commas and semi colons.  
makes sense to prevent someone form just building the ransomware if they managed to get a hold of the locker files like I have. 
There are other measures taken to prevent the building of the ransomware, 
I believe there is a missing #ifdef statement in one of the header files resulting in a flood of errors from the calls to the 
windows api header files. you will also need a visual studio version capable of using V140_xp build tools.
The latest version of Visual studio to support this was 2017 I believe, as I couldnt get it to build using 2019. 
This Ransomware was originally compiled using Visual Studio 2015 so might be best just to use what they use.
