# LuauLayer
Wrapping Lua 5.1 calls to Luau to achieve Luau execution in older versions of ROBLOX
## Requirements
1. [StudPE](http://www.cgsoftlabs.ro/zip/Stud_PE.zip) to patch the client
2. A supported client (only ROBLOX client currently supported is the [August 2007](https://github.com/CloneTrooper1019/Roblox-2007-Client/archive/main.zip) client)

## Installing
1. Download the [latest release here](https://github.com/stan2474/LuauLayer/releases/latest) and move it to the client's folder
2. Open StudPE and drag the client's executable into it
3. Go to the functions page
4. Right click the "Imported Functions" tab and click on the "Add New Import" option
5. Click "Dll Select" and select the ``LuauLayer.dll`` DLL in the client's folder
6. Click "Select func" and select ``import`` (thanks [lure](https://github.com/lrre-foss/lure) for teaching me of this method) 
7. Click "Add to list", then click "ADD" and close StudPE by clicking the "OK" button in the bottom right corner.

## Known bugs
No currently known bugs.
