# ExePatchPreparer

This utility does the busy work in creating the base for a simple an exe patch, getting all the offsets and macros needed and creating a FASM .asm file. You can place your own modifications in the .asm file and compile it to apply the patches.

## Basic Usage

Simply run the tool with the name of your exe (or drag the exe onto the tool) to have the .asm patch file created. You can then modify the .asm file yourself and run the provided simple batch file to execute, or call FASM directly. You'll need the FASM assembler added to your path variables for the batch file to run.

Once you have a .asm file, you'll need to use a tool such as Ghidra and IDA to find addresses you wish to patch. From there, you can place the changes you want into the assembly file.

### Calling your own function

Say you have found a location within an executable where you wish to inject your own code. The example here patches a stretch of code from addresses 0x4af51b to 0x4af521 with a call to our own function. You'd place this code in your .asm file below the patchsetsection for the section the code you're patching resides in. Usually that's the .text section, but it can vary.
```
patchat 0x4af51b
	call YourCustomFunction
patchtill 0x4af521
```
The `patchat` and `patchtill` macros marks the segment you wish to overwrite. If the code you provide is shorter than the segment in question, `NOP` instructions will be placed to fill the remaining space. You'll get an error if your code is longer than the space available. 

You'll also need to take care that you aren't breaking the stack or registers that the function you're patching expects to work. One option would be to use a `jmp` to your code and then use a label to return to, so you can jump to your code without affecting the stack, like so:
```
patchat 0x4af51b
	jmp YourCustomFunction
YourFunctionReturn:
patchtill 0x4af521
```
You can place your own code within the created patch section, after the patch_section_start label.
```
YourCustomFunction:
	; just regular fasm assembly, whatever you want goes here
	add dword [ecx+4],2 ;just some random example
	retn
```
If you're using a jmp to access your function, you'd want to replace the return with a jmp back to your label.
### Handy macros

In addition to `patchat` and `patchtill`, there are a number of macros designed to quickly patch certain values. Those are:

```
quickpatchpush address, target ; patches a simple push operation (5 bytes in length) to your own value
quickpatchbyte address, value ; patches a single byte at a specific address
quickpatchshort address, value ; patches a word size value at a specific address
quickpatchint address, value ; patches a dword size value at a specific address
quickpatchlong address, value ; patches a qword size value at a specific address
```