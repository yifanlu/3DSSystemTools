These are just some of the scripts I wrote while analyzing CARDBOARD. It's mostly 
useless now but the build scripts and function addresses for functions in 
CARDBOARD may be of use to someone some day.

The way these hooks work is that you first connect NTR Debugger to CARDBOARD 
(which can be done only in the first step when CARDBOARD is connected to the 
internet instead of local wireless). You run the various patches (source to 
generate them is also provided) for your analysis.

The hooks are small assembly code snippets that replace the prologue or epilogue 
of function calls making sure to not overwrite too much data and then jumping to 
the space at the end of the .text section that is currently unused. We then write 
our patch code (in C) to that location. Our patch code also makes sure to run the 
instructions we overwrote as well as jump back when it is done.

patches.txt defines all the patches I wrote while analyzing CARDBOARD. Not every 
patch corresponds to a source file though since it was all scratchwork so I didn't 
bother keeping all the sources. If you look at all the commented out code you 
can see the things I've tried.
