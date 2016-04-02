#Some Tools

In this long journey to produce an American 3DS (non-XL) with all my information transferred over, I made a couple of homebrew tools and patches that others may find helpful.

* [**3DSInstallTickets**](https://github.com/yifanlu/3DSSystemTools/tree/master/3DSInstallTickets) lets you import tickets and CIAs into the system. Not really useful now since [FBI](http://gbatemp.net/threads/release-fbi-open-source-cia-installer.386433/) has a much nicer interface and more features.
* [**3DSTransferDevice**](https://github.com/yifanlu/3DSSystemTools/tree/master/3DSTransferDevice) lets you export movable.sed and import SecureInfo and movable.sed. It uses official APIs which does verification checks on the data you’re importing so it is “safer” than manually writing the files to the NAND. Of course, you can still brick your device with this so be careful!
* [**CardboardPatches**](https://github.com/yifanlu/3DSSystemTools/tree/master/CardboardPatches) are the patches I wrote to log and analyze CARDBOARD (especially the local communication stuff that disconnects you from NTR debugger). Not useful to anyone except hackers wanting to continue this work.

Source: [Opening Up CARDBOARD: Crafting an American New 3DS (non-XL)](http://yifan.lu/2015/04/22/opening-up-cardboard-crafting-an-american-new-3ds-non-xl/)
