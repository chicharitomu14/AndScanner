# bootimg_tools
unpack, repack, ramdisk

### boot_info
prints information about the boot.img passed to it, including the base address and ramdisk address. This tool prints out everything needed to repack the boot.img correctly.

### split_boot
More commonly known as split_bootimg.pl, this rips apart the boot.img to extract the ramdisk and zImage. It has been modified by me to split the boot.img into a separate folder (specified by the file name of the boot.img passed to it) and to extract the ramdisk into a sub-folder as well (extracts the cpio from the gz and then extracts the actual files from the cpio archive)

### unpack_ramdisk - unpacks the given ramdisk file.
Usage:
```
unpack_ramdisk <ramdiskFile>
```
### repack_ramdisk - repacks the ramdisk from the given directory (found online and modified slightly to take a directory)
Usage:
```
repack_ramdisk <ramdiskDirectory> [outputFile]
```
### mkbootimg
mkbootimg binary that creates a boot.img file from the given ramdisk and zImage. Updated to a version compiled by me to support the --ramdiskaddr option (ramdisk address) so that even nonstandard boot.img's can be repacked correctly (Use with boot_info for best results).
### umkbootimg
included for convenience. Not made by me. Original thread [here](http://forum.xda-developers.com/showthread.php?t=1877807).
### unpack
wrapper script made by me for the umkbootimg binary^ to unpack the boot.img into a separate directory and then unpack the ramdisk into a sub-directory.

## Note: These tools were made for Linux. They may also work on Cygwin, but I have not personally tested them.
