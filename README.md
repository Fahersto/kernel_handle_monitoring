This unsigned driver is to be mapped with [kdmapper](https://github.com/z175/kdmapper) on Windows 10 systems. It utilizes a trick (https://www.unknowncheats.me/forum/2350590-post9.html) to register handle operation callbacks from an unsigned driver.

If you a running Windows 7 you can use [DSEFix](https://github.com/hfiref0x/DSEFix) to load your driver and will not need to use this trick because your driver has valid driver object.