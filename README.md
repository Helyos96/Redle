# Redle

Redle is a generic ARPG server software.

## What works

Handshaking and setting up the crypto stuff with the game client.

## Building

Note that Redle currently uses Windows APIs so it can only compile on that.
Porting it to multiplatform is on the TODO list.

Redle uses `[meson](https://mesonbuild.com/Quick-guide.html)` as the meta-build system.

You can generate `ninja` build files with it, or VSTUDIO solution files.

## Using

* Edit `C:\Windows\System32\drivers\etc\hosts` and add this line:
```
127.0.0.1 lon01.login.pathofexile.com
```
* Launch `redle.exe`
* Copy `launcher.exe` and `dsa-public.key` to the game's root folder.
* Launch `launcher.exe`

