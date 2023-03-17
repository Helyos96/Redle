# Redle

Redle is a generic ARPG server software.

## What works

Handshaking and setting up the crypto stuff with the game client.

## No downloads

We do not offer prebuilt binaries.

## Building

So far compilation has only been tested on Windows, although the code should be multiplatform.

Redle uses [`meson`](https://mesonbuild.com/Quick-guide.html) as the meta-build system.

You can generate `ninja` build files with it, or VSTUDIO solution files.

## Using

* Edit `C:\Windows\System32\drivers\etc\hosts` and add this line:
```
127.0.0.1 lon01.login.pathofexile.com
```
* Launch `redle.exe`
* Copy `launcher.exe` and `dsa-public.key` to the game's root folder.
* Launch `launcher.exe`

