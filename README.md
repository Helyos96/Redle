# Redle

Redle is a generic ARPG server software.

## What works

* Handshaking and setting up the crypto stuff with the game client.
* Logging in and displaying character list

## No downloads

We do not offer prebuilt binaries.

## Building

Dependencies:
* [CryptoPP](https://github.com/weidai11/cryptopp) (tested with v8.7)

Redle is cross-platform, although only compilation under Windows and Linux (Ubuntu) have been tested.
Some tools, like the launcher and packet dumper, are Windows-only.

Redle uses [`meson`](https://mesonbuild.com/Quick-guide.html) as its meta-build system.

## Using

* Add the following DNS redirection to your system:
```
127.0.0.1 lon01.login.pathofexile.com
```
* Launch `redle.exe`
* Copy `launcher.exe` and `dsa-public.key` to the game's root folder.
* Launch `launcher.exe`

