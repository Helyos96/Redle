# Redle

Redle is a generic ARPG server software.

## What works (3.21.0c)

* Handshaking and setting up the crypto stuff with the game client.
* Logging in and displaying character list
* ~~Entering world instance~~
* ~~Packet dumping tool~~
* Custom launcher tool

## No downloads

We do not offer prebuilt binaries.

## Building

Redle is cross-platform, although only compilation under Windows and Linux (Ubuntu) have been tested.
Some tools, like the launcher and packet dumper, are Windows-only.

Redle uses [`meson`](https://mesonbuild.com/Quick-guide.html) as its meta-build system. By default, it generates [ninja](https://ninja-build.org/) build files.

### Windows

From the command line (open a "x64 Native Tools Command Prompt"):
```
meson setup builddir
meson compile -C builddir
```

Or, generate Visual Studio solution files:
```
meson setup builddir --backend vs
```

You can then open `builddir/redle.sln`

### Linux

```
meson setup builddir
meson compile -C builddir
```

## Using

* Add the following DNS redirection to your system:
```
127.0.0.1 lon01.login.pathofexile.com
```
* Launch `redle.exe` (make sure `dsa-private.key` is reachable by it)
* Copy `launcher.exe` and `dsa-public.key` to the game's root folder.
* Launch `launcher.exe`
* Select London server (this is tied to lon01.login.pathofexile.com)
