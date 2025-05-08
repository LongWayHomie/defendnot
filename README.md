
# defendnot

An even funnier way to disable windows defender.
**Razz note:**
**This version has some evasive measures implemented to bypass Windows Defender and some worse AVs there.** Implemented methods for implemented CRT injection:
- String hashing using Djb2,
- Custom function prototypes for function obfuscation
- Custom GetProcAddress
- Custom GetModuleHandle

Defendnot is a successor of [no-defender](https://github.com/es3n1n/no-defender).

![](https://i.imgur.com/VGE8g6a.jpeg)

## How it works
There's a WSC (Windows Security Center) service in Windows which is used by antiviruses to let Windows know that there's some other antivirus in the hood and it should disable Windows Defender.  
This WSC API is undocumented and furthermore requires people to sign an NDA with Microsoft to get its documentation.

The initial implementation of [no-defender](https://github.com/es3n1n/no-defender) used thirdparty code provided by other AVs to register itself in the WSC, while defendnot interacts with WSC directly.

## Limitations

Sadly, to keep this WSC stuff even after reboot, defendnot adds itself to the autorun. Thus, you would need to keep the defendnot binaries on your disk :(

## Usage

```commandline
Usage: defendnot-loader [--help] [--version] [--name VAR] [--disable] [--verbose]

Optional arguments:
  -h, --help      shows help message and exits
  -v, --version   prints version information and exits
  -n, --name      av display name [default: "https://github.com/es3n1n/defendnot"]
  -d, --disable   disable defendnot
  -v, --verbose   verbose logging
```

## Implementation

A more detailed writeup will be coming in a few days.

## Special thanks

* [mrbruh](https://mrbruh.com) for poking me to research this topic
* [pindos](https://github.com/pind0s) for providing their machine for WSC service debugging

## License

Apache-2.0
