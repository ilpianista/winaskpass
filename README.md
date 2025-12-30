[![Crate](https://img.shields.io/crates/v/winaskpass.svg)](https://crates.io/crates/winaskpass)

# winaskpass

A Rust CLI tool that serves as an ssh-askpass helper for WSL (Windows Subsystem for Linux). It securely stores SSH key passphrases in the Windows Credential Manager so you don't have to re-enter them repeatedly.

This project uses PowerShell with embedded C# to call Windows APIs (credui.dll, advapi32.dll) since this runs in WSL.

![](images/winaskpass.png)

## Installation and building

`cargo install` can be used to install in `~/.cargo/bin/`:

```sh
cargo install winaskpass
```

To build from the repository, use:
```sh
git clone https://github.com/ilpianista/winaskpass.git
cd winaskpass
cargo build --release --locked
```

## Setup

To make `ssh` use `winaskpass` set `SSH_ASKPASS=/path/to/winaskpass`.

`SSH_ASKPASS_REQUIRE=force` might be required as well.

## License

MIT
