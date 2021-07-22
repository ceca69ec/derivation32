derivation32
============

**Implementation of [bip-0032](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki)
 in rust for use on command line interface.**

## Advantages

* **Freedom**

    This tool don't have the restrictions that almost all others have. It's capable of derive
 any child in any path that you want, any time you want. But remember: *with great power comes
 great responsibility*.

## Disclaimer

* **Don't trust, verify**

    Compare the results of this tool with others. Verify the implementation (and the tests).

    If encryption is used, test [decryption](https://crates.io/crates/encrypt38) until you are
 convinced that the passphrase you *used* was the one you *wanted*.

    **Use at your won risk.**

## Example

```console
$ derivation32 ypub6ZXGqDMx4DsojFChRekQJdW5w1UW5JaLUrSN7wXUcoDf2egC21Ycq1ostNik2wz9nd48pyEL6n6CxBNap6B56iMyHEBv3ytGugKRUCj9LSP
ypub6ZXGqDMx4DsojFChRekQJdW5w1UW5JaLUrSN7wXUcoDf2egC21Ycq1ostNik2wz9nd48pyEL6n6CxBNap6B56iMyHEBv3ytGugKRUCj9LSP
m/0 | 3AvgNg5V1TkMU7yZZCPTdohzySmBX3Wsnt | 03ea2d750dab0388662ecc142eec8379d52a3fb2c3d03c5a64555a85dff3b34497
m/1 | 3511m3xxtmKjiBJYcKZGyxVSJ7jwNBwAPK | 024940543af2b30e68762feaad32457dc7f0711f01d20e1097bafb7eee47f257d5
m/2 | 3FSwvaEECxQHJgWA6fQeYoYYEAauk7cJSg | 036e7cee3e0e0a951178716fa5e5e7bfb26b7f073fc5daca26ff528c0846cabbb4
m/3 | 33QM6BAorebmxpB35S1Kuo5edwMy7QrhHC | 036c6b4e86ef104fe72725de3508bd041a797728ac83631e927679163ff0fc8c19
m/4 | 35tf6DpuS7iZ2nXH8C6DNawFXz4Br9mqie | 03d93e0c9ab1a4442d73707053a9fa4b56dd14f3d2f79e73d6f181d1ad8783a0e6
m/5 | 3PuaDPqBkHnwHWAufm78UdozMPzj2Ap5qo | 0300e46b582e78f38abb219cb3eb22b386789b1988b829a30b563a9e69b95dce2d
m/6 | 3HmBbbDfgKTxGAGfxy1n1okKudgphwVgym | 025b841819bc7f849d55942392e404899affc1a0b76b9575b3e2dbf0f76cdb5b86
m/7 | 3FdEm4dakmMs4ScSmDmyUbBK3THRWkBBFk | 03cbbfb8922148d2af520a680bbcba42add58f7dc6c403308aedce957a994ff6b2
m/8 | 3Nn995qzzzUwz8mKyjfAozBKb6xX68GBgt | 0255c327c5c4507cb76b961b518d985db340f9b1c19add118171d0ef98254c1964
m/9 | 3EES1qCEGAzXbSNtXcpCZBe5G2u4p9pEC5 | 02b9ca0ff5e63fb59a464ab146612e9d79f8b21bbb2f606283fcbcf7c2f5bb06d1
```

## Features

* **Address**

    Insert an address to show information about it.

    Inform hexadecimal entropy or wif private key to generate address.

    This tool show the respective address of a derived child in the legacy, segwit-nested and
 segwit-native formats according to the version prefix of the informed extended private key.

* **Custom separator**

    Customization of the default separator of information when deriving an extended key.

* **Derivation**

    Receives an extended key and show the derivation on default path (according to version
prefix).

* **Encryption**

    Optional encryption of resulting private keys with bip-0038 standard.

* **Extended keys**

    Show the private and public extended keys of the derived path.

* **Path specification**

    Specify a custom path used to derive the extended key.

* **Range of result**

    This tool optionally receives a range of child numbers to be showed (including hardened ones
 when possible).

## Help

```shell
derivation32 1.1.2
Inform extended key and optional path and/or range to show derivation. Insert
address, hexadecimal entropy or wif private key to show information about it.
Optional range is closed (include start and end). Optionally encrypts private
keys. Default separator of results can be customized.

USAGE:
    derivation32 [OPTIONS] <DATA>

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

OPTIONS:
    -e <passphrase>        Encrypt resulting private keys (bip-0038)
    -p <path>              Path used to derive the extended private key
    -r <range>             Closed range in the form of (1..9h) used on derivation
    -s <separator>         Specify a character (or string) to separate results

ARGS:
    <DATA>    Address, hexadecimal entropy, extended key or wif key
```

## Installation

You have to install [rust](https://www.rust-lang.org/tools/install) and a
 [linker](https://gcc.gnu.org/wiki/InstallingGCC) if you don't already have them.

```shell
$ cargo install derivation32
```

## Recommendation

* **Generation of extended root keys**

    If you don't have a mnemonic and the corresponding extended root keys consider using
 [mnemonic39](https://crates.io/crates/mnemonic39).
