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
 convinced that the passphrase you *used* was the one you *wanted*. **Use at your won risk.**

## Example

```console
$ derivation32 ypub6YfAsJGdMwB6pV9eE1Dpa7KwpfYXagJpDh7e6yi1myzwEutoMVu477LQUzyReCocRU3EigHApDYSYfJPMAT8j1FLmZvgD7EQJ68ubL77b4H
ypub6YfAsJGdMwB6pV9eE1Dpa7KwpfYXagJpDh7e6yi1myzwEutoMVu477LQUzyReCocRU3EigHApDYSYfJPMAT8j1FLmZvgD7EQJ68ubL77b4H
m/0 | 3GhPc11bE5hu5CSR6KVqam2tcS1sLR9rAB | 037a2925d9cc2455f2c5f20b2c50cfa41c7b02a17e3bf1840c0c3579c4f4fe9bfe
m/1 | 3EtSyXgk2qRAs4TSy1UQf1QZtu2i169obQ | 029c77ed6cbe722c9f1b031190999a8f1e52446976bc1315b41efeb0fb61f15815
m/2 | 3EeyKYEMcTrVAZo8vHCTHDjN5fVnRjQtpi | 02404649eb104b7278b408272db3e1842b3478616770a91a3ad23e358aa9e56699
m/3 | 39umhwrWwoGADMKa8QumnC87tBrFerpxFM | 020b326057bf83e052b44cadae5fa15c763ada4ba1c2af2416a7a726126d9e16ce
m/4 | 33Stx25eoDKZTcaRzL5u8MvTRjMo7QL1ow | 020b32841216439f5349f59babc5e53d4416e97e2e19fa92e710c9a843bac89917
m/5 | 35rpXAQWhcXjvr8YXfnXBSzyBBgyDNwTiG | 024b87bb67600cd07313a34455c4e3b94062b22f1180bc53d1ad9abb289cef39e7
m/6 | 3AWJfQXDWmmJJSUrjeAbvSFt2Gw7Y3uqwm | 02ee01d644e0a8357f22b861e752c817cd8d5baaec5b6ab8c2e5fcf574f6608cce
m/7 | 3J7HeTNdu9dHiMvFNjbEZZXVgcEqKNndW2 | 03f6350d75a5d65e966a1d3faa93884d5a399f7cd7f0ee77c017ef04852cafa9af
m/8 | 3EgWkKMRY8XpSkuD8YcezarGWco9YqSGaY | 032d954ac76c6afb5aeebc814a9202bb8669de911cad4b3f02e2cb9b4a4894f1c8
m/9 | 34FzroffJL1B4jXZX6ZVuaaiq6nEn61zVz | 02ffa6af7389e4d05ee663551b0ac31fe0185bbb534080fddcfb5ca7ed06db9d85
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

    This tool optionally receives a range of child number to be showed (including hardened ones
 when possible).

## Help

```shell
derivation32 1.1.0
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
    -s <separator>         Specific character (or string) to separate results

ARGS:
    <DATA>    Address, hexadecimal entropy, extended key or wif key
```

## Recommendation

* **Generation of extended root keys**

    If you don't have a mnemonic and corresponding extended root keys consider using
 [mnemonic39](https://crates.io/crates/mnemonic39)
