derivation32
============

**Implementation of [bip-0032](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki) in rust for use on command line interface.**

## Advantages

* **Freedom**
    - This tool don't have the restrictions that almost all others have. It's capable of derive any child in any path that you want, any time you want. But remember: *with great power comes great responsibility*.

## Disclaimer

* **Don't trust, verify**
    - Compare the results of this tool with others. Verify the implementation (and the tests).
    - If encryption is used, test [decryption](https://crates.io/crates/encrypt38) until you are convinced that the passphrase you *used* was the one you *wanted*. **Use at your won risk.**

## Features

* **Address**
    - Insert an address to show information about it.
    - Inform hexadecimal entropy or wif private key to generate address.
    - This tool show the respective address of a derived child in the legacy, segwit-nested and segwit-native formats according to the version prefix of the informed extended private key.
 * **Custom separator**
    - Customization of the default separator of information on result.
* **Derivation**
    - Receives an extended private key and show the derivation on default path (according to version prefix).
* **Encryption**
    - Optional encryption of resulting private keys with bip-0038 standard (option `-e <passphrase>`).
* **Extended keys**
    - Show the private and public extended keys of the derived path.
* **Path specification**
    - The option `-p <path>` can be used optionally to specify a custom path used to derive the extended key.
* **Range of result**
    - This tool optionally receives a range of child number to be showed (including hardened ones when is possible).

## Recommendation

* **Build and test**
    - Always use the flag `--release` in `cargo` even for running tests. The encryption algorithm is intended to be heavy on cpu so, without the optimizations of a release build, running the tests will be a slow process. With `--release` all tests are done in seconds.
* **Extended root keys generation**
    - If you don't have mnemonic and corresponding extended root keys consider using [mnemonic39](https://crates.io/crates/mnemonic39)
