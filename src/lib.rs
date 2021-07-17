//! **Implementation of [bip-0032](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki)
//!  in rust for use on command line interface.**
//!
//! ## Advantages
//!
//! * **Freedom**
//!
//!     This tool don't have the restrictions that almost all others have. It's capable of derive
//!  any child in any path that you want, any time you want. But remember: *with great power comes
//!  great responsibility*.
//!
//! ## Disclaimer
//!
//! * **Don't trust, verify**
//!
//!     Compare the results of this tool with others. Verify the implementation (and the tests).
//!
//!     If encryption is used, test [decryption](https://crates.io/crates/encrypt38) until you are
//!  convinced that the passphrase you *used* was the one you *wanted*.
//!
//!     **Use at your won risk.**
//!
//! ## Example
//!
//! ```console
//! $ derivation32 ypub6ZXGqDMx4DsojFChRekQJdW5w1UW5JaLUrSN7wXUcoDf2egC21Ycq1ostNik2wz9nd48pyEL6n6CxBNap6B56iMyHEBv3ytGugKRUCj9LSP
//! ypub6ZXGqDMx4DsojFChRekQJdW5w1UW5JaLUrSN7wXUcoDf2egC21Ycq1ostNik2wz9nd48pyEL6n6CxBNap6B56iMyHEBv3ytGugKRUCj9LSP
//! m/0 | 3AvgNg5V1TkMU7yZZCPTdohzySmBX3Wsnt | 03ea2d750dab0388662ecc142eec8379d52a3fb2c3d03c5a64555a85dff3b34497
//! m/1 | 3511m3xxtmKjiBJYcKZGyxVSJ7jwNBwAPK | 024940543af2b30e68762feaad32457dc7f0711f01d20e1097bafb7eee47f257d5
//! m/2 | 3FSwvaEECxQHJgWA6fQeYoYYEAauk7cJSg | 036e7cee3e0e0a951178716fa5e5e7bfb26b7f073fc5daca26ff528c0846cabbb4
//! m/3 | 33QM6BAorebmxpB35S1Kuo5edwMy7QrhHC | 036c6b4e86ef104fe72725de3508bd041a797728ac83631e927679163ff0fc8c19
//! m/4 | 35tf6DpuS7iZ2nXH8C6DNawFXz4Br9mqie | 03d93e0c9ab1a4442d73707053a9fa4b56dd14f3d2f79e73d6f181d1ad8783a0e6
//! m/5 | 3PuaDPqBkHnwHWAufm78UdozMPzj2Ap5qo | 0300e46b582e78f38abb219cb3eb22b386789b1988b829a30b563a9e69b95dce2d
//! m/6 | 3HmBbbDfgKTxGAGfxy1n1okKudgphwVgym | 025b841819bc7f849d55942392e404899affc1a0b76b9575b3e2dbf0f76cdb5b86
//! m/7 | 3FdEm4dakmMs4ScSmDmyUbBK3THRWkBBFk | 03cbbfb8922148d2af520a680bbcba42add58f7dc6c403308aedce957a994ff6b2
//! m/8 | 3Nn995qzzzUwz8mKyjfAozBKb6xX68GBgt | 0255c327c5c4507cb76b961b518d985db340f9b1c19add118171d0ef98254c1964
//! m/9 | 3EES1qCEGAzXbSNtXcpCZBe5G2u4p9pEC5 | 02b9ca0ff5e63fb59a464ab146612e9d79f8b21bbb2f606283fcbcf7c2f5bb06d1
//! ```
//!
//! ## Features
//!
//! * **Address**
//!
//!     Insert an address to show information about it.
//!
//!     Inform hexadecimal entropy or wif private key to generate address.
//!
//!     This tool show the respective address of a derived child in the legacy, segwit-nested and
//!  segwit-native formats according to the version prefix of the informed extended private key.
//!
//! * **Custom separator**
//!
//!     Customization of the default separator of information when deriving an extended key.
//!
//! * **Derivation**
//!
//!     Receives an extended key and show the derivation on default path (according to version
//! prefix).
//!
//! * **Encryption**
//!
//!     Optional encryption of resulting private keys with bip-0038 standard.
//!
//! * **Extended keys**
//!
//!     Show the private and public extended keys of the derived path.
//!
//! * **Path specification**
//!
//!     Specify a custom path used to derive the extended key.
//!
//! * **Range of result**
//!
//!     This tool optionally receives a range of child numbers to be showed (including hardened
//!  ones when possible).
//!
//! ## Help
//!
//! ```shell
//! derivation32 1.1.1
//! Inform extended key and optional path and/or range to show derivation. Insert
//! address, hexadecimal entropy or wif private key to show information about it.
//! Optional range is closed (include start and end). Optionally encrypts private
//! keys. Default separator of results can be customized.
//!
//! USAGE:
//!     derivation32 [OPTIONS] <DATA>
//!
//! FLAGS:
//!     -h, --help       Prints help information
//!     -V, --version    Prints version information
//!
//! OPTIONS:
//!     -e <passphrase>        Encrypt resulting private keys (bip-0038)
//!     -p <path>              Path used to derive the extended private key
//!     -r <range>             Closed range in the form of (1..9h) used on derivation
//!     -s <separator>         Specify a character (or string) to separate results
//!
//! ARGS:
//!     <DATA>    Address, hexadecimal entropy, extended key or wif key
//! ```
//!
//! ## Recommendation
//!
//! * **Generation of extended root keys**
//!
//!     If you don't have a mnemonic and the corresponding extended root keys consider using
//!  [mnemonic39](https://crates.io/crates/mnemonic39).

use bech32::ToBase32;
use bip38::Encrypt;
use clap::{Arg, ArgMatches};
use hmac::{Hmac, Mac, NewMac};
use ripemd160::Ripemd160;
use secp256k1::{Secp256k1, SecretKey, PublicKey};
use sha2::Digest;

/// Head of user information.
const ABOUT: &str =
"Inform extended key and optional path and/or range to show derivation. Insert
address, hexadecimal entropy or wif private key to show information about it.
Optional range is closed (include start and end). Optionally encrypts private
keys. Default separator of results can be customized.";

/// Default range of 'children' used in derivation if none is specified.
const DEF_RNG: (u32, u32) = (0, 9);

/// Default separator used between results if no other is specified.
const DEF_SEP: &str = " | ";

/// First index of a hardened derivation (first hardened child: 0h).
const HARD_NB: u32 = 0x80000000;

/// Character that denotes a hardened child in the derivation path.
const HARD_CHAR: char = 'h';

/// Minimal number of characters in data argument
const LEN_ARG_MIN: usize = 27;

/// Number of base 58 characters that represent an extended key.
const LEN_XKEY: usize = 111;

/// Maximum base 58 characters in legacy and nested tipe of address (1,3)
const LEN_LEG_MAX: usize = 35;

/// Minimum base 58 characters in legacy and nested tipe of address (1,3).
const LEN_LEG_MIN: usize = 27;

/// Number of characters present in native segwit address.
const LEN_SEGWIT: usize = 42;

/// Number of characters in wif compressed secret key.
const LEN_WIF_C: usize = 52;

/// Number of characters in wif uncompressed secret key.
const LEN_WIF_U: usize = 51;

/// Number of bytes of a public key compressed.
const NBBY_PUBC: usize = 33;

/// Number of bytes of a public key uncompressed.
const NBBY_PUBU: usize = 65;

/// Number of bytes (payload only) contained a decoded wif compressed key.
const NBBY_WIFC: usize = 34;

/// Number of bytes (payload only) contained a decoded wif uncompressed key.
const NBBY_WIFU: usize = 33;

/// Number of bytes of a root key (payload only).
const NBBY_XKEY: usize = 78;

/// Byte of 'OP_0' in the Script language.
const OP_0: u8 = 0x00;

/// Byte to push the next 20 bytes in the Script language.
const OP_PUSH20: u8 = 0x14;

/// First character of all paths.
const PATH_START: &str = "m";

/// Valid prefixes of main net address.
const PRE_ADDR: &str = "13bc";

/// Prefix of all p2wpkh-p2sh address in main net.
const PRE_P2WPKH_P2SH_B: u8 = 0x05;

/// First two possible characters of wif compressed.
const PRE_WIF_C: &str = "KL";

/// First byte of all wif encoded secret keys.
const PRE_WIF_B: u8 = 0x80;

/// First character of wif uncompressed.
const PRE_WIF_U: &str = "5";

/// All valid versions in string representation of private extended keys.
const PRE_PRV_KEY: [&str; 6] = [ "tprv", "uprv", "vprv", "xprv", "yprv", "zprv" ];

/// All valid versions in string representation of public extended keys.
const PRE_PUB_KEY: [&str; 6] = [ "tpub", "upub", "vpub", "xpub", "ypub", "zpub" ];

/// String used as separator on derivation paths.
const SEP_PATH: char = '/';

/// String used as separator of range.
const SEP_RANGE: &str = "..";

/// Test net version of bip-0032 extended private keys.
const TPRV: [u8; 4] = [0x04, 0x35, 0x83, 0x94];

/// Test net version of bip-0032 extended public keys.
const TPUB: [u8; 4] = [0x04, 0x35, 0x87, 0xcf];

/// Test net version of bip-0049 extended private keys.
const UPRV: [u8; 4] = [0x04, 0x4a, 0x4e, 0x28];

/// Test net version of bip-0049 extended public keys.
const UPUB: [u8; 4] = [0x04, 0x4a, 0x52, 0x62];

/// Test net version of bip-0084 extended private keys.
const VPRV: [u8; 4] = [0x04, 0x5f, 0x18, 0xbc];

/// Test net version of bip-0084 extended public keys.
const VPUB: [u8; 4] = [0x04, 0x5f, 0x1c, 0xf6];

/// Main net version of bip-0032 extended private keys.
const XPRV: [u8; 4] = [0x04, 0x88, 0xad, 0xe4];

/// Main net version of bip-0032 extended public keys.
const XPUB: [u8; 4] = [0x04, 0x88, 0xb2, 0x1e];

/// Main net version of bip-0049 extended private keys.
const YPRV: [u8; 4] = [0x04, 0x9d, 0x78, 0x78];

/// Main net version of bip-0049 extended public keys.
const YPUB: [u8; 4] = [0x04, 0x9d, 0x7c, 0xb2];

/// Main net version of bip-0084 extended private keys.
const ZPRV: [u8; 4] = [0x04, 0xb2, 0x43, 0x0c];

/// Main net version of bip-0084 extended public keys.
const ZPUB: [u8; 4] = [0x04, 0xb2, 0x47, 0x46];

/// Error types of 'derivation' project.
#[derive(Clone, Debug, Eq, Hash, PartialEq, PartialOrd)]
#[doc(hidden)]
pub enum Error {
    /// Invalid address is received.
    Address,
    /// Invalid argument length.
    Argument(String),
    /// Invalid base 58 string encountered.
    Base58,
    /// Invalid bench32 data is found.
    Bech32,
    /// Wrapper for errors of 'bip38' dependency.
    Bip38(bip38::Error),
    /// Invalid checksum encountered.
    Checksum,
    /// Found invalid option in the current context.
    Context(String),
    /// Invalid attempt to derive a hardened child from extended public key.
    FromHard,
    /// Invalid hexadecimal value represented in string.
    HexStr,
    /// Invalid input in hmac function.
    Hmac,
    /// Key with invalid length found.
    KeyLen,
    /// Invalid key version (as prefix) found.
    KeyVer,
    /// Invalid number of public key bytes.
    NbPubB(usize),
    /// Not found data to process
    NotFound,
    /// Invalid derivation path string.
    Path(String),
    /// Invalid private data found.
    PrvData,
    /// Invalid public data found.
    PubData,
    /// Invalid range was found.
    Range(String),
    /// Invalid secret entropy found (could not generate address).
    SecEnt,
    /// Invalid wif secret key.
    WifKey,
}

/// Structure to represent a extended private key.
#[derive(Clone, Copy, Debug, PartialEq)]
struct ExtPrvKey {
    pub version: [u8; 4],
    pub depth: u8,
    pub parentf: [u8; 4],
    pub childnb: u32,
    pub chaincd: [u8; 32],
    pub prvdata: [u8; 32], // ignores '0x00' prefix of all private data
    pub purpose: u32
}

/// Structure to represent a extended public key.
#[derive(Clone, Copy, Debug, PartialEq)]
struct ExtPubKey {
    pub version: [u8; 4],
    pub depth: u8,
    pub parentf: [u8; 4],
    pub childnb: u32,
    pub chaincd: [u8; 32],
    pub pubdata: [u8; 33],
    pub purpose: u32
}

/// Functions to manipulate data in form of arbitrary number of bytes [u8].
trait BytesManipulation {
    /// Encode informed data in base 58 check.
    fn encode_base58ck(&self) -> String;

    /// Sha256 and ripemd160 in sequence.
    fn hash160(&self) -> [u8; 20];

    /// Receives an arbitrary number of bytes and return 32 bytes of a double sha256 hash.
    fn hash256(&self) -> [u8; 32];

    /// Receives bytes and return string of hexadecimal characters.
    fn hex_string(&self) -> String;

    /// Create an p2wpkh address according to inserted public key bytes.
    fn p2wpkh(&self) -> Result<String, Error>;
}

/// Function to manipulate derivation path in form of [u32].
trait PathManipulation {
    /// Transform a path in a form of u32 values into a string of type 'm/0...'
    fn encode_path(&self) -> String;
}

/// Functions to manipulate private keys in 32 bytes.
trait PrivateKeyManipulation {
    /// Generate a secret key represented in wif format.
    fn encode_wif(&self, compress: bool) -> Result<String, Error>;

    /// Generate secp256k1 point based on target secret key.
    fn public_key(&self, compress: bool) -> Result<Vec<u8>, Error>;

}

/// Functions to manipulate compressed public keys (33 bytes).
trait PublicKeyCompressedManipulation {
    /// Generate an segwit address of a compressed public key.
    fn segwit_p2wpkh(&self) -> Result<String, Error>;

    /// Generate an segwit address according to informed compressed public key.
    fn segwit_p2wpkh_p2sh(&self) -> Result<String, Error>;
}

/// Functions to manipulate strings in various occasions.
trait StringManipulation {
    /// Decode an address into bytes (payload only).
    fn decode_address(&self) -> Result<Vec<u8>, Error>;

    /// Decode target base 58 string into bytes (payload only).
    fn decode_base58ck(&self) -> Result<Vec<u8>, Error>;

    /// Migrate from a bech 32 string to a vector of bytes (payload only).
    fn decode_bech32(&self) -> Result<Vec<u8>, Error>;

    /// Decode a secret key encoded in base 58 and return bytes compression.
    fn decode_wif(&self) -> Result<([u8; 32], bool), Error>;

    /// Transform string of hexadecimal characters into a vector of bytes.
    fn hex_bytes(&self) -> Result<Vec<u8>, Error>;

    /// Show information about target secret hexadecimal entropy.
    fn info_entropy(&self, pass: &str, separator: &str) -> Result<(), Error>;

    /// Show information about informed wif secret key.
    fn info_wif(&self, pass: &str, separator: &str) -> Result<(), Error>;

    /// Test if an string of arbitrary length contains only hexadecimal chars.
    fn is_hex(&self) -> bool;

    /// Transform a path string into u32 vector of corresponding values.
    fn decode_path(&self, public: bool) -> Result<Vec<u32>, Error>;

    /// Transform a range of the type '0..9' into values (inclusive).
    fn decode_range(&self) -> Result<(u32, u32), Error>;
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
            Error::Address => write!(f, "invalid address"),
            Error::Argument(a) => write!(f, "invalid argument: '\x1b[33m{}\x1b[m'", a),
            Error::Base58 => write!(f, "invalid base 58 string"),
            Error::Bech32 => write!(f, "invalid bench32 string"),
            Error::Bip38(err) => write!(f, "{}", err),
            Error::Checksum => write!(f, "invalid checksum"),
            Error::Context(o) =>
                write!(f, "option '\x1b[33m{}\x1b[m' invalid in this context (aborted)", o),
            Error::FromHard => write!(f, "cannot derive hardened from public"),
            Error::HexStr => write!(f, "invalid hexadecimal string"),
            Error::Hmac => write!(f, "invalid input in hmac"),
            Error::KeyLen => write!(f, "invalid key length"),
            Error::KeyVer => write!(f, "invalid key version (prefix)"),
            Error::NbPubB(nb) =>
                write!(f, "invalid number of bytes in the public key: '\x1b[33m{}\x1b[m'", nb),
            Error::NotFound => write!(f, "data to process not found"),
            Error::Path(v) => write!(f, "invalid path value: '\x1b[33m{}\x1b[m'", v),
            Error::PrvData => write!(f, "invalid private data"),
            Error::PubData => write!(f, "invalid public data"),
            Error::Range(r) => write!(f, "invalid range value: '\x1b[33m{}\x1b[m'", r),
            Error::SecEnt => write!(f, "invalid secret entropy"),
            Error::WifKey => write!(f, "invalid wif secret key")
        }
    }
}

impl From<bip38::Error> for Error {
    fn from(err: bip38::Error) -> Self {
        Error::Bip38(err)
    }
}

/// Implementation of trait BytesManipulation.
impl BytesManipulation for [u8] {
    #[inline]
    fn encode_base58ck(&self) -> String {
        let mut decoded: Vec<u8> = self.to_vec();
        decoded.append(&mut decoded.hash256()[..4].to_vec());
        bs58::encode(decoded).into_string()
    }

    #[inline]
    fn hash160(&self) -> [u8; 20] {
        let mut result = [0x00; 20];
        result[..].copy_from_slice(&Ripemd160::digest(&sha2::Sha256::digest(self)));
        result
    }

    #[inline]
    fn hash256(&self) -> [u8; 32] {
        let mut result = [0x00; 32];
        result[..].copy_from_slice( &sha2::Sha256::digest(&sha2::Sha256::digest(self)));
        result
    }

    #[inline]
    fn hex_string(&self) -> String {
        let mut result = String::new();
        for byte in self {
            result = format!("{}{:02x}", result, byte);
        }
        result
    }

    #[inline]
    fn p2wpkh(&self) -> Result<String, Error> {
        if self.len() != NBBY_PUBC && self.len() != NBBY_PUBU {
            return Err(Error::NbPubB(self.len()));
        }
        let mut address_bytes = vec![0x00]; // version prefix
        address_bytes.append(&mut self.hash160().to_vec());
        Ok(address_bytes.encode_base58ck())
    }
}

/// Implementation of enum Error.
impl Error {
    /// Retrieve the status code to be showed when exiting because of an error.
    #[doc(hidden)]
    pub fn status(&self) -> i32 {
        match self {
            Error::Address => 1,
            Error::Argument(_) => 2,
            Error::Base58 => 3,
            Error::Bech32 => 4,
            Error::Bip38(_) => 5,
            Error::Checksum => 6,
            Error::Context(_) => 7,
            Error::FromHard => 8,
            Error::HexStr => 9,
            Error::Hmac => 10,
            Error::KeyLen => 11,
            Error::KeyVer => 12,
            Error::NbPubB(_) => 13,
            Error::NotFound => 14,
            Error::Path(_) => 15,
            Error::PrvData => 16,
            Error::PubData => 17,
            Error::Range(_) => 18,
            Error::SecEnt => 19,
            Error::WifKey => 20
        }
    }
}

/// Implementation of the structure ExtPrvKey.
impl ExtPrvKey {
    /// Return the extended private key as base 58 check string representation.
    fn as_bs58ck_prv(&self) -> String {
        let mut result = [0x00; 82];
        result[..NBBY_XKEY].copy_from_slice(&self.bytes_prv());
        result[NBBY_XKEY..].copy_from_slice(&self.bytes_prv().hash256()[..4]);
        bs58::encode(result).into_string()
    }

    /// Return the extended private key as bytes.
    fn bytes_prv(&self) -> [u8; 78] {
        let mut result = [0x00; 78];
        result[..4].copy_from_slice(&self.version);
        result[4] = self.depth;
        result[5..9].copy_from_slice(&self.parentf);
        result[9..13].copy_from_slice(&self.childnb.to_be_bytes());
        result[13..45].copy_from_slice(&self.chaincd);
        result[45] = 0x00;
        result[46..].copy_from_slice(&self.prvdata);
        result
    }

    /// Private to private child key derivation.
    fn ckd_prv(&self, childnb: &u32) -> Result<ExtPrvKey, Error> {
        let mut hmac = Hmac::<sha2::Sha512>::new_from_slice(&self.chaincd)
            .map_err(|_| Error::Hmac)?;

        if childnb >= &HARD_NB {
            hmac.update(&[0x00]); // zeroed first byte of all private data
            hmac.update(&self.prvdata);
        } else {
            hmac.update(&self.prvdata.public_key(true)?);
        }

        hmac.update(&childnb.to_be_bytes());

        let r_hmac = hmac.finalize().into_bytes();
        let mut sk = SecretKey::from_slice(&r_hmac[..32]).map_err(|_| Error::SecEnt)?;

        sk.add_assign(&self.prvdata).map_err(|_| Error::SecEnt)?;

        let (mut parentf, mut chaincd, mut prvdata) = ([0x00; 4], [0x00; 32], [0x00; 32]);

        parentf[..].copy_from_slice(&self.prvdata.public_key(true)?.hash160()[..4]);
        chaincd[..].copy_from_slice(&r_hmac[32..]);
        prvdata[..].copy_from_slice(&sk[..]);

        Ok(
            Self {
                version: self.version,
                depth: self.depth + 1,
                parentf,
                childnb: *childnb,
                chaincd,
                prvdata,
                purpose: self.purpose
            }
        )
    }

    /// Derive the extended private key according to informed path.
    fn derive_prv(&self, path: &[u32]) -> Result<ExtPrvKey, Error> {
        let mut derived = *self;
        for cnb in path {
            derived = derived.ckd_prv(cnb)?;
        }
        Ok(derived)
    }

    /// Transform a crude vector of bytes in the structure ExtPrvKey (checked).
    fn from_bs58_prv(prvk: &str) -> Result<Self, Error> {
        if prvk.len() < 4 || !prvk.is_char_boundary(4) || !PRE_PRV_KEY.contains(&(&prvk[..4])) {
            return Err(Error::KeyVer);
        } else if prvk.len() != LEN_XKEY {
            return Err(Error::KeyLen);
        }
        let prvk = prvk.decode_base58ck()?;

        if prvk.len() != NBBY_XKEY { return Err(Error::KeyLen); }
        if prvk[45] != 0 { return Err(Error::PrvData); }

        let (mut version, mut parentf, mut childnb, mut chaincd, mut prvdata) =
            ([0x00; 4], [0x00; 4], [0x00; 4], [0x00; 32], [0x00; 32]);
        version[..].copy_from_slice(&prvk[..4]);
        parentf[..].copy_from_slice(&prvk[5..9]);
        childnb[..].copy_from_slice(&prvk[9..13]);
        chaincd[..].copy_from_slice(&prvk[13..45]);
        prvdata[..].copy_from_slice(&prvk[46..]);

        Ok(
            Self {
                version,
                depth: prvk[4],
                parentf,
                childnb: u32::from_be_bytes(childnb),
                chaincd,
                prvdata,
                purpose: if prvk[..4] == TPRV || prvk[..4] == XPRV {
                    44
                } else if prvk[..4] == UPRV || prvk[..4] == YPRV {
                    49
                } else { // trusts in the first if
                    84
                }
            }
        )
    }

    /// Show derivation of the extended private key in command line interface.
    fn show_prv(
        &self,
        path: &[u32],
        range: (u32, u32),
        pass: &str,
        separator: &str
    ) -> Result<(), Error> {
        let base_path_str = path.encode_path();
        let parent = self.derive_prv(path)?;

        println!("{}\n{}", parent.as_bs58ck_prv(), ExtPubKey::from_prv(&parent)?.as_bs58ck_pub());

        let encrypt = !pass.is_empty();

        // + 1 to reach possible last child and be close range maintaining u32
        for child_nb in range.0..range.1 + 1 {
            let child_prv = parent.derive_prv(&[child_nb])?;
            let child_pub = ExtPubKey::from_prv(&child_prv)?;
            let address = match child_prv.purpose {
                44 => child_pub.pubdata.p2wpkh()?,
                49 => child_pub.pubdata.segwit_p2wpkh_p2sh()?,
                84 => child_pub.pubdata.segwit_p2wpkh()?,
                _ => String::from("please, don't")
            };
            let prv_str = if encrypt {
                child_prv.prvdata.encrypt(pass, true)?
            } else {
                child_prv.prvdata.encode_wif(true)?
            };
            println!(
                "{}/{}{}{}{}{}{}{}",
                base_path_str,
                child_nb,
                separator,
                address,
                separator,
                child_pub.pubdata.hex_string(),
                separator,
                prv_str
            );
        }
        Ok(())
    }
}

/// Implementation of the structure ExtPubKey.
impl ExtPubKey {
    /// Return the extended public key represented as a base 58 check string.
    fn as_bs58ck_pub(&self) -> String {
        let mut result = [0x00; 82];
        result[..NBBY_XKEY].copy_from_slice(&self.bytes_pub());
        result[NBBY_XKEY..].copy_from_slice(&self.bytes_pub().hash256()[..4]);
        bs58::encode(result).into_string()
    }

    /// Return the extended public key as bytes.
    fn bytes_pub(&self) -> [u8; 78] {
        let mut result = [0x00; 78];
        result[..4].copy_from_slice(&self.version);
        result[4] = self.depth;
        result[5..9].copy_from_slice(&self.parentf);
        result[9..13].copy_from_slice(&self.childnb.to_be_bytes());
        result[13..45].copy_from_slice(&self.chaincd);
        result[45..].copy_from_slice(&self.pubdata);
        result
    }

    /// Public to public key derivation.
    fn ckd_pub(&self, childnb: &u32) -> Result<ExtPubKey, Error> {
        if childnb >= &HARD_NB { return Err(Error::FromHard); }

        let mut hmac = Hmac::<sha2::Sha512>::new_from_slice(&self.chaincd)
            .map_err(|_| Error::Hmac)?;

        hmac.update(&self.pubdata);
        hmac.update(&childnb.to_be_bytes());

        let r_hmac = hmac.finalize().into_bytes();
        let mut pubk = PublicKey::from_slice(&self.pubdata).map_err(|_| Error::PubData)?;

        pubk.add_exp_assign(
            &Secp256k1::new(),
            &SecretKey::from_slice(&r_hmac[..32])
                .map_err(|_| Error::SecEnt)?[..]
        ).map_err(|_| Error::SecEnt)?;

        let (mut parentf, mut chaincd) = ([0x00; 4], [0x00; 32]);
        parentf[..].copy_from_slice(&self.pubdata.hash160()[..4]);
        chaincd[..].copy_from_slice(&r_hmac[32..]);

        Ok(
            Self {
                version: self.version,
                depth: self.depth + 1,
                parentf,
                childnb: *childnb,
                chaincd,
                pubdata: pubk.serialize(),
                purpose: self.purpose
            }
        )
    }

    /// Derive the extended public key according to valid informed path.
    fn derive_pub(&self, path: &[u32]) -> Result<ExtPubKey, Error> {
        let mut derived = *self;
        for child_nb in path {
            derived = derived.ckd_pub(child_nb)?;
        }
        Ok(derived)
    }

    /// Transform a crude vector of bytes in the structure ExtPubKey (checked).
    fn from_bs58_pub(pubk: &str) -> Result<Self, Error> {
        if pubk.len() < 4 || !pubk.is_char_boundary(4) ||
            !PRE_PUB_KEY.contains(&(&pubk[..4])) {
            return Err(Error::KeyVer);
        } else if pubk.len() != LEN_XKEY {
            return Err(Error::KeyLen);
        }
        let pubk = pubk.decode_base58ck()?;
        if pubk.len() != NBBY_XKEY { return Err(Error::KeyLen); }

        let (mut version, mut parentf, mut childnb, mut chaincd, mut pubdata) =
            ([0x00; 4], [0x00; 4], [0x00; 4], [0x00; 32], [0x00; NBBY_PUBC]);
        version[..].copy_from_slice(&pubk[..4]);
        parentf[..].copy_from_slice(&pubk[5..9]);
        childnb[..].copy_from_slice(&pubk[9..13]);
        chaincd[..].copy_from_slice(&pubk[13..45]);
        pubdata[..].copy_from_slice(&pubk[45..]);

        Ok(
            Self {
                version,
                depth: pubk[4],
                parentf,
                childnb: u32::from_be_bytes(childnb),
                chaincd,
                pubdata,
                purpose: if pubk[..4] == TPUB || pubk[..4] == XPUB {
                    44
                } else if pubk[..4] == UPUB || pubk[..4] == YPUB {
                    49
                } else { // trusts in the first if
                    84
                }
            }
        )
    }

    /// Derive a extended public key from a private one.
    fn from_prv(prv: &ExtPrvKey) -> Result<ExtPubKey, Error> {
        let mut pubdata = [0x00; NBBY_PUBC];
        pubdata[..].copy_from_slice(&prv.prvdata.public_key(true)?);
        Ok(
            ExtPubKey {
                version: match prv.version {
                    TPRV => TPUB,
                    UPRV => UPUB,
                    VPRV => VPUB,
                    XPRV => XPUB,
                    YPRV => YPUB,
                    ZPRV => ZPUB,
                    _ => XPUB
                },
                depth: prv.depth,
                parentf: prv.parentf,
                childnb: prv.childnb,
                chaincd: prv.chaincd,
                pubdata,
                purpose: prv.purpose
            }
        )
    }

    /// Show derivation of the extended public key based on path and range.
    fn show_pub(&self, path: &[u32], range: (u32, u32), separator: &str) -> Result<(), Error> {
        if range.0 >= HARD_NB || range.1 >= HARD_NB { return Err(Error::FromHard); }
        let base_path_str = path.encode_path();
        let parent = self.derive_pub(path)?;
        println!("{}", parent.as_bs58ck_pub());
        for child_nb in range.0..range.1 + 1{
            let child = parent.derive_pub(&[child_nb])?;
            let address = match child.purpose {
                44 => child.pubdata.p2wpkh()?,
                49 => child.pubdata.segwit_p2wpkh_p2sh()?,
                84 => child.pubdata.segwit_p2wpkh()?,
                _ => String::from("please, don't")
            };

            println!(
                "{}/{}{}{}{}{}",
                base_path_str,
                child_nb,
                separator,
                address,
                separator,
                child.pubdata.hex_string()
            );
        }
        Ok(())
    }
}

/// Implementation of trait PathManipulation.
impl PathManipulation for [u32] {
    #[inline]
    fn encode_path(&self) -> String {
        if self.is_empty() { return String::from(PATH_START) }
        let mut encoded_path = String::from(PATH_START);
        for value in self {
            let child = if value < &HARD_NB {
                format!("{}", value)
            } else {
                format!("{}{}", value - HARD_NB, HARD_CHAR)
            };
            encoded_path += &format!("{}{}", SEP_PATH, child);
        }
        encoded_path
    }
}

/// Implementation of trait PrivateKeyManipulation.
impl PrivateKeyManipulation for [u8; 32] {
    #[inline]
    fn encode_wif(&self, compress: bool) -> Result<String, Error> {
        let mut decoded: Vec<u8> = vec![PRE_WIF_B];
        decoded.append(&mut self.to_vec());
        if compress { decoded.push(0x01); }
        Ok(decoded.encode_base58ck())
    }

    #[inline]
    fn public_key(&self, compress: bool) -> Result<Vec<u8>, Error> {
        let secp_pub = PublicKey::from_secret_key(
            &Secp256k1::new(),
            &SecretKey::from_slice(self).map_err(|_| Error::SecEnt)?
        );
        if compress {
            Ok(secp_pub.serialize().to_vec())
        } else {
            Ok(secp_pub.serialize_uncompressed().to_vec())
        }
    }
}

/// Implementation of trait PublicKeyCompressedManipulation.
impl PublicKeyCompressedManipulation for [u8; NBBY_PUBC] {
    #[inline]
    fn segwit_p2wpkh(&self) -> Result<String, Error> {
        // segwit version prefix has to be inserted as 5 bit unsigned integer
        let mut decoded_u5 = vec![bech32::u5::try_from_u8(0x00).map_err(|_| Error::Bech32)?];
        decoded_u5.append(&mut self.hash160().to_base32());
        let encoded = bech32::encode("bc", decoded_u5, bech32::Variant::Bech32)
            .map_err(|_| Error::Bech32)?;
        Ok(encoded)
    }

    #[inline]
    fn segwit_p2wpkh_p2sh(&self) -> Result<String, Error> {
        let mut redeem_script = vec![OP_0, OP_PUSH20];
        redeem_script.append(&mut self.hash160().to_vec());
        let mut address_bytes = vec![PRE_P2WPKH_P2SH_B];
        address_bytes.append(&mut redeem_script.hash160().to_vec());
        Ok(address_bytes.encode_base58ck())
    }
}

/// Implementation of trait StringManipulation.
impl StringManipulation for str {
    #[inline]
    fn decode_address(&self) -> Result<Vec<u8>, Error> {
        if self.len() == LEN_SEGWIT && self.starts_with("bc") {
            let decoded = self.decode_bech32()?;
            Ok(decoded)
        } else if (self.starts_with('1') || self.starts_with('3')) &&
            self.len() >= LEN_LEG_MIN && self.len() <= LEN_LEG_MAX {
            let decoded = &self.decode_base58ck()?[1..]; // remove version
            Ok(decoded.to_vec())
        } else {
            Err(Error::Address)
        }
    }

    #[inline]
    fn decode_base58ck(&self) -> Result<Vec<u8>, Error> {
        if self.len() < LEN_ARG_MIN { // to protect posterior slicing
            return Err(Error::Argument(String::from(self)));
        }
        let raw = bs58::decode(self).into_vec().map_err(|_| Error::Base58)?;
        if raw[raw.len() - 4..] == raw[..raw.len() - 4].hash256()[..4] {
            Ok(raw[..(raw.len() - 4)].to_vec())
        } else {
            Err(Error::Checksum)
        }
    }

    #[inline]
    fn decode_bech32(&self) -> Result<Vec<u8>, Error> {
        let vec_u5 = match bech32::decode(self) {
            Ok(value) => value.1,
            Err(err) => {
                if err == bech32::Error::InvalidChecksum {
                    return Err(Error::Checksum);
                } else {
                    return Err(Error::Bech32);
                }
            }
        };
        let decoded = bech32::convert_bits(&vec_u5[1..], 5, 8, true)
            .map_err(|_| Error::Bech32)?; // slicing to remove version prefix
        Ok(decoded)
    }

    #[inline]
    fn decode_wif(&self) -> Result<([u8; 32], bool), Error> {
        if (!self.is_char_boundary(1) || !PRE_WIF_C.contains(&self[..1]) ||
            self.len() != LEN_WIF_C) && (!self.starts_with(PRE_WIF_U) ||
            self.len() != LEN_WIF_U) {
            return Err(Error::WifKey);
        }
        let raw_bytes = self.decode_base58ck()?;
        if (raw_bytes.len() != NBBY_WIFC && raw_bytes.len() != NBBY_WIFU) ||
            raw_bytes[0] != PRE_WIF_B {
            return Err(Error::WifKey)
        }
        let mut payload = [0x00; 32];
        payload[..].copy_from_slice(&raw_bytes[1..33]);
        Ok((payload, raw_bytes.len() == NBBY_WIFC))
    }

    #[inline]
    fn hex_bytes(&self) -> Result<Vec<u8>, Error> {
        let mut out = Vec::new();
        for index in (0..self.len()).step_by(2) {
            out.push(u8::from_str_radix(&self[index..index + 2], 16).map_err(|_| Error::HexStr)?);
        }
        Ok(out)
    }

    #[inline]
    fn info_entropy(&self, pass: &str, separator: &str) -> Result<(), Error> {
        if self.len() != 64 { return Err(Error::SecEnt) }
        let mut secret = [0x00; 32];
        secret[..].copy_from_slice(&self.hex_bytes()?);
        let mut pubc = [0x00; NBBY_PUBC];
        pubc[..].copy_from_slice(&secret.public_key(true)?);
        let pubu = secret.public_key(false)?;
        let hex_pubc = pubc.hex_string();
        let secret_str = if pass.is_empty() {
            secret.encode_wif(true)?
        } else {
            secret.encrypt(pass, true)?
        };

        if separator == DEF_SEP {
            println!(
                "{:42}{}{}{}{}\n{:42}{}{}{}{}\n{}{}{}{}{}",
                pubc.p2wpkh()?,
                separator,
                hex_pubc,
                separator,
                secret_str,
                pubc.segwit_p2wpkh_p2sh()?,
                separator,
                hex_pubc,
                separator,
                secret_str,
                pubc.segwit_p2wpkh()?,
                separator,
                hex_pubc,
                separator,
                secret_str
            );
        } else {
            println!(
                "{}{}{}{}{}\n{}{}{}{}{}\n{}{}{}{}{}",
                pubc.p2wpkh()?,
                separator,
                hex_pubc,
                separator,
                secret_str,
                pubc.segwit_p2wpkh_p2sh()?,
                separator,
                hex_pubc,
                separator,
                secret_str,
                pubc.segwit_p2wpkh()?,
                separator,
                hex_pubc,
                separator,
                secret_str
            );
        }

        println!(
            "{}{}{}{}{}",
            pubu.p2wpkh()?,
            separator,
            pubu.hex_string(),
            separator,
            if pass.is_empty() {
                secret.encode_wif(false)?
            } else {
                secret.encrypt(pass, false)?
            }
        );
        Ok(())
    }

    #[inline]
    fn info_wif(&self, pass: &str, separator: &str) -> Result<(), Error> {
        let (secret, compress) = self.decode_wif()?;
        let public = secret.public_key(compress)?;
        let secret = if !pass.is_empty() {
            secret.encrypt(pass, compress)?
        } else {
            String::from(self)
        };

        if compress {
            let hex_pubc = public.hex_string();
            let mut public_comp = [0x00; NBBY_PUBC];
            public_comp[..].copy_from_slice(&public);
            if separator == DEF_SEP {
                println!(
                    "{:42}{}{}{}{}\n{:42}{}{}{}{}\n{}{}{}{}{}",
                    public_comp.p2wpkh()?,
                    separator,
                    hex_pubc,
                    separator,
                    secret,
                    public_comp.segwit_p2wpkh_p2sh()?,
                    separator,
                    hex_pubc,
                    separator,
                    secret,
                    public_comp.segwit_p2wpkh()?,
                    separator,
                    hex_pubc,
                    separator,
                    secret
                );
            } else {
                println!(
                    "{}{}{}{}{}\n{}{}{}{}{}\n{}{}{}{}{}",
                    public_comp.p2wpkh()?,
                    separator,
                    hex_pubc,
                    separator,
                    secret,
                    public_comp.segwit_p2wpkh_p2sh()?,
                    separator,
                    hex_pubc,
                    separator,
                    secret,
                    public_comp.segwit_p2wpkh()?,
                    separator,
                    hex_pubc,
                    separator,
                    secret
                );
            };
        } else {
            println!(
                "{}{}{}{}{}",
                public.p2wpkh()?,
                separator,
                public.hex_string(),
                separator,
                secret
            );
        }
        Ok(())
    }

    #[inline]
    fn is_hex(&self) -> bool {
        for c in self.chars() {
            if !c.is_ascii_hexdigit() {
                return false;
            }
        }
        true
    }

    #[inline]
    fn decode_path(&self, public: bool) -> Result<Vec<u32>, Error> {
        if self.is_empty() || !self.starts_with(PATH_START) {
            return Err(Error::Path(String::from(self)));
        } else if public && self.contains(HARD_CHAR) {
            return Err(Error::FromHard);
        }

        let mut result: Vec<u32> = Vec::new();
        let mut first_m = true; // used to prevent 'm' in the middle of path

        for cnb in self.split_terminator(SEP_PATH) {
            let mut total: u32 = 0;

            if cnb.is_empty() {
                return Err(Error::Path(String::from("//")));
            } else if cnb == PATH_START && first_m {
                first_m = false;
                continue;
            } else if cnb.ends_with(HARD_CHAR) {
                total += match cnb.trim_end_matches(HARD_CHAR).parse::<u32>() {
                    Ok(value) => {
                        if value < HARD_NB {
                            HARD_NB + value //accepts 0 as value
                        } else {
                            return Err(Error::Path(String::from(cnb)))
                        }
                    },
                    Err(_) => return Err(Error::Path(String::from(cnb)))
                };
            } else {
                total = match cnb.parse::<u32>() {
                    Ok(value) => {
                        if value < HARD_NB { // prevent unwanted hardened child
                            value
                        } else {
                            return Err(Error::Path(String::from(cnb)))
                        }
                    },
                    Err(_) => return Err(Error::Path(String::from(cnb)))
                };
            }
            result.push(total);
        }
        Ok(result)
    }

    #[inline]
    fn decode_range(&self) -> Result<(u32, u32), Error> {
        if !self.contains(SEP_RANGE) {
            match self.trim_end_matches(HARD_CHAR).parse::<u32>() {
                Ok(value) => {
                    if self.ends_with(HARD_CHAR) {
                        return Ok((value + HARD_NB, value + HARD_NB))
                    } else {
                        return Ok((value, value))
                    }
                },
                Err(_) => return Err(Error::Range(String::from(self)))
            }
        }

        let (start, stop) = self.split_once(SEP_RANGE)
            .ok_or_else(|| Error::Range(String::from(self)))?;

        if start.ends_with(HARD_CHAR) &&
            !stop.is_empty() && !stop.ends_with(HARD_CHAR) {
            return Err(Error::Range(String::from(stop)))
        }

        let start = match start.parse::<u32>() {
            Ok(value) => {
                if value < HARD_NB {
                    value
                } else {
                    return Err(Error::Range(String::from(start)))
                }
            },
            Err(_) => {
                if start.is_empty() {
                    0
                } else if start.ends_with(HARD_CHAR) {
                    match start.trim_end_matches(HARD_CHAR).parse::<u32>() {
                        Ok(value) => {
                            if value < HARD_NB {
                                value + HARD_NB
                            } else {
                                return Err(Error::Range(String::from(start)))
                            }
                        },
                        Err(_) => return Err(Error::Range(String::from(start)))
                    }
                } else {
                    return Err(Error::Range(String::from(start)))
                }
            }
        };

        let stop = match stop.parse::<u32>() {
            Ok(value) => {
                if value < HARD_NB {
                    value
                } else {
                    return Err(Error::Range(String::from(stop)))
                }
            },
            Err(_) => {
                if stop.is_empty() && start < HARD_NB {
                    HARD_NB - 1
                } else if stop.is_empty() && start >= HARD_NB {
                    u32::MAX
                } else if stop.ends_with(HARD_CHAR) {
                    match stop.trim_end_matches(HARD_CHAR).parse::<u32>() {
                        Ok(value) => {
                            if value < HARD_NB {
                                value + HARD_NB
                            } else {
                                return Err(Error::Range(String::from(stop)))
                            }
                        },
                        Err(_) => return Err(Error::Range(String::from(stop)))
                    }
                } else {
                    return Err(Error::Range(String::from(stop)))
                }
            }
        };

        if start >= stop {
            Err(Error::Range(String::from(self)))
        } else {
            Ok((start, stop))
        }
    }
}

/// Evaluate arguments and execute actions accordingly.
#[doc(hidden)]
pub fn handle_arguments(matches: ArgMatches) -> Result<(), Error> {
    let data = matches.value_of("DATA").ok_or(Error::NotFound)?;
    let passphrase = matches.value_of("passphrase").unwrap_or("");
    let path = matches.value_of("path").unwrap_or("");
    let range = matches.value_of("range").unwrap_or("");
    let rng_t = if range.is_empty() { DEF_RNG } else { range.decode_range()? };
    let separator = matches.value_of("separator").unwrap_or(DEF_SEP);

    if PRE_WIF_C.contains(&data[..1]) || data.starts_with(PRE_WIF_U) {
        if !path.is_empty() {
            return Err(Error::Context(String::from("p")));
        } else if !range.is_empty() {
            return Err(Error::Context(String::from("r")));
        }
        data.info_wif(passphrase, separator)?;
    } else if data.is_hex() && data.len() == 64 {
        if !path.is_empty() {
            return Err(Error::Context(String::from("p")));
        } else if !range.is_empty() {
            return Err(Error::Context(String::from("r")));
        }
        data.info_entropy(passphrase, separator)?;
    } else if PRE_ADDR.contains(&data[..1]) || PRE_ADDR.contains(&data[..2]) {
        if matches.is_present("passphrase") { // protects from empty passphrase
            return Err(Error::Context(String::from("e")));
        } else if !path.is_empty() {
            return Err(Error::Context(String::from("p")));
        } else if !range.is_empty() {
            return Err(Error::Context(String::from("r")));
        } else if matches.is_present("separator") { // protects from " | "
            return Err(Error::Context(String::from("s")));
        }
        println!("{}", data.decode_address()?.hex_string());
    } else if PRE_PRV_KEY.contains(&(&data[..4])) {
        let parent = ExtPrvKey::from_bs58_prv(data)?;
        parent.show_prv(
            &if path.is_empty() { // decisive, default path and flag 'false'
                vec![parent.purpose + HARD_NB, HARD_NB, HARD_NB, 0]
            } else {
                path.decode_path(false)?
            },
            rng_t,
            passphrase,
            separator
        )?;
    } else if PRE_PUB_KEY.contains(&(&data[..4])) {
        if matches.is_present("passphrase") {
            return Err(Error::Context(String::from("e")));
        }
        ExtPubKey::from_bs58_pub(data)?.show_pub(
            &if path.is_empty() { // decisive too
                vec![]
            } else {
                path.decode_path(true)?
            },
            rng_t,
            separator
        )?;
    } else {
        return Err(Error::Argument(String::from(data)));
    }
    Ok(())
}

/// Create the default clap app for the project
#[doc(hidden)]
pub fn init_clap() -> clap::App<'static, 'static> {
    clap::App::new("derivation32")
        .about(ABOUT)
        .arg(
            Arg::with_name("DATA")
                .help("Address, hexadecimal entropy, extended key or wif key")
                .required(true)
                .takes_value(true)
                .validator(validate_data)
        ).arg(
            Arg::with_name("passphrase")
                .help("Encrypt resulting private keys (bip-0038)")
                .short("e")
                .takes_value(true)
        ).arg(
            Arg::with_name("path")
                .help("Path used to derive the extended private key")
                .short("p")
                .takes_value(true)
                .validator(validate_path)
        ).arg(
            Arg::with_name("range")
                .help("Closed range in the form of (1..9h) used on derivation")
                .short("r")
                .takes_value(true)
                .validator(validate_range)
        ).arg(
            Arg::with_name("separator")
                .help("Specify a character (or string) to separate results")
                .short("s")
                .takes_value(true)
        ).version(clap::crate_version!())
}

/// Used in clap to validate the argument 'data'
fn validate_data(data: String) -> Result<(), String> {
    if data.len() >= LEN_ARG_MIN && (data.len() == LEN_WIF_C &&
        data.is_char_boundary(1) && PRE_WIF_C.contains(&data[..1])) ||
        (data.len() == LEN_WIF_U && data.starts_with(PRE_WIF_U)) || // wif key
        data.len() == 64 && data.is_hex() || // hexadecimal entropy
        (data.len() >= LEN_LEG_MIN && data.len() <= LEN_LEG_MAX &&
        data.is_char_boundary(1) && PRE_ADDR.contains(&data[..1])) ||
        (data.len() == LEN_SEGWIT && data.is_char_boundary(2) &&
        PRE_ADDR.contains(&data[..2])) || // address
        data.is_char_boundary(4) && (PRE_PRV_KEY.contains(&(&data[..4]))
        || PRE_PUB_KEY.contains(&(&data[..4]))) && data.len() == LEN_XKEY {
        Ok(()) // last but not least: extended key
    } else {
        Err(String::from("not a hexadecimal entropy, extended key or wif key"))
    }
}

/// Used in clap to validate the option 'path'
fn validate_path(path: String) -> Result<(), String> {
    if path.decode_path(false).is_ok() { Ok(()) } else { Err(path) }
}

/// Used in clap to validate the option 'range'
fn validate_range(range: String) -> Result<(), String> {
    if range.decode_range().is_ok() { Ok(()) } else { Err(range) }
}

/// Tests of the project
#[cfg(test)]
mod tests {
    use super::*;

    /// Result of a double sha256 in 32 '0xff' bytes.
    const DS256_F: [u8; 32] = [
        0x71, 0xca, 0x50, 0x49, 0x66, 0x1b, 0x67, 0xd2, 0xba, 0xba, 0xf3, 0x06, 0xcd, 0x9b, 0xc8,
        0x09, 0x0a, 0x93, 0x32, 0x4c, 0x2d, 0x4f, 0xf1, 0xbb, 0x12, 0xa3, 0x71, 0xa0, 0x2c, 0xc2,
        0x3e, 0xb8
    ];

    /// Result of a double sha256 in 32 '0x69' bytes.
    const DS256_L: [u8; 32] = [
        0xc1, 0x61, 0xd0, 0x98, 0x17, 0x97, 0x65, 0xc7, 0x6b, 0x8a, 0x2e, 0xae, 0xbd, 0xd1, 0xcc,
        0x27, 0x6c, 0xfa, 0x02, 0x72, 0x18, 0xe6, 0x9c, 0x09, 0xb7, 0xa0, 0x94, 0x7e, 0x81, 0xc7,
        0x60, 0x85
    ];

    /// Result of a double sha256 in a '0x00' byte.
    const DS256_Z: [u8; 32] = [
        0x14, 0x06, 0xe0, 0x58, 0x81, 0xe2, 0x99, 0x36, 0x77, 0x66, 0xd3, 0x13, 0xe2, 0x6c, 0x05,
        0x56, 0x4e, 0xc9, 0x1b, 0xf7, 0x21, 0xd3, 0x17, 0x26, 0xbd, 0x6e, 0x46, 0xe6, 0x06, 0x89,
        0x53, 0x9a
    ];

    /// Result from 33 bytes '0x11' inserted in sha256 and after in ripemd160.
    const H160_33_1: [u8; 20] = [
        0x8e, 0xc4, 0xcf, 0x3e, 0xe1, 0x60, 0xb0, 0x54, 0xe0, 0xab, 0xb6, 0xf5, 0xc8, 0x17, 0x7b,
        0x9e, 0xe5, 0x6f, 0xa5, 0x1e
    ];

    /// Result from 33 bytes '0x69' inserted in sha256 and after in ripemd160.
    const H160_33_L: [u8; 20] = [
        0x05, 0x88, 0xa4, 0x7e, 0x70, 0xb0, 0x2d, 0x64, 0x6a, 0xb0, 0x65, 0x80, 0x50, 0x74, 0x66,
        0x25, 0xb0, 0x51, 0x03, 0xc8
    ];

    /// 64 zeros hexadecimal number represented in str format.
    const HEX_STR_0: &str =
        "0000000000000000000000000000000000000000000000000000000000000000";

    /// 64 ones hexadecimal number represented in str format.
    const HEX_STR_1: &str =
        "1111111111111111111111111111111111111111111111111111111111111111";

    /// 2 ^ 256 - 1 represented in a str of hexadecimal characters.
    const HEX_STR_F: &str =
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";

    /// Interesting hexadecimal number represented in str format.
    const HEX_STR_L: &str =
        "6969696969696969696969696969696969696969696969696969696969696969";

    /// Compressed address with secret key of all bytes '0x11'
    const P2WPKH_C_1: &str = "1Q1pE5vPGEEMqRcVRMbtBK842Y6Pzo6nK9";

    /// Compressed address that generated with 'secret' entropy.
    const P2WPKH_C_A: &str = "16JrGhLx5bcBSA34kew9V6Mufa4aXhFe9X";

    /// Compressed address with secret key of all bytes '0x69'.
    const P2WPKH_C_L: &str = "1N7qxowv8SnfdBYhmvpxZxyjsYQDPd88ES";

    /// Segwit p2wpkh-p2sh address with all secret bytes '0x11'.
    const P2WPKH_P2SH_1: &str = "3PFpzMLrKWsphFtc8BesF3MGPnimKMuF4x";

    /// Segwit p2wpkh-p2sh address with 'secret' entropy.
    const P2WPKH_P2SH_A: &str = "34N3tf5m5rdNhW5zpTXNEJucHviFEa8KEq";

    /// Segwit p2wpkh-p2sh address with all secret bytes '0x69'.
    const P2WPKH_P2SH_L: &str = "35E9BxrEWjgHDFWucazLK5VVxH5oGLRj4g";

    /// Uncompressed address generated with entropy of 32 '0x11' bytes.
    const P2WPKH_U_1: &str = "1MsHWS1BnwMc3tLE8G35UXsS58fKipzB7a";

    /// Uncompressed address generated with 'secret' entropy.
    const P2WPKH_U_A: &str = "19P1LctLQmH6tuHCRkv8QznNBGBvFCyKxi";

    /// Uncompressed address generated with entropy of 32 '0x69' bytes.
    const P2WPKH_U_L: &str = "17iS4e5ib2t2Bj2UFjPbxSDdmecHNnCAwy";

    /// m/0 address from extended public key 'XPUB_Z'.
    const P2WPKH_Z_0: &str = "1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA";

    /// m/44h/0h/0h/0/19 address from master root key with zeroed entropy.
    const P2WPKH_Z_19: &str = "19hp5PzFjsD6z1hwMucUbLHAYeYDWdvB1B";

    /// 'Secret' entropy to generate address.
    const P2WPKH_B: [u8; 32] = [
        0xa9, 0x66, 0xeb, 0x60, 0x58, 0xf8, 0xec, 0x9f, 0x47, 0x07, 0x4a, 0x2f, 0xaa, 0xdd, 0x3d,
        0xab, 0x42, 0xe2, 0xc6, 0x0e, 0xd0, 0x5b, 0xc3, 0x4d, 0x39, 0xd6, 0xc0, 0xe1, 0xd3, 0x2b,
        0x8b, 0xdf
    ];

    /// Bytes of compressed public key generated with 'P2PKG_B' secret.
    const PUB_C_A: [u8; NBBY_PUBC] = [
        0x02, 0x3c, 0xba, 0x1f, 0x4d, 0x12, 0xd1, 0xce, 0x0b, 0xce, 0xd7, 0x25, 0x37, 0x37, 0x69,
        0xb2, 0x26, 0x2c, 0x6d, 0xaa, 0x97, 0xbe, 0x6a, 0x05, 0x88, 0xcf, 0xec, 0x8c, 0xe1, 0xa5,
        0xf0, 0xbd, 0x09
    ];

    /// Bytes of compressed public key generated with all bytes '0x11'.
    const PUB_C_1: [u8; NBBY_PUBC] = [
        0x03, 0x4f, 0x35, 0x5b, 0xdc, 0xb7, 0xcc, 0x0a, 0xf7, 0x28, 0xef, 0x3c, 0xce, 0xb9, 0x61,
        0x5d, 0x90, 0x68, 0x4b, 0xb5, 0xb2, 0xca, 0x5f, 0x85, 0x9a, 0xb0, 0xf0, 0xb7, 0x04, 0x07,
        0x58, 0x71, 0xaa
    ];

    /// Bytes of compressed public key generated with all bytes '0x69'.
    const PUB_C_L: [u8; NBBY_PUBC] = [
        0x02, 0x66, 0x6b, 0xdf, 0x20, 0x25, 0xe3, 0x2f, 0x41, 0x08, 0x88, 0x99, 0xf2, 0xbc, 0xb4,
        0xbf, 0x69, 0x83, 0x18, 0x7f, 0x38, 0x0e, 0x72, 0xfc, 0x7d, 0xee, 0x11, 0x5b, 0x1f, 0x99,
        0x57, 0xcc, 0x72
    ];

    /// Bytes of uncompressed public key generated with all bytes '0x11'.
    const PUB_U_1: [u8; NBBY_PUBU] = [
        0x04, 0x4f, 0x35, 0x5b, 0xdc, 0xb7, 0xcc, 0x0a, 0xf7, 0x28, 0xef, 0x3c, 0xce, 0xb9, 0x61,
        0x5d, 0x90, 0x68, 0x4b, 0xb5, 0xb2, 0xca, 0x5f, 0x85, 0x9a, 0xb0, 0xf0, 0xb7, 0x04, 0x07,
        0x58, 0x71, 0xaa, 0x38, 0x5b, 0x6b, 0x1b, 0x8e, 0xad, 0x80, 0x9c, 0xa6, 0x74, 0x54, 0xd9,
        0x68, 0x3f, 0xcf, 0x2b, 0xa0, 0x34, 0x56, 0xd6, 0xfe, 0x2c, 0x4a, 0xbe, 0x2b, 0x07, 0xf0,
        0xfb, 0xdb, 0xb2, 0xf1, 0xc1
    ];

    /// Bytes of uncompressed public key generated with 'P2PKG_B' secret.
    const PUB_U_A: [u8; NBBY_PUBU] = [
        0x04, 0x3c, 0xba, 0x1f, 0x4d, 0x12, 0xd1, 0xce, 0x0b, 0xce, 0xd7, 0x25, 0x37, 0x37, 0x69,
        0xb2, 0x26, 0x2c, 0x6d, 0xaa, 0x97, 0xbe, 0x6a, 0x05, 0x88, 0xcf, 0xec, 0x8c, 0xe1, 0xa5,
        0xf0, 0xbd, 0x09, 0x2f, 0x56, 0xb5, 0x49, 0x2a, 0xdb, 0xfc, 0x57, 0x0b, 0x15, 0x64, 0x4c,
        0x74, 0xcc, 0x8a, 0x48, 0x74, 0xed, 0x20, 0xdf, 0xe4, 0x7e, 0x5d, 0xce, 0x2e, 0x08, 0x60,
        0x1d, 0x6f, 0x11, 0xf5, 0xa4
    ];

    /// Bytes of uncompressed public key generated with all bytes '0x69'.
    const PUB_U_L: [u8; NBBY_PUBU] = [
        0x04, 0x66, 0x6b, 0xdf, 0x20, 0x25, 0xe3, 0x2f, 0x41, 0x08, 0x88, 0x99, 0xf2, 0xbc, 0xb4,
        0xbf, 0x69, 0x83, 0x18, 0x7f, 0x38, 0x0e, 0x72, 0xfc, 0x7d, 0xee, 0x11, 0x5b, 0x1f, 0x99,
        0x57, 0xcc, 0x72, 0x9d, 0xd9, 0x76, 0x13, 0x1c, 0x4c, 0x8e, 0x12, 0xab, 0x10, 0x83, 0xca,
        0x06, 0x54, 0xca, 0x5f, 0xdb, 0xca, 0xc8, 0xd3, 0x19, 0x8d, 0xaf, 0x90, 0xf5, 0x81, 0xb5,
        0x91, 0xd5, 0x63, 0x79, 0xca
    ];

    /// Segwit address generated with secret of all bytes '0x11'
    const SEGW_1: &str = "bc1ql3e9pgs3mmwuwrh95fecme0s0qtn2880lsvsd5";

    /// Segwit address generated with 'secret' number.
    const SEGW_A: &str = "bc1q8gudgnt2pjxshwzwqgevccet0eyvwtswt03nuy";

    /// Segwit address generated with secret of all bytes '0x69'
    const SEGW_L: &str = "bc1qu7nqysur9dr49e4vd9xvguwh5ewzft597d8mc7";

    /// Decoded segwit address generated with secret of all bytes '0x11'
    const SEGW_DEC_1: [u8; 20] = [
        0xfc, 0x72, 0x50, 0xa2, 0x11, 0xde, 0xdd, 0xc7, 0x0e, 0xe5, 0xa2, 0x73, 0x8d, 0xe5, 0xf0,
        0x78, 0x17, 0x35, 0x1c, 0xef
    ];

    /// Decoded segwit address generated with 'secret' number.
    const SEGW_DEC_A: [u8; 20] = [
        0x3a, 0x38, 0xd4, 0x4d, 0x6a, 0x0c, 0x8d, 0x0b, 0xb8, 0x4e, 0x02, 0x32, 0xcc, 0x63, 0x2b,
        0x7e, 0x48, 0xc7, 0x2e, 0x0e
    ];

    /// Decoded segwit address generated with secret of all bytes '0x69'
    const SEGW_DEC_L: [u8; 20] = [
        0xe7, 0xa6, 0x02, 0x43, 0x83, 0x2b, 0x47, 0x52, 0xe6, 0xac, 0x69, 0x4c, 0xc4, 0x71, 0xd7,
        0xa6, 0x5c, 0x24, 0xae, 0x85
    ];

    /// Paths of first test vector of bip-0032.
    const TV_32_01_PATH: [&str; 6] = [
        "m", "m/0h", "m/0h/1", "m/0h/1/2h", "m/0h/1/2h/2", "m/0h/1/2h/2/1000000000"
    ];

    /// Paths of second test vector of bip-0032.
    const TV_32_02_PATH: [&str; 6] = [
        "m", "m/0", "m/0/2147483647h", "m/0/2147483647h/1", "m/0/2147483647h/1/2147483646h",
        "m/0/2147483647h/1/2147483646h/2"
    ];

    /// Paths of third test vector of bip-0032.
    const TV_32_03_PATH: [&str; 2] = ["m", "m/0h"];

    /// Private extended keys of first test vector of bip-0032.
    const TV_32_01_XPRV: [[&str; 2]; 6] = [
        [
            "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kej",
            "MRNNU3TGtRBeJgk33yuGBxrMPHi"
        ],
        [
            "xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT",
            "11eZG7XnxHrnYeSvkzY7d2bhkJ7"
        ],
        [
            "xprv9wTYmMFdV23N2TdNG573QoEsfRrWKQgWeibmLntzniatZvR9BmLnvSxqu53Kw1UmYPxLgboyZQaXwTCg",
            "8MSY3H2EU4pWcQDnRnrVA1xe8fs"
        ],
        [
            "xprv9z4pot5VBttmtdRTWfWQmoH1taj2axGVzFqSb8C9xaxKymcFzXBDptWmT7FwuEzG3ryjH4ktypQSAewR",
            "iNMjANTtpgP4mLTj34bhnZX7UiM"
        ],
        [
            "xprvA2JDeKCSNNZky6uBCviVfJSKyQ1mDYahRjijr5idH2WwLsEd4Hsb2Tyh8RfQMuPh7f7RtyzTtdrbdqqs",
            "unu5Mm3wDvUAKRHSC34sJ7in334"
        ],
        [
            "xprvA41z7zogVVwxVSgdKUHDy1SKmdb533PjDz7J6N6mV6uS3ze1ai8FHa8kmHScGpWmj4WggLyQjgPie1rF",
            "SruoUihUZREPSL39UNdE3BBDu76"
        ]
    ];

    /// Private extended keys of second test vector of bip-0032.
    const TV_32_02_XPRV: [[&str; 2]; 6] = [
        [
            "xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNq",
            "Pqm55Qn3LqFtT2emdEXVYsCzC2U"
        ],
        [
            "xprv9vHkqa6EV4sPZHYqZznhT2NPtPCjKuDKGY38FBWLvgaDx45zo9WQRUT3dKYnjwih2yJD9mkrocEZXo1e",
            "x8G81dwSM1fwqWpWkeS3v86pgKt"
        ],
        [
            "xprv9wSp6B7kry3Vj9m1zSnLvN3xH8RdsPP1Mh7fAaR7aRLcQMKTR2vidYEeEg2mUCTAwCd6vnxVrcjfy2kR",
            "gVsFawNzmjuHc2YmYRmagcEPdU9"
        ],
        [
            "xprv9zFnWC6h2cLgpmSA46vutJzBcfJ8yaJGg8cX1e5StJh45BBciYTRXSd25UEPVuesF9yog62tGAQtHjXa",
            "jPPdbRCHuWS6T8XA2ECKADdw4Ef"
        ],
        [
            "xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcx",
            "FLJ8HFsTjSyQbLYnMpCqE2VbFWc"
        ],
        [
            "xprvA2nrNbFZABcdryreWet9Ea4LvTJcGsqrMzxHx98MMrotbir7yrKCEXw7nadnHM8Dq38EGfSh6dqA9QWT",
            "yefMLEcBYJUuekgW4BYPJcr9E7j"
        ]
    ];

    /// Private extended keys of third test vector of bip-0032.
    const TV_32_03_XPRV: [[&str; 2]; 2] = [
        [
            "xprv9s21ZrQH143K25QhxbucbDDuQ4naNntJRi4KUfWT7xo4EKsHt2QJDu7KXp1A3u7Bi1j8ph3EGsZ9Xvz9",
            "dGuVrtHHs7pXeTzjuxBrCmmhgC6"
        ],
        [
            "xprv9uPDJpEQgRQfDcW7BkF7eTya6RPxXeJCqCJGHuCJ4GiRVLzkTXBAJMu2qaMWPrS7AANYqdq6vcBcBUdJ",
            "CVVFceUvJFjaPdGZ2y9WACViL4L"
        ]
    ];

    /// Public extended keys of first test vector of bip-0032.
    const TV_32_01_XPUB: [[&str; 2]; 6] = [
        [
            "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqs",
            "efD265TMg7usUDFdp6W1EGMcet8"
        ],
        [
            "xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1",
            "bgwQ9xv5ski8PX9rL2dZXvgGDnw"
        ],
        [
            "xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq",
            "527Hqck2AxYysAA7xmALppuCkwQ"
        ],
        [
            "xpub6D4BDPcP2GT577Vvch3R8wDkScZWzQzMMUm3PWbmWvVJrZwQY4VUNgqFJPMM3No2dFDFGTsxxpG5uJh7",
            "n7epu4trkrX7x7DogT5Uv6fcLW5"
        ],
        [
            "xpub6FHa3pjLCk84BayeJxFW2SP4XRrFd1JYnxeLeU8EqN3vDfZmbqBqaGJAyiLjTAwm6ZLRQUMv1ZACTj37",
            "sR62cfN7fe5JnJ7dh8zL4fiyLHV"
        ],
        [
            "xpub6H1LXWLaKsWFhvm6RVpEL9P4KfRZSW7abD2ttkWP3SSQvnyA8FSVqNTEcYFgJS2UaFcxupHiYkro49S8",
            "yGasTvXEYBVPamhGW6cFJodrTHy"
        ]
    ];

    /// Public extended keys of second test vector of bip-0032.
    const TV_32_02_XPUB: [[&str; 2]; 6] = [
        [
            "xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6",
            "mr8BDzTJY47LJhkJ8UB7WEGuduB"
        ],
        [
            "xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDzn",
            "ezpbZb7ap6r1D3tgFxHmwMkQTPH"
        ],
        [
            "xpub6ASAVgeehLbnwdqV6UKMHVzgqAG8Gr6riv3Fxxpj8ksbH9ebxaEyBLZ85ySDhKiLDBrQSARLq1uNRts8",
            "RuJiHjaDMBU4Zn9h8LZNnBC5y4a"
        ],
        [
            "xpub6DF8uhdarytz3FWdA8TvFSvvAh8dP3283MY7p2V4SeE2wyWmG5mg5EwVvmdMVCQcoNJxGoWaU9DCWh89",
            "LojfZ537wTfunKau47EL2dhHKon"
        ],
        [
            "xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY",
            "2grBGRjaDMzQLcgJvLJuZZvRcEL"
        ],
        [
            "xpub6FnCn6nSzZAw5Tw7cgR9bi15UV96gLZhjDstkXXxvCLsUXBGXPdSnLFbdpq8p9HmGsApME5hQTZ3emM2",
            "rnY5agb9rXpVGyy3bdW6EEgAtqt"
        ]
    ];

    /// Public extended keys of third test vector of bip-0032.
    const TV_32_03_XPUB: [[&str; 2]; 2] = [
        [
            "xpub661MyMwAqRbcEZVB4dScxMAdx6d4nFc9nvyvH3v4gJL378CSRZiYmhRoP7mBy6gSPSCYk6SzXPTf3ND1",
            "cZAceL7SfJ1Z3GC8vBgp2epUt13"
        ],
        [
            "xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9M",
            "Yo6oDaPPLPxSb7gwQN3ih19Zm4Y"
        ]
    ];

    /// WIF secret key with payload of all bytes '0x11'.
    const WIF_1: &str = "5HwoXVkHoRM8sL2KmNRS217n1g8mPPBomrY7yehCuXC1115WWsh";

    /// WIF secret key with payload of 'secret' entropy.
    const WIF_A: &str = "5K6tjEYPunJtSHRbWLSWtYGXmeFW4UJStKb3RUo5VUqQtksHkze";

    /// WIF secret key with payload of all bytes '0x69'.
    const WIF_L: &str = "5JciBbkdYdjKKE9rwZ7c1XscwwcLBbv9aJyeZeWQi2gZnHeiX57";

    /// WIF compressed secret key with all bytes '0x11'.
    const WIC_1: &str = "KwntMbt59tTsj8xqpqYqRRWufyjGunvhSyeMo3NTYpFYzZbXJ5Hp";

    /// WIF compressed secret key of 'secret' entropy.
    const WIC_A: &str = "L2u1KQma7xyx2bVZJUocvV1Yp3R1GKW1FX3Fh3gNphrgTDVqp1sG";

    /// WIF compressed secret key with all bytes '0x69'.
    const WIC_L: &str = "KzkcmnPaJd7mqT47Rnk9XMGRfW2wfo7ar2M2o6Yoe6Rdgbg2bHM9";

    ///army van defense carry jealous true garbage claim echo media make crunch
    const XPRV_A: [&str; 2] = [
        "xprv9s21ZrQH143K3t4UZrNgeA3w861fwjYLaGwmPtQyPMmzshV2owVpfBSd2Q7YsHZ9j6i6ddYjb5PLtUdMZn8L",
        "hvuCVhGcQntq5rn7JVMqnie"
    ];

    /// Root key generated randomly.
    const XPRV_R: [&str; 2] = [
        "xprv9s21ZrQH143K2maNNY6YGXJZ4yGBEae4Jc4s6pfR6haWQEjLbCa2gBzUyYJS5cQuxPNjTtfBqUC9DPPyXfJV",
        "UgMn6qqmUUDJBtTzqa6rY2w"
    ];

    /// m/1h/2/3h/4/5h/6/7h/8/9' derivation of root key generated randomly.
    const XPRV_R_D: [&str; 2] = [
        "xprvAAVaDKt9qqGMFfrRPXWyL9SVkSsq7QozvfmVh1e9g1A9XZUuYwewdx84fw9iL8YkyzycjB4STWQf9bFuzATG",
        "yZTR7PUB1CLpGRaLUAiGgxH"
    ];

    /// 'XPRV_R' with a non zero value at byte index 45 (invalid in private).
    const XPRV_R_NZ: [&str; 2] = [
        "xprv9s21ZrQH143K2maNNY6YGXJZ4yGBEae4Jc4s6pfR6haWQEjLbCa2gBzV34QbbxYGS4PWd2gF2LN4N4MHgdxt",
        "jcqiixH56CSRZhAiexotiHQ"
    ];

    /// Root key generated with zeroed entropy.
    const XPRV_Z: [&str; 2] = [
        "xprv9s21ZrQH143K3GJpoapnV8SFfukcVBSfeCficPSGfubmSFDxo1kuHnLisriDvSnRRuL2Qrg5ggqHKNVpxR86",
        "QEC8w35uxmGoggxtQTPvfUu"
    ];

    /// Extended public key of 'XPRV_A' with path m/44h/0h/0h/0.
    const XPUB_A: [&str; 2] = [
        "xpub6EdHrjLe1JdwRR6W5romAvmVzk7bfXQWV2N9SuTWP1ebszkLVQMev6KWTNtb2D9mQpocUfAsPQGkE6wtVe8K",
        "ug3dYyA9yCJTnHRPJAbgEAF"
    ];

    /// Extended public key of 'XPRV_R' with path m/44h/0h/0h/0.
    const XPUB_R: [&str; 2] = [
        "xpub6EBARkwLtwz68GAfCSJ8AAqn6gxR2Lw6mJfK23rqDya64GvRT2LHYwDmBVdG5Cazs1Q59gPXj1MNmmL24Vi4",
        "Ce7nmjizMude8mGYqzSbMB8"
    ];

    /// Extended public key of 'XPRV_Z' with path m/44h/0h/0h/0.
    const XPUB_Z: [&str; 2] = [
        "xpub6ELHKXNimKbxMCytPh7EdC2QXx46T9qLDJWGnTraz1H9kMMFdcduoU69wh9cxP12wDxqAAfbaESWGYt5rREs",
        "X1J8iR2TEunvzvddduAPYcY"
    ];

    /// Bytes representation of the private extended key 'army van defense...'
    const XPRV_A_B: [u8; NBBY_XKEY] = [
        0x04, 0x88, 0xad, 0xe4, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xb7, 0x0d,
        0x67, 0x53, 0x23, 0xc4, 0x0e, 0xc4, 0x61, 0xe0, 0xa6, 0xaf, 0x60, 0x3b, 0x1f, 0x13, 0x5f,
        0xb2, 0xaf, 0x9a, 0xe7, 0x53, 0xee, 0xff, 0x18, 0x92, 0x27, 0x32, 0xa7, 0x3b, 0x0f, 0x05,
        0x00, 0xb2, 0xa0, 0xd5, 0x76, 0xb8, 0x28, 0xb5, 0x37, 0x68, 0x8b, 0x56, 0x1f, 0x2c, 0xfa,
        0x8d, 0xac, 0x36, 0x02, 0xd5, 0x4c, 0x62, 0xbd, 0xe6, 0x19, 0xad, 0x53, 0x31, 0xe6, 0xc2,
        0x35, 0xee, 0x26,
    ];

    /// Bytes representation of the private extended key generated randomly.
    const XPRV_R_B: [u8; NBBY_XKEY] = [
        0x04, 0x88, 0xad, 0xe4, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x47, 0x61,
        0x89, 0xa3, 0xed, 0x99, 0xca, 0xf4, 0x0f, 0x7c, 0x9b, 0x88, 0xf1, 0x6d, 0x80, 0x58, 0x92,
        0xc9, 0x26, 0xb7, 0xbf, 0x8e, 0xcf, 0x7b, 0xff, 0x63, 0x2d, 0x7d, 0x40, 0x42, 0xbd, 0x4d,
        0x00, 0xd1, 0x95, 0x7c, 0xc8, 0x92, 0xb0, 0xd4, 0xf0, 0x48, 0x35, 0x65, 0xc4, 0x5c, 0x8c,
        0x4f, 0x2a, 0xe9, 0x46, 0x1c, 0x65, 0xb6, 0x1e, 0x33, 0x76, 0xb5, 0x05, 0xbe, 0x15, 0x6e,
        0xce, 0x5e, 0x3c
    ];

    /// Bytes representation of the private extended key with zeroed entropy.
    const XPRV_Z_B: [u8; NBBY_XKEY] = [
        0x04, 0x88, 0xad, 0xe4, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x79, 0x23,
        0x40, 0x8d, 0xad, 0xd3, 0xc7, 0xb5, 0x6e, 0xed, 0x15, 0x56, 0x77, 0x07, 0xae, 0x5e, 0x5d,
        0xca, 0x08, 0x9d, 0xe9, 0x72, 0xe0, 0x7f, 0x3b, 0x86, 0x04, 0x50, 0xe2, 0xa3, 0xb7, 0x0e,
        0x00, 0x18, 0x37, 0xc1, 0xbe, 0x8e, 0x29, 0x95, 0xec, 0x11, 0xcd, 0xa2, 0xb0, 0x66, 0x15,
        0x1b, 0xe2, 0xcf, 0xb4, 0x8a, 0xdf, 0x9e, 0x47, 0xb1, 0x51, 0xd4, 0x6a, 0xda, 0xb3, 0xa2,
        0x1c, 0xdf, 0x67
    ];

    /// Bytes representation of the extended public key 'XPUB_A'.
    const XPUB_A_B: [u8; NBBY_XKEY] = [
        0x04, 0x88, 0xb2, 0x1e, 0x04, 0x94, 0xb0, 0x09, 0xed, 0x00, 0x00, 0x00, 0x00, 0xca, 0x1a,
        0xc2, 0x0b, 0x6c, 0xbf, 0x6e, 0x45, 0xc3, 0xcf, 0xc2, 0xf2, 0x39, 0x9a, 0x5f, 0xd8, 0x91,
        0xa9, 0x2f, 0xff, 0x52, 0x21, 0xcd, 0xe0, 0x8a, 0x73, 0x98, 0xb5, 0x2d, 0x58, 0x1f, 0xd0,
        0x03, 0x86, 0x36, 0x98, 0x82, 0x77, 0x1a, 0x91, 0xbe, 0xc8, 0xb1, 0xc9, 0xd5, 0x0c, 0x54,
        0x66, 0xfe, 0x04, 0x44, 0xff, 0x76, 0x3e, 0xe0, 0xf7, 0x3b, 0xa0, 0x60, 0xc4, 0x7c, 0x63,
        0x53, 0xbd, 0xf7
    ];

    /// Bytes representation of the extended public key 'XPUB_R'.
    const XPUB_R_B: [u8; NBBY_XKEY] = [
        0x04, 0x88, 0xb2, 0x1e, 0x04, 0x57, 0x66, 0x12, 0xd8, 0x00, 0x00, 0x00, 0x00, 0x83, 0x59,
        0xda, 0xd5, 0x56, 0xc1, 0xf4, 0x3c, 0x23, 0x3f, 0xb4, 0xba, 0x56, 0x55, 0xc1, 0xd6, 0x89,
        0x3b, 0x1f, 0x9d, 0x6d, 0x42, 0x52, 0xdb, 0x18, 0xd3, 0x0f, 0xc7, 0xfe, 0x3c, 0x44, 0xd6,
        0x02, 0xbb, 0xb6, 0xd2, 0x7b, 0x71, 0xb2, 0x6b, 0xf9, 0x23, 0xf9, 0xce, 0xcb, 0x31, 0x3f,
        0x1c, 0xb3, 0x48, 0xda, 0x6a, 0x92, 0xe8, 0xba, 0x7c, 0xa1, 0x70, 0x25, 0x61, 0xb4, 0x62,
        0x00, 0xc0, 0x67
    ];

    /// Bytes representation of the extended public key 'XPUB_Z'.
    const XPUB_Z_B: [u8; NBBY_XKEY] = [
        0x04, 0x88, 0xb2, 0x1e, 0x04, 0x6c, 0xc9, 0xf2, 0x52, 0x00, 0x00, 0x00, 0x00, 0xbc, 0xe8,
        0x0d, 0xd5, 0x80, 0x79, 0x2c, 0xd1, 0x8a, 0xf5, 0x42, 0x79, 0x0e, 0x56, 0xaa, 0x81, 0x31,
        0x78, 0xdc, 0x28, 0x64, 0x4b, 0xb5, 0xf0, 0x3d, 0xbd, 0x44, 0xc8, 0x5f, 0x2d, 0x2e, 0x7a,
        0x03, 0x86, 0xb8, 0x65, 0xb5, 0x2b, 0x75, 0x3d, 0x0a, 0x84, 0xd0, 0x9b, 0xc2, 0x00, 0x63,
        0xfa, 0xb5, 0xd8, 0x45, 0x3e, 0xc3, 0x3c, 0x21, 0x5d, 0x40, 0x19, 0xa5, 0x80, 0x1c, 0x9c,
        0x64, 0x38, 0xb9
    ];

    #[test]
    fn test_as_bs58ck_prv() {
        assert_eq!(
            ExtPrvKey::from_bs58_prv(&XPRV_A.concat()).unwrap().as_bs58ck_prv(),
            XPRV_A.concat()
        );
        assert_eq!(
            ExtPrvKey::from_bs58_prv(&XPRV_R.concat()).unwrap().as_bs58ck_prv(),
            XPRV_R.concat()
        );
        assert_eq!(
            ExtPrvKey::from_bs58_prv(&XPRV_Z.concat()).unwrap().as_bs58ck_prv(),
            XPRV_Z.concat()
        );
        assert_eq!(
            ExtPrvKey::from_bs58_prv(&XPRV_R.concat()).unwrap().derive_prv(
                &"m/1h/2/3h/4/5h/6/7h/8/9h".decode_path(false).unwrap()
            ).unwrap()
            .as_bs58ck_prv(),
            XPRV_R_D.concat()
        );
        assert_ne!(
            ExtPrvKey::from_bs58_prv(&XPRV_Z.concat()).unwrap().as_bs58ck_prv(),
            "error"
        );
    }

    #[test]
    fn test_as_bs58ck_pub() {
        assert_eq!(
            ExtPubKey::from_bs58_pub(&XPUB_A.concat()).unwrap().as_bs58ck_pub(),
            XPUB_A.concat()
        );
        assert_eq!(
            ExtPubKey::from_bs58_pub(&XPUB_R.concat()).unwrap().as_bs58ck_pub(),
            XPUB_R.concat()
        );
        assert_eq!(
            ExtPubKey::from_bs58_pub(&XPUB_Z.concat()).unwrap().as_bs58ck_pub(),
            XPUB_Z.concat()
        );
        assert_ne!(
            ExtPubKey::from_bs58_pub(&XPUB_Z.concat()).unwrap().as_bs58ck_pub(),
            "error"
        );
    }

    #[test]
    fn test_bytes_prv() {
        assert_eq!(
            ExtPrvKey::from_bs58_prv(&XPRV_A.concat()).unwrap().bytes_prv(), XPRV_A_B[..NBBY_XKEY]
        );
        assert_eq!(
            ExtPrvKey::from_bs58_prv(&XPRV_R.concat()).unwrap().bytes_prv(), XPRV_R_B[..NBBY_XKEY]
        );
        assert_eq!(
            ExtPrvKey::from_bs58_prv(&XPRV_Z.concat()).unwrap().bytes_prv(), XPRV_Z_B[..NBBY_XKEY]
        );
    }

    #[test]
    fn test_bytes_pub() {
        assert_eq!(
            ExtPubKey::from_bs58_pub(&XPUB_A.concat()).unwrap().bytes_pub(), XPUB_A_B[..NBBY_XKEY]
        );
        assert_eq!(
            ExtPubKey::from_bs58_pub(&XPUB_R.concat()).unwrap().bytes_pub(), XPUB_R_B[..NBBY_XKEY]
        );
        assert_eq!(
            ExtPubKey::from_bs58_pub(&XPUB_Z.concat()).unwrap().bytes_pub(), XPUB_Z_B[..NBBY_XKEY]
        );
    }

    #[test]
    fn test_ckd_prv() {
        assert!(ExtPrvKey::from_bs58_prv(&XPRV_A.concat()).unwrap().ckd_prv(&0).is_ok());
        assert!(ExtPrvKey::from_bs58_prv(&XPRV_R.concat()).unwrap().ckd_prv(&0).is_ok());
        assert!(ExtPrvKey::from_bs58_prv(&XPRV_Z.concat()).unwrap().ckd_prv(&0).is_ok());
        let mut to_test = ExtPrvKey::from_bs58_prv(&XPRV_A.concat()).unwrap();
        to_test.prvdata = [0xff; 32];
        assert_eq!(to_test.ckd_prv(&0).unwrap_err(), Error::SecEnt);
        to_test.prvdata = [0x00; 32];
        assert_eq!(to_test.ckd_prv(&0).unwrap_err(), Error::SecEnt);
    }

    #[test]
    fn test_ckd_pub() {
        assert!(ExtPubKey::from_bs58_pub(&XPUB_A.concat()).unwrap().ckd_pub(&0).is_ok());
        assert!(ExtPubKey::from_bs58_pub(&XPUB_R.concat()).unwrap().ckd_pub(&0).is_ok());
        assert!(ExtPubKey::from_bs58_pub(&XPUB_Z.concat()).unwrap() .ckd_pub(&0).is_ok());
        let mut to_test = ExtPubKey::from_bs58_pub(&XPUB_A.concat()).unwrap();
        to_test.pubdata = [0xff; 33];
        assert_eq!(to_test.ckd_pub(&0).unwrap_err(), Error::PubData);
        to_test.pubdata = [0x00; 33];
        assert_eq!(to_test.ckd_pub(&0).unwrap_err(), Error::PubData);
    }

    #[test]
    fn test_decode_address() {
        assert!(P2WPKH_C_1.decode_address().is_ok());
        assert!(P2WPKH_C_A.decode_address().is_ok());
        assert!(P2WPKH_C_L.decode_address().is_ok());
        assert!(P2WPKH_P2SH_1.decode_address().is_ok());
        assert!(P2WPKH_P2SH_L.decode_address().is_ok());
        assert!(P2WPKH_U_1.decode_address().is_ok());
        assert!(P2WPKH_U_A.decode_address().is_ok());
        assert!(P2WPKH_U_L.decode_address().is_ok());
        assert_eq!(SEGW_1.decode_address().unwrap(), SEGW_DEC_1);
        assert_eq!(SEGW_A.decode_address().unwrap(), SEGW_DEC_A);
        assert_eq!(SEGW_L.decode_address().unwrap(), SEGW_DEC_L);
        assert_eq!("invalid".decode_address().unwrap_err(), Error::Address);
        assert_eq!("1_invalid".decode_address().unwrap_err(), Error::Address);
        assert_eq!("3_invalid".decode_address().unwrap_err(), Error::Address);
        assert_eq!("bc_invalid".decode_address().unwrap_err(), Error::Address);
        assert_eq!(SEGW_1[..41].decode_address().unwrap_err(), Error::Address);
    }

    #[test]
    fn test_decode_base58ck() {
        assert_eq!(XPRV_A.concat().decode_base58ck().unwrap(), XPRV_A_B);
        assert_eq!(XPRV_R.concat().decode_base58ck().unwrap(), XPRV_R_B);
        assert_eq!(XPRV_Z.concat().decode_base58ck().unwrap(), XPRV_Z_B);
        assert_eq!(["!"; LEN_ARG_MIN].concat().decode_base58ck().unwrap_err(),Error::Base58);
        assert_eq!(
            ["a"; LEN_ARG_MIN - 1].concat().decode_base58ck().unwrap_err(),
            Error::Argument(String::from(["a"; LEN_ARG_MIN - 1].concat()))
        );
        assert_eq!(
            XPRV_A.concat().replace("a", "A").decode_base58ck().unwrap_err(),
            Error::Checksum
        );
    }

    #[test]
    fn test_decode_bech32() {
        assert_eq!(SEGW_1.decode_bech32().unwrap(), SEGW_DEC_1);
        assert_eq!(SEGW_A.decode_bech32().unwrap(), SEGW_DEC_A);
        assert_eq!(SEGW_L.decode_bech32().unwrap(), SEGW_DEC_L);
        assert_eq!(SEGW_L.replace("7", "0").decode_bech32().unwrap_err(), Error::Checksum);
        assert_eq!(SEGW_L.replace("7", "!").decode_bech32().unwrap_err(), Error::Bech32);
    }

    #[test]
    fn test_decode_path() {
        assert!(PATH_START.decode_path(false).is_ok());
        assert!("m/0h/0".decode_path(true).is_err());
        assert!("m/0/1h/9/2147483647h/0/32h/69/96/0h/1".decode_path(false).is_ok());
        assert!("m/0/1h/9/2147483647h/0/32h/69/96/0h/1/".decode_path(false).is_ok());
        assert!("m/0/1h/9/4294967295/0/32h/69/96/0h/1/".decode_path(false).is_err());
        assert!("M".decode_path(false).is_err());
        assert!("n".decode_path(false).is_err());
        assert!("/0h/mh".decode_path(false).is_err());
        assert!("0h/mh".decode_path(false).is_err());
        assert!("0/mh".decode_path(false).is_err());
        assert!("m/0h/ah".decode_path(false).is_err());
        assert_eq!(PATH_START.decode_path(false).unwrap(), []);
        assert_eq!("m/0h/1".decode_path(false).unwrap(), [HARD_NB, 1]);
        assert_eq!("m/1/10h".decode_path(false).unwrap(), [1, 0x8000000a]);
        assert_eq!("m/0/1/2/3/4/".decode_path(false).unwrap(), [0, 1, 2, 3, 4]);
        assert_eq!(
            "m/0/1h/9/2147483647h/m/32".decode_path(false).unwrap_err(),
            Error::Path(String::from("m"))
        );
        assert_eq!(
            "m/0/1h/9/2147483648/0/32".decode_path(false).unwrap_err(),
            Error::Path(String::from("2147483648"))
        );
        assert_eq!(
            "m/0/1h/9/2147483648/0/32".decode_path(false).unwrap_err(),
            Error::Path(String::from("2147483648"))
        );
        assert_eq!(
            "m/0/1h/9/4294967295/0/32".decode_path(false).unwrap_err(),
            Error::Path(String::from("4294967295"))
        );
    }

    #[test]
    fn test_decode_range() {
        assert_eq!("1".decode_range().unwrap(), (1, 1));
        assert_eq!("1h".decode_range().unwrap(), (0x80000001, 0x80000001));
        assert_eq!("..1".decode_range().unwrap(), (0, 1));
        assert_eq!("..1h".decode_range().unwrap(), (0, 0x80000001));
        assert_eq!("1..".decode_range().unwrap(), (1, 0x7fffffff));
        assert_eq!("1h..".decode_range().unwrap(), (0x80000001, 0xffffffff));
        assert_eq!("0..9".decode_range().unwrap(), (0, 9));
        assert_eq!("0..9h".decode_range().unwrap(), (0, 0x80000009));
        assert_eq!("0h..9h".decode_range().unwrap(), (0x80000000, 0x80000009));
        assert_eq!("6232..6233".decode_range().unwrap(), (6232, 6233));
        assert_eq!("1h..0".decode_range().unwrap_err(), Error::Range(String::from("0")));
        assert_eq!("0:9".decode_range().unwrap_err(), Error::Range(String::from("0:9")));
        assert_eq!("9..9".decode_range().unwrap_err(), Error::Range(String::from("9..9")));
        assert_eq!("9..0".decode_range().unwrap_err(), Error::Range(String::from("9..0")));
        assert_eq!("-9..0".decode_range().unwrap_err(), Error::Range(String::from("-9")));
        assert_eq!("-1..".decode_range().unwrap_err(), Error::Range(String::from("-1")));
        assert_eq!("..-1".decode_range().unwrap_err(), Error::Range(String::from("-1")));
        assert_eq!(
            "0..2147483649".decode_range().unwrap_err(),
            Error::Range(String::from("2147483649"))
        );
    }

    #[test]
    fn test_decode_wif() {
        assert_eq!(WIC_1.decode_wif().unwrap(), ([0x11; 32], true));
        assert_eq!(WIC_L.decode_wif().unwrap(), ([0x69; 32], true));
        assert_eq!(WIF_1.decode_wif().unwrap(), ([0x11; 32], false));
        assert_eq!(WIF_L.decode_wif().unwrap(), ([0x69; 32], false));
        assert_eq!([WIF_L, "a"].concat().decode_wif().unwrap_err(), Error::WifKey);
        assert_eq!(WIC_L.replace("dgbg", "dgdg").decode_wif().unwrap_err(), Error::Checksum);
        assert_eq!(["a"; LEN_WIF_U].concat().decode_wif().unwrap_err(), Error::WifKey);
        assert_eq!(["a"; LEN_WIF_C].concat().decode_wif().unwrap_err(), Error::WifKey);
    }

    #[test]
    fn test_derive_prv() {
        for (idx, xprv) in TV_32_01_XPRV.iter().enumerate() {
            assert_eq!(
                ExtPrvKey::from_bs58_prv(&TV_32_01_XPRV[0].concat())
                    .unwrap()
                    .derive_prv(
                        &TV_32_01_PATH[idx].decode_path(false).unwrap()
                    ).unwrap()
                    .as_bs58ck_prv(),
                xprv.concat()
            );
        }
        for (idx, xprv) in TV_32_02_XPRV.iter().enumerate() {
            assert_eq!(
                ExtPrvKey::from_bs58_prv(&TV_32_02_XPRV[0].concat())
                    .unwrap()
                    .derive_prv(
                        &TV_32_02_PATH[idx].decode_path(false).unwrap()
                    ).unwrap()
                    .as_bs58ck_prv(),
                xprv.concat()
            );
        }
        for (idx, xprv) in TV_32_03_XPRV.iter().enumerate() {
            assert_eq!(
                ExtPrvKey::from_bs58_prv(&TV_32_03_XPRV[0].concat())
                    .unwrap()
                    .derive_prv(
                        &TV_32_03_PATH[idx].decode_path(false).unwrap()
                    ).unwrap()
                    .as_bs58ck_prv(),
                xprv.concat()
            );
        }
        let to_test = ExtPrvKey::from_bs58_prv(&XPRV_R.concat()).unwrap();
        assert!(to_test.derive_prv(&"m".decode_path(false).unwrap()).is_ok());
        assert!(
            to_test.derive_prv(
                &"m/0/1h/9/2147483647h/0/32h/69/96/0h/1".decode_path(false)
                    .unwrap()
                ).is_ok()
        );
        let pub_key = ExtPrvKey::from_bs58_prv(&XPRV_Z.concat()).unwrap()
            .derive_prv(
                &"m/44h/0h/0h/0/19".decode_path(false).unwrap()
            ).unwrap()
            .prvdata.public_key(true)
            .unwrap();
        assert_eq!(pub_key.p2wpkh().unwrap(), P2WPKH_Z_19);
    }

    #[test]
    fn test_derive_pub() {
        let to_test = ExtPubKey::from_bs58_pub(&XPUB_R.concat()).unwrap();
        assert!(to_test.derive_pub(&"m".decode_path(true).unwrap()).is_ok());
        assert!(
            to_test.derive_pub(
                &"m/0/9/2147483647/0/32/69/96/0/1".decode_path(true).unwrap()
            ).is_ok()
        );
        assert!(
            to_test.derive_pub( // false let pass hardened value
                &"m/0/9/0h/0/32/69/96/0/1".decode_path(false).unwrap()
            ).is_err()
        );
        assert_eq!(
            ExtPubKey::from_bs58_pub(&XPUB_Z.concat())
                .unwrap()
                .derive_pub(
                    &"m/0".decode_path(true).unwrap()
                ).unwrap()
                .pubdata.p2wpkh()
                .unwrap(),
            P2WPKH_Z_0
        );
    }

    #[test]
    fn test_encode_base58ck() {
        assert_eq!("a".as_bytes().encode_base58ck(), "C2dGTwc");
        assert_eq!("abc".as_bytes().encode_base58ck(), "4h3c6RH52R");
    }

    #[test]
    fn test_encode_path() {
        assert_eq!("m".decode_path(false).unwrap().encode_path(), "m");
        assert_eq!("m/00000000h/1".decode_path(false).unwrap().encode_path(), "m/0h/1");
        assert_eq!("m/000001/10h".decode_path(false).unwrap().encode_path(), "m/1/10h");
        assert_eq!([0u32; 0].encode_path(), "m");
        assert_eq!([1u32, 2, 3, 4, 5, HARD_NB].encode_path(), "m/1/2/3/4/5/0h");
    }

    #[test]
    fn test_encode_wif() {
        assert_eq!(&[0x11; 32].encode_wif(true).unwrap(), WIC_1);
        assert_eq!(&P2WPKH_B.encode_wif(true).unwrap(), WIC_A);
        assert_eq!(&[0x69; 32].encode_wif(true).unwrap(), WIC_L);
        assert_eq!(&[0x11; 32].encode_wif(false).unwrap(), WIF_1);
        assert_eq!(&P2WPKH_B.encode_wif(false).unwrap(), WIF_A);
        assert_eq!(&[0x69; 32].encode_wif(false).unwrap(), WIF_L);
    }

    #[test]
    fn test_from_bs58_prv() {
        assert_eq!(
            ExtPrvKey::from_bs58_prv(&XPRV_A.concat()).unwrap().bytes_prv(),
            XPRV_A_B[..NBBY_XKEY]
        );
        assert_eq!(
            ExtPrvKey::from_bs58_prv(&XPRV_R.concat()).unwrap().bytes_prv(),
            XPRV_R_B[..NBBY_XKEY]
        );
        assert_eq!(
            ExtPrvKey::from_bs58_prv(&XPRV_Z.concat()).unwrap().bytes_prv(),
            XPRV_Z_B[..NBBY_XKEY]
        );
        assert_eq!(
            ExtPrvKey::from_bs58_prv(&XPUB_Z.concat()).unwrap_err(), // xpub
            Error::KeyVer
        );
        assert_eq!(
            ExtPrvKey::from_bs58_prv(
                &XPRV_Z.concat().replace("a", "A")
            ).unwrap_err(),
            Error::Checksum
        );
        assert_eq!(
            ExtPrvKey::from_bs58_prv(
                &XPRV_Z.concat()[..100]
            ).unwrap_err(),
            Error::KeyLen
        );
        assert_eq!(
            ExtPrvKey::from_bs58_prv(
                &[&XPRV_Z.concat(), "aaaaa"].concat()
            ).unwrap_err(),
            Error::KeyLen
        );
        assert_eq!(
            ExtPrvKey::from_bs58_prv(&XPRV_R_NZ.concat()).unwrap_err(), //non 0
            Error::PrvData
        );
    }

    #[test]
    fn test_from_bs58_pub() {
        assert_eq!(
            ExtPubKey::from_bs58_pub(&XPUB_A.concat()).unwrap().bytes_pub(),
            XPUB_A_B[..NBBY_XKEY]
        );
        assert_eq!(
            ExtPubKey::from_bs58_pub(&XPUB_R.concat()).unwrap().bytes_pub(),
            XPUB_R_B[..NBBY_XKEY]
        );
        assert_eq!(
            ExtPubKey::from_bs58_pub(&XPUB_Z.concat()).unwrap().bytes_pub(),
            XPUB_Z_B[..NBBY_XKEY]
        );
        assert_eq!(
            ExtPubKey::from_bs58_pub(&XPRV_Z.concat()).unwrap_err(), // xprv
            Error::KeyVer
        );
        assert_eq!(
            ExtPubKey::from_bs58_pub(
                &XPUB_Z.concat()[..100]
            ).unwrap_err(),
            Error::KeyLen
        );
        assert_eq!(
            ExtPubKey::from_bs58_pub(
                &[&XPUB_Z.concat(), "aaaaa"].concat()
            ).unwrap_err(),
            Error::KeyLen
        );
        assert_eq!(
            ExtPubKey::from_bs58_pub(
                &XPUB_Z.concat().replace("a", "A")
            ).unwrap_err(),
            Error::Checksum
        );
    }

    #[test]
    fn test_from_prv() {
        for (idx, xpub) in TV_32_01_XPUB.iter().enumerate() {
            assert_eq!(
                ExtPubKey::from_prv(
                    &ExtPrvKey::from_bs58_prv(&TV_32_01_XPRV[0].concat())
                        .unwrap()
                        .derive_prv(
                            &TV_32_01_PATH[idx].decode_path(false).unwrap()
                        ).unwrap()
                    ).unwrap().as_bs58ck_pub(),
                xpub.concat()
            );
        }
        for (idx, xpub) in TV_32_02_XPUB.iter().enumerate() {
            assert_eq!(
                ExtPubKey::from_prv(
                    &ExtPrvKey::from_bs58_prv(&TV_32_02_XPRV[0].concat())
                        .unwrap()
                        .derive_prv(
                            &TV_32_02_PATH[idx].decode_path(false).unwrap()
                        ).unwrap()
                    ).unwrap().as_bs58ck_pub(),
                xpub.concat()
            );
        }
        for (idx, xpub) in TV_32_03_XPUB.iter().enumerate() {
            assert_eq!(
                ExtPubKey::from_prv(
                    &ExtPrvKey::from_bs58_prv(&TV_32_03_XPRV[0].concat())
                        .unwrap()
                        .derive_prv(
                            &TV_32_03_PATH[idx].decode_path(false).unwrap()
                        ).unwrap()
                    ).unwrap().as_bs58ck_pub(),
                xpub.concat()
            );
        }
        assert_eq!(
            ExtPubKey::from_prv(
                &ExtPrvKey::from_bs58_prv(&XPRV_A.concat())
                    .unwrap()
                    .derive_prv(&"m/44h/0h/0h/0".decode_path(false).unwrap())
                    .unwrap()
            ).unwrap().as_bs58ck_pub(),
            XPUB_A.concat()
        );
        assert_eq!(
            ExtPubKey::from_prv(
                &ExtPrvKey::from_bs58_prv(&XPRV_R.concat())
                    .unwrap()
                    .derive_prv(&"m/44h/0h/0h/0".decode_path(false).unwrap())
                    .unwrap()
            ).unwrap().as_bs58ck_pub(),
            XPUB_R.concat()
        );
        assert_eq!(
            ExtPubKey::from_prv(
                &ExtPrvKey::from_bs58_prv(&XPRV_Z.concat())
                    .unwrap()
                    .derive_prv(&"m/44h/0h/0h/0".decode_path(false).unwrap())
                    .unwrap()
            ).unwrap().as_bs58ck_pub(),
            XPUB_Z.concat()
        );
    }

    #[test]
    fn test_handle_arguments() {
        let inputs = [
            &XPRV_A.concat(), &XPRV_R.concat(), &XPRV_Z.concat(), HEX_STR_1,
            HEX_STR_L, WIF_1, WIF_L, WIC_1, WIC_L, &P2WPKH_B.hex_string(),
            P2WPKH_C_1, P2WPKH_C_A, P2WPKH_C_L, P2WPKH_P2SH_1, P2WPKH_P2SH_L,
            P2WPKH_U_1, P2WPKH_U_A, P2WPKH_U_L, SEGW_1, SEGW_A, SEGW_L
        ];
        for input in &inputs {
            assert!(handle_arguments(init_clap().get_matches_from(vec!["", input])).is_ok());
        }
        assert!(
            handle_arguments(
                init_clap().get_matches_from(
                    vec!["", &XPRV_R.concat(), "-e","バンドメイド", "-p", "m/0h", "-r", "0h..11h"]
                )
            ).is_ok()
        );
    }

    #[test]
    fn test_hash160() {
        assert_eq!([0x11; 33].hash160(), H160_33_1);
        assert_eq!([0x69; 33].hash160(), H160_33_L);
    }

    #[test]
    fn test_hash256() {
        // created with dual 'echo HEX_NB | xxd -r -p | openssl sha256'
        assert_eq!([0x00].hash256(), DS256_Z);
        assert_eq!([0x69; 32].hash256(), DS256_L);
        assert_eq!([0xff; 32].hash256(), DS256_F);
    }

    #[test]
    fn test_hex_bytes() {
        assert_eq!("0488ade4".hex_bytes().unwrap(), XPRV);
        assert_eq!("BABACA".hex_bytes().unwrap(), [0xba, 0xba, 0xca]);
    }

    #[test]
    fn test_hex_string() {
        assert_eq!(XPRV.hex_string(), String::from("0488ade4"));
        assert_eq!([0xba, 0xba, 0xca].hex_string(), String::from("babaca"));
    }

    #[test]
    fn test_info_entropy() {
        assert!(HEX_STR_1.info_entropy("", DEF_SEP).is_ok());
        assert!(HEX_STR_L.info_entropy("", DEF_SEP).is_ok());
        assert!(HEX_STR_1.info_entropy("pass", DEF_SEP).is_ok());
        assert_eq!(HEX_STR_0.info_entropy("", DEF_SEP).unwrap_err(), Error::SecEnt);
        assert_eq!(HEX_STR_F.info_entropy("", DEF_SEP).unwrap_err(), Error::SecEnt);
        assert_eq!(["a"; 63].concat().info_entropy("", DEF_SEP).unwrap_err(), Error::SecEnt);
        assert_eq!(["?"; 64].concat().info_entropy("", DEF_SEP).unwrap_err(), Error::HexStr);
    }

    #[test]
    fn test_info_wif() {
        assert!(WIF_1.info_wif("", DEF_SEP).is_ok());
        assert!(WIF_L.info_wif("", DEF_SEP).is_ok());
        assert!(WIF_1.info_wif("superpass", DEF_SEP).is_ok());
        assert!(WIC_1.info_wif("", DEF_SEP).is_ok());
        assert!(WIC_L.info_wif("", DEF_SEP).is_ok());
        assert!(WIC_1.info_wif("superduperpass", DEF_SEP).is_ok());
        assert_eq!(WIC_1.replace("H", "h").info_wif("", DEF_SEP).unwrap_err(), Error::Checksum);
        assert_eq!(WIF_1.replace("W", "w").info_wif("", DEF_SEP).unwrap_err(), Error::Checksum);
        assert_eq!("something_wrong".info_wif("", DEF_SEP).unwrap_err(), Error::WifKey);
    }

    #[test]
    fn test_init_clap() {
        let inputs = [
            &XPRV_A.concat(), &XPRV_R.concat(), &XPRV_Z.concat(), HEX_STR_1,
            HEX_STR_L, WIF_1, WIF_L, WIC_1, WIC_L, &P2WPKH_B.hex_string(),
            P2WPKH_C_1, P2WPKH_C_A, P2WPKH_C_L, P2WPKH_P2SH_1, P2WPKH_P2SH_L,
            P2WPKH_U_1, P2WPKH_U_A, P2WPKH_U_L, SEGW_1, SEGW_A, SEGW_L
        ];
        for input in &inputs {
            assert!(init_clap().get_matches_from_safe(vec!["", input]).is_ok());
        }
        assert!(
            init_clap().get_matches_from_safe(
                vec![
                    "", &XPRV_A.concat(), "-e", "ultrasecretpass", "-p",
                    "m/10h/20", "-r", "..7"
                ]
            ).is_ok()
        );
        assert!(init_clap().get_matches_from_safe(vec!["only_binary_name"]).is_err());
        assert!(
            init_clap().get_matches_from_safe(
                vec!["", &["a"; LEN_ARG_MIN - 1].concat()]
            ).is_err()
        );
        assert!(init_clap().get_matches_from_safe(vec!["", "wrong_data"]).is_err());
        assert!(init_clap().get_matches_from_safe(vec!["", &XPRV_A.concat(), "-e"]).is_err());
        assert!(init_clap().get_matches_from_safe(vec!["", &XPRV_A.concat(), "-p"]).is_err());
        assert!(init_clap().get_matches_from_safe(vec!["", &XPRV_A.concat(), "-r"]).is_err());
        assert!(init_clap().get_matches_from_safe(vec!["", &XPRV_A.concat(), "-x"]).is_err());
        assert!(init_clap().get_matches_from_safe(vec!["", "double", "data"]).is_err());
    }

    #[test]
    fn test_is_hex() {
        assert!("0123456789abcdf".is_hex());
        assert!("ABCDEF".is_hex());
        assert!(!"ghijkl".is_hex());
        assert!(!"'!@#$%&*;:><?".is_hex());
    }

    #[test]
    fn test_p2wpkh() {
        assert_eq!(PUB_C_1.p2wpkh().unwrap(), P2WPKH_C_1);
        assert_eq!(PUB_C_A.p2wpkh().unwrap(), P2WPKH_C_A);
        assert_eq!(PUB_C_L.p2wpkh().unwrap(), P2WPKH_C_L);
        assert_eq!(PUB_U_1.p2wpkh().unwrap(), P2WPKH_U_1);
        assert_eq!(PUB_U_A.p2wpkh().unwrap(), P2WPKH_U_A);
        assert_eq!(PUB_U_L.p2wpkh().unwrap(), P2WPKH_U_L);
        assert_eq!(PUB_C_L[1..].p2wpkh().unwrap_err(), Error::NbPubB(32));
        assert_eq!(PUB_U_L[1..].p2wpkh().unwrap_err(), Error::NbPubB(64));
    }

    #[test]
    fn test_public_key() {
        assert_eq!(P2WPKH_B.public_key(true).unwrap(), PUB_C_A);
        assert_eq!([0x11; 32].public_key(true).unwrap(), PUB_C_1);
        assert_eq!([0x69; 32].public_key(true).unwrap(), PUB_C_L);
        assert_eq!(P2WPKH_B.public_key(false).unwrap(), PUB_U_A);
        assert_eq!([0x11; 32].public_key(false).unwrap(), PUB_U_1);
        assert_eq!([0x69; 32].public_key(false).unwrap(), PUB_U_L);
    }

    #[test]
    fn test_segwit_p2wpkh() {
        assert_eq!(PUB_C_1.segwit_p2wpkh().unwrap(), SEGW_1);
        assert_eq!(PUB_C_A.segwit_p2wpkh().unwrap(), SEGW_A);
        assert_eq!(PUB_C_L.segwit_p2wpkh().unwrap(), SEGW_L);
    }

    #[test]
    fn test_segwit_p2wpkh_p2sh() {
        assert_eq!(PUB_C_1.segwit_p2wpkh_p2sh().unwrap(), P2WPKH_P2SH_1);
        assert_eq!(PUB_C_A.segwit_p2wpkh_p2sh().unwrap(), P2WPKH_P2SH_A);
        assert_eq!(PUB_C_L.segwit_p2wpkh_p2sh().unwrap(), P2WPKH_P2SH_L);
    }

    #[test]
    fn test_show_prv() {
        assert!(
            &ExtPrvKey::from_bs58_prv(&XPRV_A.concat()).unwrap().show_prv(
                &vec![],
                (0, 1),
                "",
                DEF_SEP
            ).is_ok()
        );
        assert!(
            ExtPrvKey::from_bs58_prv(&XPRV_R.concat()).unwrap().show_prv(
                &vec![],
                (0, 1),
                "",
                DEF_SEP
            ).is_ok()
        );
        assert!(
            ExtPrvKey::from_bs58_prv(&XPRV_Z.concat()).unwrap().show_prv(
                &vec![],
                (0, 1),
                "",
                DEF_SEP
            ).is_ok()
        );
    }

    #[test]
    fn test_show_pub() {
        assert!(
            ExtPubKey::from_bs58_pub(&XPUB_A.concat()).unwrap().show_pub(
                &vec![],
                (0, 1),
                DEF_SEP
            ).is_ok()
        );
        assert!(
            ExtPubKey::from_bs58_pub(&XPUB_R.concat()).unwrap().show_pub(
                &vec![],
                (0, 1),
                DEF_SEP
            ).is_ok()
        );
        assert!(
            ExtPubKey::from_bs58_pub(&XPUB_Z.concat()).unwrap().show_pub(
                &vec![],
                (0, 1),
                DEF_SEP
            ).is_ok()
        );
        assert_eq!(
            ExtPubKey::from_bs58_pub(&XPUB_Z.concat()).unwrap().show_pub(
                &vec![],
                (0x7fffffff, HARD_NB),
                DEF_SEP
            ).unwrap_err(),
            Error::FromHard
        );
    }

    #[test]
    fn test_validate_data() {
        let inputs = [
            &XPRV_A.concat(), &XPRV_R.concat(), &XPRV_Z.concat(), HEX_STR_1,
            HEX_STR_L, WIF_1, WIF_L, WIC_1, WIC_L, &P2WPKH_B.hex_string(),
            P2WPKH_C_1, P2WPKH_C_A, P2WPKH_C_L, P2WPKH_P2SH_1, P2WPKH_P2SH_L,
            P2WPKH_U_1, P2WPKH_U_A, P2WPKH_U_L, SEGW_1, SEGW_A, SEGW_L
        ];
        for input in &inputs {
            assert!(validate_data(String::from(*input)).is_ok());
        }
        assert!(validate_data(String::from(&XPRV_A.concat()[..LEN_XKEY - 1])) .is_err());
        assert!(validate_data(format!("{}a", XPRV_A.concat())).is_err());
        assert!(validate_data(String::from(&HEX_STR_1[1..])).is_err());
        assert!(validate_data(format!("{}a", HEX_STR_1)).is_err());
        assert!(validate_data(String::from(&WIF_L[..LEN_WIF_U - 1])).is_err());
        assert!(validate_data(format!("{}a", WIF_L)).is_err());
        assert!(validate_data(String::from(&WIC_L[..LEN_WIF_C - 1])).is_err());
        assert!(validate_data(format!("{}a", WIC_L)).is_err());
        assert!(validate_data(String::from(&P2WPKH_C_A[..LEN_LEG_MIN - 1])).is_err());
        assert!(validate_data(format!("{}ab", P2WPKH_C_A)).is_err());
        assert!(validate_data(String::from(&P2WPKH_P2SH_L[..LEN_LEG_MIN - 1])).is_err());
        assert!(validate_data(format!("{}ab", P2WPKH_P2SH_L)).is_err());
        assert!(validate_data(String::from(&SEGW_A[..LEN_SEGWIT - 1])).is_err());
        assert!(validate_data(format!("{}a", SEGW_A)).is_err());
    }

    #[test]
    fn test_validate_path() {
        assert!(validate_path(String::from("m/0h/1")).is_ok());
        assert!(validate_path(String::from("m/h/1")).is_err());
        // to see more go to 'test_decode_path'
    }

    #[test]
    fn test_validate_range() {
        assert!(validate_range(String::from("1..9")).is_ok());
        assert!(validate_range(String::from("9..1")).is_err());
        // to see more go to 'test_decode_range'
    }
}
