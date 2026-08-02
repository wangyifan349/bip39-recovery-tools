"""
This script generates or imports a BIP39 mnemonic phrase and derives Bitcoin
and Ethereum mainnet addresses.

Features:
1. Generates a new 24-word English BIP39 mnemonic phrase.
2. Imports an existing 12-, 15-, 18-, 21-, or 24-word BIP39 mnemonic phrase.
3. Supports spaces, English commas, and Chinese commas as separators.
4. Supports an optional BIP39 passphrase.
5. Generates 5 Bitcoin addresses and 5 Ethereum addresses by default.
6. Allows Bitcoin and Ethereum address indexes to be hardened independently.
7. Prints Bitcoin Native SegWit addresses and WIF private keys.
8. Prints Ethereum addresses and hexadecimal private keys.

Standard compatible paths:
Bitcoin:  m/84'/0'/0'/0/index
Ethereum: m/44'/60'/0'/0/index

Optional custom hardened-index paths:
Bitcoin:  m/84'/0'/0'/0/index'
Ethereum: m/44'/60'/0'/0/index'

Install dependency:
python -m pip install --upgrade bip-utils

Important:
Hardened address indexes are custom and may not be automatically restored by
Electrum, MetaMask, Ledger, Trezor, or other common wallet software.

Wallet recovery requires the same mnemonic phrase, BIP39 passphrase, derivation
path, and hardening settings.

Never disclose mnemonic phrases, passphrases, WIF private keys, or Ethereum
private keys. Run this script only on a secure, trusted, and offline device.
"""

from bip_utils import (
    Bip32Slip10Secp256k1,
    Bip39MnemonicGenerator,
    Bip39MnemonicValidator,
    Bip39SeedGenerator,
    Bip39WordsNum,
    EthAddrEncoder,
    P2PKHPubKeyModes,
    P2WPKHAddrEncoder,
    WifEncoder,
)

print("1. Generate a new 24-word mnemonic phrase")
print("2. Import an existing BIP39 mnemonic phrase")
mode = input("Select mode [1/2]: ").strip()

if mode == "1":
    mnemonic = str(
        Bip39MnemonicGenerator().FromWordsNumber(
            Bip39WordsNum.WORDS_NUM_24
        )
    )
    print(f"New mnemonic phrase: {mnemonic}")
elif mode == "2":
    mnemonic_input = input(
        "Enter the mnemonic phrase. Spaces, English commas, "
        "and Chinese commas are supported: "
    ).strip()

    mnemonic = " ".join(
        mnemonic_input
        .replace(",", " ")
        .replace("，", " ")
        .split()
    )

    word_count = len(mnemonic.split())

    if word_count not in (12, 15, 18, 21, 24):
        raise ValueError(
            "The mnemonic phrase must contain 12, 15, 18, 21, or 24 words. "
            f"Detected: {word_count}"
        )

    if not Bip39MnemonicValidator().IsValid(mnemonic):
        raise ValueError(
            "The mnemonic phrase is invalid, the word order is incorrect, "
            "or the checksum is invalid"
        )

    print(f"Mnemonic phrase imported successfully: {mnemonic}")
else:
    raise ValueError("The mode must be 1 or 2")

passphrase = input(
    "Enter the BIP39 passphrase, or press Enter if none: "
)

count_text = input(
    "Enter the number of addresses for each cryptocurrency. Default [5]: "
).strip()

if count_text:
    if not count_text.isdigit():
        raise ValueError("The address count must be a positive integer")
    address_count = int(count_text)
else:
    address_count = 5

if address_count < 1 or address_count > 1000:
    raise ValueError("The address count must be between 1 and 1000")

bitcoin_hardened_input = input(
    "Harden the Bitcoin address index? [y/N]: "
).strip().lower()

if bitcoin_hardened_input in ("", "n", "no"):
    bitcoin_hardened = False
elif bitcoin_hardened_input in ("y", "yes"):
    bitcoin_hardened = True
else:
    raise ValueError("Bitcoin hardening selection must be y or n")

ethereum_hardened_input = input(
    "Harden the Ethereum address index? [y/N]: "
).strip().lower()

if ethereum_hardened_input in ("", "n", "no"):
    ethereum_hardened = False
elif ethereum_hardened_input in ("y", "yes"):
    ethereum_hardened = True
else:
    raise ValueError("Ethereum hardening selection must be y or n")

seed = Bip39SeedGenerator(mnemonic).Generate(passphrase)
master_key = Bip32Slip10Secp256k1.FromSeed(seed)

bitcoin_index_suffix = "'" if bitcoin_hardened else ""
ethereum_index_suffix = "'" if ethereum_hardened else ""

print("=" * 80)
print("Bitcoin Mainnet BIP84 Native SegWit Addresses")

if bitcoin_hardened:
    print("Mode: Custom hardened address index")
    print("Path format: m/84'/0'/0'/0/index'")
else:
    print("Mode: Standard compatible address index")
    print("Path format: m/84'/0'/0'/0/index")

print(
    f"BIP39 passphrase: "
    f"{passphrase if passphrase else 'Not set'}"
)
print("=" * 80)

for index in range(address_count):
    bitcoin_path = (
        f"m/84'/0'/0'/0/{index}{bitcoin_index_suffix}"
    )

    bitcoin_key = master_key.DerivePath(bitcoin_path)

    bitcoin_private_key = (
        bitcoin_key.PrivateKey().Raw().ToBytes()
    )

    bitcoin_public_key = (
        bitcoin_key.PublicKey().RawCompressed().ToBytes()
    )

    bitcoin_address = P2WPKHAddrEncoder.EncodeKey(
        bitcoin_public_key,
        hrp="bc",
    )

    bitcoin_wif = WifEncoder.Encode(
        bitcoin_private_key,
        net_ver=b"\x80",
        pub_key_mode=P2PKHPubKeyModes.COMPRESSED,
    )

    print(f"Index: {index}")
    print(f"Path: {bitcoin_path}")
    print(f"Address: {bitcoin_address}")
    print(f"WIF private key: {bitcoin_wif}")
    print("-" * 80)

print("=" * 80)
print("Ethereum Mainnet Addresses")

if ethereum_hardened:
    print("Mode: Custom hardened address index")
    print("Path format: m/44'/60'/0'/0/index'")
else:
    print("Mode: Standard compatible address index")
    print("Path format: m/44'/60'/0'/0/index")

print(
    f"BIP39 passphrase: "
    f"{passphrase if passphrase else 'Not set'}"
)
print("=" * 80)

for index in range(address_count):
    ethereum_path = (
        f"m/44'/60'/0'/0/{index}{ethereum_index_suffix}"
    )

    ethereum_key = master_key.DerivePath(ethereum_path)

    ethereum_private_key = (
        ethereum_key.PrivateKey().Raw().ToHex()
    )

    ethereum_public_key = (
        ethereum_key.PublicKey().RawUncompressed().ToBytes()
    )

    ethereum_address = EthAddrEncoder.EncodeKey(
        ethereum_public_key
    )

    print(f"Index: {index}")
    print(f"Path: {ethereum_path}")
    print(f"Address: {ethereum_address}")
    print(f"Private key: 0x{ethereum_private_key}")
    print("-" * 80)
