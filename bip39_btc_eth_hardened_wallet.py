"""
This script generates or imports an English BIP39 mnemonic phrase and derives
fully hardened Bitcoin and Ethereum mainnet addresses.

Features:
1. Generates a new 24-word English BIP39 mnemonic phrase.
2. Imports an existing 12-, 15-, 18-, 21-, or 24-word English BIP39 mnemonic.
3. Supports spaces, English commas, and Chinese commas as separators.
4. Supports an optional BIP39 passphrase.
5. Generates 5 Bitcoin addresses and 5 Ethereum addresses by default.
6. Uses fully hardened derivation paths at every level.
7. Prints Bitcoin Native SegWit addresses and WIF private keys.
8. Prints Ethereum addresses and hexadecimal private keys.

Fully hardened derivation paths:
Bitcoin:  m/84'/0'/0'/0'/index'
Ethereum: m/44'/60'/0'/0'/index'

Install dependency:
python -m pip install --upgrade bip-utils

Important:
These are custom fully hardened derivation paths and are not standard BIP84 or
BIP44 wallet paths. Common wallet software may not automatically find or
restore these addresses.

Wallet recovery requires exactly the same mnemonic phrase, BIP39 passphrase,
derivation paths, and address indexes.

Never disclose mnemonic phrases, passphrases, WIF private keys, or Ethereum
private keys. Run this script only on a secure, trusted, and offline device.
"""
from bip_utils import Bip32Slip10Secp256k1, Bip39Languages, Bip39MnemonicGenerator, Bip39MnemonicValidator, Bip39SeedGenerator, Bip39WordsNum, EthAddrEncoder, P2PKHPubKeyModes, P2WPKHAddrEncoder, WifEncoder

print("1. Generate a new 24-word mnemonic phrase")
print("2. Import an existing BIP39 mnemonic phrase")
mode = input("Select mode [1/2]: ").strip()

if mode == "1":
    mnemonic = str(Bip39MnemonicGenerator(Bip39Languages.ENGLISH).FromWordsNumber(Bip39WordsNum.WORDS_NUM_24))
    print(f"New mnemonic phrase: {mnemonic}")
elif mode == "2":
    mnemonic_input = input("Enter the mnemonic phrase. Spaces, English commas, and Chinese commas are supported: ").strip()
    mnemonic = " ".join(mnemonic_input.replace(",", " ").replace("，", " ").split())
    word_count = len(mnemonic.split())
    if word_count not in (12, 15, 18, 21, 24):
        raise ValueError(f"The mnemonic phrase must contain 12, 15, 18, 21, or 24 words. Detected: {word_count}")
    if not Bip39MnemonicValidator(Bip39Languages.ENGLISH).IsValid(mnemonic):
        raise ValueError("The mnemonic phrase is invalid, contains an unknown word, has an incorrect order, or has an invalid checksum")
    print(f"Mnemonic phrase imported successfully: {mnemonic}")
else:
    raise ValueError("The mode must be 1 or 2")

passphrase = input("Enter the BIP39 passphrase, or press Enter if none: ")
count_text = input("Enter the number of addresses for each cryptocurrency. Default [5]: ").strip()

if count_text:
    if not count_text.isdigit():
        raise ValueError("The address count must be a positive integer")
    address_count = int(count_text)
else:
    address_count = 5

if address_count < 1 or address_count > 1000:
    raise ValueError("The address count must be between 1 and 1000")

seed = Bip39SeedGenerator(mnemonic, Bip39Languages.ENGLISH).Generate(passphrase)
master_key = Bip32Slip10Secp256k1.FromSeed(seed)

print("=" * 80)
print("Bitcoin Mainnet Native SegWit Addresses")
print("Fully hardened path: m/84'/0'/0'/0'/index'")
print(f"BIP39 passphrase: {passphrase if passphrase else 'Not set'}")
print("=" * 80)

for index in range(address_count):
    bitcoin_path = f"m/84'/0'/0'/0'/{index}'"
    bitcoin_key = master_key.DerivePath(bitcoin_path)
    bitcoin_private_key = bitcoin_key.PrivateKey().Raw().ToBytes()
    bitcoin_public_key = bitcoin_key.PublicKey().RawCompressed().ToBytes()
    bitcoin_address = P2WPKHAddrEncoder.EncodeKey(bitcoin_public_key, hrp="bc")
    bitcoin_wif = WifEncoder.Encode(bitcoin_private_key, net_ver=b"\x80", pub_key_mode=P2PKHPubKeyModes.COMPRESSED)
    print(f"Index: {index}")
    print(f"Path: {bitcoin_path}")
    print(f"Address: {bitcoin_address}")
    print(f"WIF private key: {bitcoin_wif}")
    print("-" * 80)

print("=" * 80)
print("Ethereum Mainnet Addresses")
print("Fully hardened path: m/44'/60'/0'/0'/index'")
print(f"BIP39 passphrase: {passphrase if passphrase else 'Not set'}")
print("=" * 80)

for index in range(address_count):
    ethereum_path = f"m/44'/60'/0'/0'/{index}'"
    ethereum_key = master_key.DerivePath(ethereum_path)
    ethereum_private_key = ethereum_key.PrivateKey().Raw().ToHex()
    ethereum_public_key = ethereum_key.PublicKey().RawUncompressed().ToBytes()
    ethereum_address = EthAddrEncoder.EncodeKey(ethereum_public_key)
    print(f"Index: {index}")
    print(f"Path: {ethereum_path}")
    print(f"Address: {ethereum_address}")
    print(f"Private key: 0x{ethereum_private_key}")
    print("-" * 80)
