"""
This script generates or imports an English BIP39 mnemonic phrase and derives
Bitcoin and Ethereum mainnet addresses.

Features:
1. Generates a new 24-word English BIP39 mnemonic phrase.
2. Imports an existing 12-, 15-, 18-, 21-, or 24-word English BIP39 mnemonic.
3. Supports spaces, English commas, and Chinese commas as separators.
4. Supports an optional BIP39 passphrase.
5. Generates 5 Bitcoin addresses and 5 Ethereum addresses by default.
6. Uses a non-hardened change level and a hardened address index.
7. Prints Bitcoin Native SegWit addresses and WIF private keys.
8. Prints Ethereum addresses and hexadecimal private keys.

Custom derivation paths:
Bitcoin:  m/84'/0'/0'/0/index'
Ethereum: m/44'/60'/0'/0/index'

Install dependency:
python -m pip install --upgrade bip-utils

Important:
These are custom derivation paths and are not standard BIP84 or BIP44 wallet
paths. Common wallet software may not automatically find or restore these
addresses.

Wallet recovery requires exactly the same mnemonic phrase, BIP39 passphrase,
derivation paths, and address indexes.

Never disclose mnemonic phrases, passphrases, WIF private keys, or Ethereum
private keys. Run this script only on a secure, trusted, and offline device.
"""

from bip_utils import Bip32Slip10Secp256k1, Bip39Languages, Bip39MnemonicGenerator, Bip39MnemonicValidator, Bip39SeedGenerator, Bip39WordsNum, EthAddrEncoder, P2PKHPubKeyModes, P2WPKHAddrEncoder, WifEncoder  # Import mnemonic, key derivation, and address encoding utilities

print("1. Generate a new 24-word mnemonic phrase")  # Mode 1: generate a new 24-word mnemonic
print("2. Import an existing BIP39 mnemonic phrase")  # Mode 2: import an existing mnemonic
mode = input("Select mode [1/2]: ").strip()  # Read and normalize the selected mode

if mode == "1":
    mnemonic = str(Bip39MnemonicGenerator(Bip39Languages.ENGLISH).FromWordsNumber(Bip39WordsNum.WORDS_NUM_24))  # Generate a 24-word English mnemonic
    print(f"New mnemonic phrase: {mnemonic}")  # Display the newly generated mnemonic
elif mode == "2":
    mnemonic_input = input("Enter the mnemonic phrase. Spaces, English commas, and Chinese commas are supported: ").strip()  # Read the existing mnemonic
    mnemonic = " ".join(mnemonic_input.replace(",", " ").replace("，", " ").split())  # Normalize commas and whitespace
    word_count = len(mnemonic.split())  # Count the mnemonic words
    if word_count not in (12, 15, 18, 21, 24):
        raise ValueError(f"The mnemonic phrase must contain 12, 15, 18, 21, or 24 words. Detected: {word_count}")  # Validate the word count
    if not Bip39MnemonicValidator(Bip39Languages.ENGLISH).IsValid(mnemonic):
        raise ValueError("The mnemonic phrase is invalid, contains an unknown word, has an incorrect order, or has an invalid checksum")  # Validate the words and checksum
    print(f"Mnemonic phrase imported successfully: {mnemonic}")  # Display the successful import message
else:
    raise ValueError("The mode must be 1 or 2")  # Reject an invalid mode

passphrase = input("Enter the BIP39 passphrase, or press Enter if none: ")  # Read the optional BIP39 passphrase
count_text = input("Enter the number of addresses for each cryptocurrency. Default [5]: ").strip()  # Read the address count for each cryptocurrency

if count_text:
    if not count_text.isdigit():
        raise ValueError("The address count must be a positive integer")  # Validate that the input contains only digits
    address_count = int(count_text)  # Convert the input to an integer
else:
    address_count = 5  # Generate five addresses by default

if address_count < 1 or address_count > 1000:
    raise ValueError("The address count must be between 1 and 1000")  # Enforce the allowed address count range

seed = Bip39SeedGenerator(mnemonic, Bip39Languages.ENGLISH).Generate(passphrase)  # Generate the seed from the mnemonic and passphrase
master_key = Bip32Slip10Secp256k1.FromSeed(seed)  # Generate the secp256k1 master key from the seed

print("=" * 80)  # Print a separator line
print("Bitcoin Mainnet Native SegWit Addresses")  # Bitcoin mainnet Native SegWit addresses
print("Custom path: m/84'/0'/0'/0/index'")  # The change level is not hardened and the index is hardened
print(f"BIP39 passphrase: {passphrase if passphrase else 'Not set'}")  # Display the passphrase value or status
print("=" * 80)  # Print a separator line

for index in range(address_count):
    bitcoin_path = f"m/84'/0'/0'/0/{index}'"  # Bitcoin path: first three levels hardened, change not hardened, and index hardened
    bitcoin_key = master_key.DerivePath(bitcoin_path)  # Derive the Bitcoin child key using the specified path
    bitcoin_private_key = bitcoin_key.PrivateKey().Raw().ToBytes()  # Get the raw 32-byte private key
    bitcoin_public_key = bitcoin_key.PublicKey().RawCompressed().ToBytes()  # Get the compressed public key
    bitcoin_address = P2WPKHAddrEncoder.EncodeKey(bitcoin_public_key, hrp="bc")  # Encode a mainnet P2WPKH address beginning with bc1q
    bitcoin_wif = WifEncoder.Encode(bitcoin_private_key, net_ver=b"\x80", pub_key_mode=P2PKHPubKeyModes.COMPRESSED)  # Encode the private key as a compressed mainnet WIF
    print(f"Index: {index}")  # Display the address index
    print(f"Path: {bitcoin_path}")  # Display the complete derivation path
    print(f"Address: {bitcoin_address}")  # Display the Bitcoin address
    print(f"WIF private key: {bitcoin_wif}")  # Display the WIF private key
    print("-" * 80)  # Print a separator line

print("=" * 80)  # Print a separator line
print("Ethereum Mainnet Addresses")  # Ethereum mainnet addresses
print("Custom path: m/44'/60'/0'/0/index'")  # The change level is not hardened and the index is hardened
print(f"BIP39 passphrase: {passphrase if passphrase else 'Not set'}")  # Display the passphrase value or status
print("=" * 80)  # Print a separator line

for index in range(address_count):
    ethereum_path = f"m/44'/60'/0'/0/{index}'"  # Ethereum path: first three levels hardened, change not hardened, and index hardened
    ethereum_key = master_key.DerivePath(ethereum_path)  # Derive the Ethereum child key using the specified path
    ethereum_private_key = ethereum_key.PrivateKey().Raw().ToHex()  # Get the hexadecimal private key
    ethereum_public_key = ethereum_key.PublicKey().RawUncompressed().ToBytes()  # Get the uncompressed public key
    ethereum_address = EthAddrEncoder.EncodeKey(ethereum_public_key)  # Generate the EIP-55 Ethereum address
    print(f"Index: {index}")  # Display the address index
    print(f"Path: {ethereum_path}")  # Display the complete derivation path
    print(f"Address: {ethereum_address}")  # Display the Ethereum address
    print(f"Private key: 0x{ethereum_private_key}")  # Display the private key with the 0x prefix
    print("-" * 80)  # Print a separator line
