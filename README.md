# BIP39 Offline Wallet Recovery Tools

[中文 README](zh/README.md)

This project provides two Python tools intended for offline use to recover Bitcoin wallets when you already possess most of the BIP39 mnemonic information. Only use them to recover wallets that you own or for which you have received explicit authorization.


## Related Standards and Dependencies

- [Bitcoin BIP39 Specification and Wordlists](https://github.com/bitcoin/bips/tree/master/bip-0039): Materials in the Bitcoin Improvement Proposals related to BIP39 mnemonics, including mnemonic construction, checksum rules, seed generation methods, and official language wordlists.
- [bip_utils](https://github.com/ebellocchia/bip_utils): The Python library used by this project, responsible for standard BIP39 seed generation and key and address derivation for BIP44, BIP49, BIP84, and BIP86.

## Project Directory

```text
bip39_recovery_tools_open_source/
├── 01_bip39_order_recovery.py
├── 02_bip39_wrong_words_recovery.py
├── README.md
├── README.zh-CN.md
├── LICENSE
├── requirements.txt
└── zh/
    ├── README.md
    ├── 01_bip39_order_recovery_zh.py
    └── 02_bip39_wrong_words_recovery_zh.py
```

The scripts in the root directory use English prompts and English comments; the scripts in the `zh/` directory use Chinese prompts, Chinese error messages, Chinese comments, and Chinese explanatory text. Their algorithms are consistent with the English versions, while variable names remain in English for easier maintenance and comparison.

## Choosing the Correct Recovery Tool

### `01_bip39_order_recovery.py`

Suitable for: all mnemonic words are correct, but their order has been scrambled.

Supports 12, 18, or 24 English BIP39 words, accepts input separated by spaces or commas, and also supports an optional BIP39 passphrase. The program scans only the Bitcoin mainnet and checks BIP44, BIP49, BIP84, and BIP86. Under account 0, it scans external address indexes 0 and 1, as well as internal/change address indexes 0 and 1, for a total of 16 paths.

The number of complete permutations grows extremely quickly. Twelve distinct words have `12! = 479,001,600` possible orders; fully scrambled 18-word and 24-word mnemonics usually cannot be exhaustively searched within a practical amount of time, although the program will still execute according to its configured logic.

### `02_bip39_wrong_words_recovery.py`

Suitable for: the mnemonic order is correct, but 0, 1, or 2 words may be incorrect.

Supports 12 or 24 English BIP39 words. If an input word is not in the BIP39 wordlist, the program treats its position as a strong indication of an incorrect position; if all input words belong to the BIP39 wordlist, the program must also iterate through the possible incorrect positions. The target address prefix is used to select BIP44, BIP49, BIP84, or BIP86, after which the same 4 account-0 address positions under that standard are scanned.

The search space for two incorrect words may still be extremely large, especially when both incorrect words are themselves valid BIP39 words and both incorrect positions are unknown.

## Scanned Bitcoin Mainnet Paths

```text
m/44'/0'/0'/0/0
m/44'/0'/0'/0/1
m/44'/0'/0'/1/0
m/44'/0'/0'/1/1

m/49'/0'/0'/0/0
m/49'/0'/0'/0/1
m/49'/0'/0'/1/0
m/49'/0'/0'/1/1

m/84'/0'/0'/0/0
m/84'/0'/0'/0/1
m/84'/0'/0'/1/0
m/84'/0'/0'/1/1

m/86'/0'/0'/0/0
m/86'/0'/0'/0/1
m/86'/0'/0'/1/0
m/86'/0'/0'/1/1
```

This project does not scan other accounts, indexes 2 and above, custom derivation paths, multisignature wallets, descriptor wallets, or nonstandard paths used by wallet vendors.

## Accurate Explanation of the BIP39 Checksum

A BIP39 mnemonic is not an arbitrary sequence of words selected from a wordlist. It encodes random entropy and a checksum. The checksum is taken from the first several bits of the SHA-256 hash of that entropy, with the relationship `CS = ENT / 32`; the total number of bits carried by the mnemonic is `ENT + CS`, which is then mapped to a wordlist index every 11 bits.

| Number of Mnemonic Words | Entropy | Checksum | Average Pass Rate of Random Candidates |
|---:|---:|---:|---:|
| 12 | 128 bits | 4 bits | Approximately 1/16 |
| 18 | 192 bits | 6 bits | Approximately 1/64 |
| 24 | 256 bits | 8 bits | Approximately 1/256 |

Both programs perform the checksum before PBKDF2 seed generation, BIP32 derivation, and address encoding. Candidates that fail the checksum are skipped immediately, and the number of address comparisons is 0. This can significantly reduce the number of candidates that actually undergo address derivation.


The BIP39 checksum is used to validate the mnemonic format and does not provide additional security.
According to theoretical probability, a 12-word mnemonic can filter out 93.75% of random combinations, while a 24-word mnemonic can filter out approximately 99.61%;
Passing validation only means that the format is valid


Passing the checksum only indicates that the candidate is valid under the BIP39 structure. It does not prove that it is your wallet, nor does it prove ownership. Final confirmation must be made by an exact match between the derived address and a known Bitcoin address provided by the user.

### Reproducible Actual Checksum Test Counts

The following numbers come from the project's embedded 2,048-word wordlist and the checksum implementation in the scripts. They use public test data and can be reproduced:

1. Order recovery test: use 11 instances of `abandon` and 1 instance of `about`. Because there are 11 repeated words, the total number of unique permutations is exactly 12. Of these, 1 has a valid checksum and 11 are skipped directly; during a complete checksum scan, only 1 candidate proceeds to address derivation.
2. Incorrect-word recovery test: the first 11 words are `abandon`, and the final word is an incorrect word that is not in the wordlist. When all 2,048 BIP39 words are tried in the final position, 128 have valid checksums and 1,920 are skipped directly. Without checksum filtering, all 2,048 candidates would require seed and address calculations.
3. When scanning in wordlist index order, the index of the correct final word `about` is 3. In the test that stops after the public address is matched, a total of 4 replacement words are checked, of which 1 has a valid checksum and 3 are skipped. Only the correct candidate actually proceeds to address derivation.

These exact numbers apply only to the public test data described above. In other constrained candidate sets, the actual number of valid candidates may differ slightly from the statistical expectation, but the probabilities in the table above remain correct estimates in general.

## Installation and Usage

Python 3.10 or later is required. Install the pinned dependencies:

```text
python -m pip install -r requirements.txt
```

A safer operating procedure is to prepare a trusted and clean computer, install Python and the dependencies, disconnect from the network, and then run the scripts:

```text
python 01_bip39_order_recovery.py
python 02_bip39_wrong_words_recovery.py
```

Chinese versions:

```text
python zh/01_bip39_order_recovery_zh.py
python zh/02_bip39_wrong_words_recovery_zh.py
```

After startup, the program reads data through interactive input and does not take the mnemonic as a command-line argument. To make input errors easier to check, the mnemonic and passphrase are displayed on the terminal screen.

## Be Sure to Protect the Mnemonic

A complete mnemonic together with the correct passphrase, if the wallet uses one, is essentially equivalent to the highest level of control over the wallet. Do not send a real mnemonic to anyone, and do not paste it into websites, online forms, chat software, cloud notes, remote assistance windows, or untrusted so-called “recovery services.”

Do not take screenshots, record the screen, livestream, or allow others to see the recovery process.

Prefer a trusted, clean, offline computer. Check for remote-control software, clipboard synchronization, cloud backups, keyloggers, malicious input methods, terminal logs, and exposure through the virtual machine host.
The scripts themselves do not actively write the mnemonic, recovery results, progress checkpoints, or logs to disk, but the operating system and other software may still record keyboard or screen contents.

After a successful recovery, the old mnemonic should be regarded as having been exposed on a general-purpose computer.
It is recommended to use a trusted hardware wallet or offline device for import testing.

## Public Test Data

Before formally entering real wallet information, it is recommended to first use the following public test mnemonic to check the environment:

```text
abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about
```

Leave the passphrase blank. The public address for the BIP84 path `m/84'/0'/0'/0/0` is:

```text
bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu
```

When testing order recovery, you can move `about` to the first position. Because this mnemonic contains 11 repeated instances of `abandon`, there are only 12 unique permutations. It is suitable for a quick functional check, but not as a speed benchmark for an ordinary scrambled 12-word mnemonic.

When testing incorrect-word recovery, you can replace the final `about` with `xxxxx`, which is not in the BIP39 wordlist, and continue using the same public address. The program should identify the 12th word and recover it as `about`.

## Good-Faith Use and Security Boundaries

This program is released entirely in good faith, with the hope of helping legitimate wallet owners resolve mnemonic transcription errors, one or two incorrect words, and mnemonic word-order errors.

This program cannot recover a wallet from a Bitcoin address alone, cannot make brute-force attacks on arbitrary unknown BIP39 mnemonics feasible, and has no attack capability.


## MIT License

This project is released under the MIT License. You may freely use, copy, modify, merge, publish, distribute, sublicense, and sell original or modified versions, but the copyright notice and license text must be retained in copies or substantial portions of the software.

The software is provided “as is,” without any express or implied warranty.

For the complete terms, see the [MIT License](https://opensource.org/license/mit/).



May this project help genuine wallet owners safely recover their assets. During recovery, please remain patient, verify each address one by one, and put security before speed; after a successful recovery, promptly transfer the assets to a brand-new wallet. Wishing everyone a smooth recovery, a safe wallet, and abundant wealth～
