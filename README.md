# BIP39 Offline Recovery Tools

[中文说明](README.zh-CN.md)

This project provides two offline-oriented Python utilities for recovering a Bitcoin wallet when most of the BIP39 mnemonic is already known. It is intended only for wallets you own or are explicitly authorized to recover.


## Related standards and libraries

- [Bitcoin BIP39 specification and word lists](https://github.com/bitcoin/bips/tree/master/bip-0039): the Bitcoin Improvement Proposal resources defining mnemonic sentence construction, checksum rules, seed generation, and the official language word lists used by BIP39-compatible wallets.
- [bip_utils](https://github.com/ebellocchia/bip_utils): the Python library used by this project for standard BIP39 seed generation and BIP44, BIP49, BIP84, and BIP86 key/address derivation.

## Project layout

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

The root scripts use English messages and comments. The scripts under `zh/` have Chinese messages, error text, comments, and docstrings while keeping the same algorithms and variable names.

## Choose the correct tool

### `01_bip39_order_recovery.py`

Use this when every mnemonic word is correct but the order is unknown.

It supports 12, 18, or 24 English BIP39 words, accepts spaces or commas, supports an optional BIP39 passphrase, and checks Bitcoin mainnet BIP44, BIP49, BIP84, and BIP86 paths. It scans account 0 at external indexes 0 and 1 and internal/change indexes 0 and 1, for 16 paths in total.

A complete permutation search grows very quickly. Twelve distinct words have `12! = 479,001,600` possible orders. Fully shuffled 18-word and 24-word mnemonics are normally impractical to exhaust, even though the program follows the requested logic.

### `02_bip39_wrong_words_recovery.py`

Use this when the word order is correct, but zero, one, or two words may be wrong.

It supports 12 or 24 English BIP39 words. When an entered word is outside the BIP39 list, its position is treated as a strong error-location hint. If all entered words are valid BIP39 words, the program must also search possible error positions. The target address prefix selects BIP44, BIP49, BIP84, or BIP86, and the script scans the same four account-0 locations for that standard.

Two-word recovery can still be extremely large, especially when both incorrect words are themselves valid BIP39 words and neither position is known.

## Scanned Bitcoin mainnet paths

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

The scripts do not scan other accounts, index 2 or above, custom derivation paths, multisignature wallets, descriptor wallets, or vendor-specific nonstandard paths.

## How the BIP39 checksum filter works

A BIP39 mnemonic is not an arbitrary sequence of dictionary words. It encodes entropy plus checksum bits derived from the beginning of the SHA-256 hash of that entropy. The relationship is `CS = ENT / 32`, and the mnemonic contains `ENT + CS` bits divided into 11-bit word indexes.

| Words | Entropy | Checksum | Random-candidate pass rate |
|---:|---:|---:|---:|
| 12 | 128 bits | 4 bits | about 1 in 16 |
| 18 | 192 bits | 6 bits | about 1 in 64 |
| 24 | 256 bits | 8 bits | about 1 in 256 |

Both programs run this checksum test before PBKDF2 seed generation, BIP32 derivation, and address encoding. A candidate that fails checksum is skipped immediately and causes zero address comparisons. This is an important optimization, but checksum validity only proves that a candidate is structurally valid BIP39; it does not prove ownership or identify the correct wallet. The known Bitcoin address is the final verification step.

### Reproducible checksum test counts

The following counts were obtained with the embedded 2048-word list and the checksum implementation included in the project:

1. Order-recovery test using eleven `abandon` words and one `about`: there are exactly 12 unique permutations. Exactly 1 permutation passes checksum and 11 are skipped, so only one candidate reaches address derivation during an exhaustive checksum scan.
2. Wrong-word test using eleven `abandon` words and an invalid final word: replacing the last position with all 2,048 BIP39 words produces exactly 128 checksum-valid candidates and skips 1,920. Without checksum filtering, all 2,048 candidates would require seed/address work.
3. In dictionary order, the correct final word `about` is replacement index 3. A search that stops on this known public match checks 4 replacements: 1 passes checksum and 3 are skipped before address derivation.

These exact numbers apply to the stated public test cases. For other constrained candidate sets, the observed count can differ from the statistical expectation, although the checksum probabilities above remain the appropriate general estimate.

## Installation and operation

Use Python 3.10 or newer. Install the pinned dependency:

```text
python -m pip install -r requirements.txt
```

A safer workflow is to prepare a clean computer, install Python and the dependency, disconnect networking, then run one of the scripts:

```text
python 01_bip39_order_recovery.py
python 02_bip39_wrong_words_recovery.py
```

Chinese versions:

```text
python zh/01_bip39_order_recovery_zh.py
python zh/02_bip39_wrong_words_recovery_zh.py
```

Input is requested interactively and is not supplied as a command-line argument. Mnemonic and passphrase text is visible on the terminal screen so it can be checked for typing mistakes.

## Protect the mnemonic

A complete mnemonic, together with its passphrase when one is used, is effectively the highest-level key to the wallet. Never send it to another person, paste it into a website, online form, chat service, cloud note, remote-support session, or untrusted recovery service. Do not livestream, screenshot, or screen-record the recovery session.

Prefer a clean, offline computer. Check for remote-control software, clipboard synchronization, cloud backup, keyloggers, malicious input methods, terminal logging, and virtual-machine host exposure. These scripts do not intentionally write the mnemonic, result, checkpoint, or log to disk, but the operating system and other software can still capture keyboard or screen data.

After recovery, consider the old mnemonic exposed because it has appeared on a general-purpose computer. Generate a new wallet on a trusted hardware wallet or offline device, verify it with a small transfer, and move the remaining funds promptly.

## Public test vector

Before entering real wallet data, test the environment with the public mnemonic:

```text
abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about
```

Leave the passphrase empty. The BIP84 address at `m/84'/0'/0'/0/0` is:

```text
bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu
```

For the order-recovery tool, move `about` to the beginning. Because the phrase contains eleven repeated words, only 12 unique permutations exist, making it suitable for a quick functional check rather than a speed benchmark.

For the wrong-word tool, replace the final `about` with a token not in the BIP39 list, such as `xxxxx`, and use the same public address. The script should identify position 12 and restore `about`.

## Good-faith purpose and security limitations

This project is published in good faith to help legitimate wallet owners repair transcription mistakes, one- or two-word mistakes, and mnemonic ordering mistakes. It does not recover a wallet from a Bitcoin address alone, bypass Bitcoin cryptography, or make arbitrary unknown BIP39 secrets feasible to brute-force. A user must already possess nearly all of the mnemonic data, and usually a matching public address and any passphrase.

No software can technically guarantee that it will never be misused. Do not use this project with mnemonic material obtained without authorization. The maintainers do not endorse unauthorized access, theft, or attempts to recover wallets belonging to other people. Users are responsible for lawful and authorized use.

## MIT License

The project is released under the MIT License. You may use, copy, modify, merge, publish, distribute, sublicense, and sell copies, including modified versions, provided that the copyright notice and license text are retained in copies or substantial portions. The software is provided “as is,” without warranty. See [LICENSE](LICENSE) for the complete terms.

May this project help legitimate owners recover their wallets safely. Take your time, verify every address, put security before speed, and after recovery move funds to a fresh wallet. Wishing you a smooth recovery, a secure wallet, and abundant prosperity.
