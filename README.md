# Nomo BIP39

Dart implementation of [Bitcoin BIP39](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki): Mnemonic code for generating deterministic keys

Convert from [bitcoinjs/bip39](https://github.com/bitcoinjs/bip39)

# Nomo Specific Changes

In this fork, a few changes were made specifically for the Nomo App.

## Security Hardening

For the unlikely case that the random number generation of Dart is compromised, this fork includes an expanded RNG-algorithm that attempts to protect Nomo Users.

## Fully Deterministic Wordlists

In this fork, we try several languages sequentially until either a matching wordlist is found or an error gets returned.
In practice, we find it better to return an error instead of recovering wallets with wrong ETH-addresses.
By doing it that way, the user has a chance of correcting spelling mistakes instead of ending up with garbage-wallets.



### Reminder for developers

**_Please do not generate non-english phrases if it can be avoided_**

Languages like french or spanish can have a non-deterministic utf8-encoding.
In other words, the exact same french word might lead to two completely different wallets depending on how it is encoded.

Nevertheless, this packages is capable of reading words in many different languages.

## Examples

```dart
// Generate a random mnemonic (uses crypto.randomBytes under the hood), defaults to 128-bits of entropy
var mnemonic = bip39.generateMnemonic()
// => 'seed sock milk update focus rotate barely fade car face mechanic mercy'

bip39.mnemonicToSeedHex('basket actual')
// => String '5cf2d4a8b0355e90295bdfc565a022a409af063d5365bb57bf74d9528f494bfa4400f53d8349b80fdae44082d7f9541e1dba2b003bcfec9d0d53781ca676651f'

bip39.mnemonicToSeed('basket actual')
// => Uint8List [92, 242, 212, 168, 176, 53, 94, 144, 41, 91, 223, 197, 101, 160, 34, 164, 9, 175, 6, 61, 83, 101, 187, 87, 191, 116, 217, 82, 143, 73, 75, 250, 68, 0, 245, 61, 131, 73, 184, 15, 218, 228, 64, 130, 215, 249, 84, 30, 29, 186, 43, 0, 59, 207, 236, 157, 13, 83, 120, 28, 166, 118, 101, 31]

bip39.validateMnemonic(mnemonic)
// => true

bip39.validateMnemonic('basket actual')
// => false
```

```dart
import 'package:bip39/bip39.dart' as bip39;

main() {
    // Only support BIP39 English word list
    // uses HEX strings for entropy
    String randomMnemonic = await bip39.generateMnemonic();

    String seed = bip39.mnemonicToSeedHex("update elbow source spin squeeze horror world become oak assist bomb nuclear");
    // => '77e6a9b1236d6b53eaa64e2727b5808a55ce09eb899e1938ed55ef5d4f8153170a2c8f4674eb94ce58be7b75922e48e6e56582d806253bd3d72f4b3d896738a4'

    String mnemonic = await bip39.entropyToMnemonic('00000000000000000000000000000000');
    // => 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about'

    bool isValid = await bip39.validateMnemonic(mnemonic);
    // => true

    isValid = await bip39.validateMnemonic('basket actual');
    // => false

    String entropy = bip39.mnemonicToEntropy(mnemonic)
    // => String '00000000000000000000000000000000'
}
```
