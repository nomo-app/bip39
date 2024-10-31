import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';
import 'dart:io' as io;
import 'package:bip39/src/wordlists/es.dart';
import 'package:bip39/src/wordlists/fr.dart';
import 'package:bip39/src/wordlists/it.dart';
import 'package:bip39/src/wordlists/ja.dart';
import 'package:bip39/src/wordlists/ko.dart';
import 'package:bip39/src/wordlists/zhHans.dart';
import 'package:bip39/src/wordlists/zhHant.dart';
import 'package:crypto/crypto.dart' show sha256;
import 'package:hex/hex.dart';

import 'utils/pbkdf2.dart';
import 'wordlists/en.dart';

const int _SIZE_BYTE = 255;
const _INVALID_MNEMONIC = 'Invalid mnemonic';
const _INVALID_ENTROPY = 'Invalid entropy';
const _INVALID_CHECKSUM = 'Invalid mnemonic checksum';

typedef Uint8List RandomBytes(int size);

int _binaryToByte(String binary) {
  return int.parse(binary, radix: 2);
}

String _bytesToBinary(Uint8List bytes) {
  return bytes.map((byte) => byte.toRadixString(2).padLeft(8, '0')).join('');
}

//Uint8List _createUint8ListFromString( String s ) {
//  var ret = new Uint8List(s.length);
//  for( var i=0 ; i<s.length ; i++ ) {
//    ret[i] = s.codeUnitAt(i);
//  }
//  return ret;
//}

String _deriveChecksumBits(Uint8List entropy) {
  final ENT = entropy.length * 8;
  final CS = ENT ~/ 32;
  final hash = sha256.convert(entropy);
  return _bytesToBinary(Uint8List.fromList(hash.bytes)).substring(0, CS);
}

Uint8List _randomSecureBytes(int size) {
  final rng = Random.secure();
  final bytes = Uint8List(size);
  for (var i = 0; i < size; i++) {
    bytes[i] = rng.nextInt(_SIZE_BYTE);
  }
  return bytes;
}

final _stopWatch = Stopwatch();
void initBip39Stopwatch() {
  _stopWatch.start();
}

Uint8List _getRandomBytesMix(int strength) {
  if (!_stopWatch.isRunning) {
    throw ArgumentError("forgot to init stopWatch!");
  }
  final secureRandomness = _randomSecureBytes(
      32); // we expect that this alone should be already secure
  final microsecondsSinceEpoch =
      utf8.encode(DateTime.now().microsecondsSinceEpoch.toString());
  final microsecondsSinceAppLaunch =
      utf8.encode(_stopWatch.elapsedMicroseconds.toString());
  final pid = utf8.encode(io.pid.toString());

  final Uint8List combinedBytes = Uint8List.fromList(secureRandomness +
      microsecondsSinceEpoch +
      microsecondsSinceAppLaunch +
      pid);
  final hash = sha256.convert(sha256.convert(combinedBytes).bytes);
  assert(strength >= 16 && strength <= 32);
  return Uint8List.fromList(hash.bytes.sublist(0, strength));
}

String generateMnemonic(
    {int strength = 128, RandomBytes randomBytes = _getRandomBytesMix}) {
  assert(strength % 32 == 0);
  final entropy = randomBytes(strength ~/ 8);
  return entropyToMnemonic(HEX.encode(entropy));
}

String entropyToMnemonic(String entropyString) {
  final entropy = Uint8List.fromList(HEX.decode(entropyString));
  if (entropy.length < 16) {
    throw ArgumentError(_INVALID_ENTROPY);
  }
  if (entropy.length > 32) {
    throw ArgumentError(_INVALID_ENTROPY);
  }
  if (entropy.length % 4 != 0) {
    throw ArgumentError(_INVALID_ENTROPY);
  }
  final entropyBits = _bytesToBinary(entropy);
  final checksumBits = _deriveChecksumBits(entropy);
  final bits = entropyBits + checksumBits;
  final regex = new RegExp(r".{1,11}", caseSensitive: false, multiLine: false);
  final chunks = regex
      .allMatches(bits)
      .map((match) => match.group(0)!)
      .toList(growable: false);
  List<String> wordlist =
      ENWORDS; // only generate english mnemonics to avoid non-deterministic utf8-encoding
  String words =
      chunks.map((binary) => wordlist[_binaryToByte(binary)]).join(' ');
  return words;
}

Uint8List? _cachedSeed;

void wipeCachedSeed() {
  _cachedSeed = null;
}

void setCachedSeed(Uint8List seed) {
  _cachedSeed = seed;
}

Uint8List? getCachedSeed() {
  return _cachedSeed;
}

Uint8List mnemonicToSeed(String mnemonic, {String passphrase = ""}) {
  if (_cachedSeed == null) {
    final pbkdf2 = PBKDF2();
    _cachedSeed = pbkdf2.process(mnemonic, passphrase: passphrase);
  }
  return _cachedSeed!;
}

String mnemonicToSeedHex(String mnemonic, {String passphrase = ""}) {
  return mnemonicToSeed(mnemonic, passphrase: passphrase).map((byte) {
    return byte.toRadixString(16).padLeft(2, '0');
  }).join('');
}

bool validateMnemonic(String mnemonic) {
  try {
    mnemonicToEntropy(mnemonic);
  } catch (e) {
    return false;
  }
  return true;
}

String mnemonicToEntropy(mnemonic) {
  try {
    return _mnemonicToEntropy(mnemonic, ENWORDS);
  } catch (e) {
    try {
      return _mnemonicToEntropy(mnemonic, ESWORDS);
    } catch (e) {
      try {
        return _mnemonicToEntropy(mnemonic, FRWORDS);
      } catch (e) {
        try {
          return _mnemonicToEntropy(mnemonic, ITWORDS);
        } catch (e) {
          try {
            return _mnemonicToEntropy(mnemonic, JAWORDS);
          } catch (e) {
            try {
              return _mnemonicToEntropy(mnemonic, KOWORDS);
            } catch (e) {
              try {
                return _mnemonicToEntropy(mnemonic, ZHHANSWORDS);
              } catch (e) {
                return _mnemonicToEntropy(mnemonic, ZHHANTWORDS);
              }
            }
          }
        }
      }
    }
  }
}

String _mnemonicToEntropy(String mnemonic, List<String> wordlist) {
  var words = mnemonic.split(' ');
  if (words.length % 3 != 0) {
    throw new ArgumentError(_INVALID_MNEMONIC);
  }
  if (words.length < 12) {
    throw new ArgumentError(_INVALID_MNEMONIC);
  }
  // convert word indices to 11 bit binary strings
  final bits = words.map((word) {
    final index = wordlist.indexOf(word);
    if (index == -1) {
      throw new ArgumentError(_INVALID_MNEMONIC);
    }
    return index.toRadixString(2).padLeft(11, '0');
  }).join('');
  // split the binary string into ENT/CS
  final dividerIndex = (bits.length / 33).floor() * 32;
  final entropyBits = bits.substring(0, dividerIndex);
  final checksumBits = bits.substring(dividerIndex);

  // calculate the checksum and compare
  final regex = RegExp(r".{1,8}");
  final entropyBytes = Uint8List.fromList(regex
      .allMatches(entropyBits)
      .map((match) => _binaryToByte(match.group(0)!))
      .toList(growable: false));
  if (entropyBytes.length < 16) {
    throw StateError(_INVALID_ENTROPY);
  }
  if (entropyBytes.length > 32) {
    throw StateError(_INVALID_ENTROPY);
  }
  if (entropyBytes.length % 4 != 0) {
    throw StateError(_INVALID_ENTROPY);
  }
  final newChecksum = _deriveChecksumBits(entropyBytes);
  if (newChecksum != checksumBits) {
    throw StateError(_INVALID_CHECKSUM);
  }
  return entropyBytes.map((byte) {
    return byte.toRadixString(16).padLeft(2, '0');
  }).join('');
}
// List<String>> _loadWordList() {
//   final res = new Resource('package:bip39/src/wordlists/english.json').readAsString();
//   List<String> words = (json.decode(res) as List).map((e) => e.toString()).toList();
//   return words;
// }
