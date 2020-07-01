import { MnemonicEnglishDictionary } from "./mnemonic-english-dictionary"
import { CryptoUtils } from "./crypto-utils"
import { BIP32KeyPair } from "./bip32key";

const WORDLIST_SIZE = 2048; 
const CryptoJS = require("crypto-js")

export class Mnemonic {
  indexes: number[];
  wordlist: string[];

  constructor(data: Uint8Array) {
    this.indexes = new Array(data.length/2);

    for (let i = 0; i < this.indexes.length; i++) {
      this.indexes[i] = ((data[i * 2] << 8) | data[(i * 2) + 1]);
    }
  }

  setWordlist(wordlist: string[]) : void {
    if (wordlist.length != WORDLIST_SIZE) {
      throw new Error("Error: The list must contain exactly 2048 entries");
    }

    this.wordlist = wordlist;
  }

  fetchBIP39EnglishWordlist() : void {
    this.wordlist = MnemonicEnglishDictionary.words;
  }

  getWords() : string[] {
    if (this.wordlist == null) {
      throw new Error("Error: The wordlist must be set first");
    }

    let words = [];

    for (let i = 0; i < this.indexes.length; i++) {
      words[i] = this.wordlist[this.indexes[i]];
    }

    return words;
  }

  toMnemonicPhrase() : string {
    let wordsArr = this.getWords();
    return wordsArr.join(" ");
  }

  public static toBinarySeed(mnemonicPhrase: string, password = "") : Uint8Array {
    let salt = "mnemonic" + password;
    let iterationCount = 2048;
    let kSize = 512 / 32;
    let PBKDF2WordArr = CryptoJS.PBKDF2(mnemonicPhrase, salt, {keySize: kSize, iterations: iterationCount, hasher: CryptoJS.algo.SHA512});

    return CryptoUtils.wordArrayToByteArray(PBKDF2WordArr);
  }

  toBinarySeed(password = "") : Uint8Array {
    return Mnemonic.toBinarySeed(this.toMnemonicPhrase(), password);
  }

  toBIP32KeyPair(password = "") : BIP32KeyPair {
    return BIP32KeyPair.fromBinarySeed(this.toBinarySeed(password));
  }
}