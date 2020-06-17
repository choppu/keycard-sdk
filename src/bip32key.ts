import { CryptoUtils } from "./crypto-utils"
import { BERTLV } from "./ber-tlv"
import { Ethereum } from "./ethereum"

const secp256k1 = require('secp256k1');
const CryptoJS = require('crypto-js');

const TLV_KEY_TEMPLATE = 0xA1;
const TLV_PUB_KEY = 0x80;
const TLV_PRIV_KEY = 0x81;
const TLV_CHAIN_CODE = 0x82;

export class BIP32KeyPair {
  privateKey: Uint8Array;
  publicKey: Uint8Array;
  chainCode: Uint8Array;

  calculatePublicKey() : void {
    this.publicKey = secp256k1.publicKeyCreate(this.privateKey, false);
  }

  constructor(privateKey: Uint8Array, chainCode: Uint8Array, publicKey: Uint8Array) {
    if (privateKey == null && (chainCode != null || publicKey == null))  {
      throw new Error ("Error: Private key can be null only if the public key is not null and the chain code is null");
    }
    
    this.privateKey = privateKey;
    this.chainCode = chainCode;
    
    if (publicKey != null) {
      this.publicKey = publicKey;
    } else {
      this.calculatePublicKey();
    }
  }

  isExtended() : boolean {
    return this.chainCode != null;
  }

  public static fromBinarySeed(binarySeed: Uint8Array) : BIP32KeyPair {
    let binarySeedWordArr = CryptoJS.lib.WordArray.create(binarySeed);
    let key = CryptoUtils.stringToUint8Array("Bitcoin seed");
    let keyWArray = CryptoJS.lib.WordArray.create(key);
    let wordArr = CryptoJS.HmacSHA512(binarySeedWordArr, keyWArray);
    let mac = CryptoUtils.wordArrayToByteArray(wordArr);

    return new BIP32KeyPair(mac.subarray(0, 32), mac.subarray(32), null);
  }

  public static fromTLV(tlvData: Uint8Array) : BIP32KeyPair {
    let tlv = new BERTLV(tlvData);
    tlv.enterConstructed(TLV_KEY_TEMPLATE);

    let pubKey, privKey, chainCode;
    let tag = tlv.readTag();

    if (tag == TLV_PUB_KEY) {
      tlv.unreadLastTag();
      pubKey = tlv.readPrimitive(TLV_PUB_KEY);
      tag = tlv.readTag();
    }

    if (tag == TLV_PRIV_KEY) {
      tlv.unreadLastTag();
      privKey = tlv.readPrimitive(TLV_PRIV_KEY);
      tag = tlv.readTag();

      if (tag == TLV_CHAIN_CODE) {
        tlv.unreadLastTag();
        chainCode = tlv.readPrimitive(TLV_CHAIN_CODE);
      }
    }

    return new BIP32KeyPair(privKey, chainCode, pubKey);
  }

  toTLV(includePublic = true) : Uint8Array {
    let privLen = this.privateKey.byteLength;
    let privOff = 0;

    if(this.privateKey[0] == 0x00) {
      privOff++;
      privLen--;
    }

    let off = 0;
    let totalLength = includePublic ? (this.publicKey.byteLength + 2) : 0;
    totalLength += (privLen + 2);
    totalLength += this.isExtended() ? (this.chainCode.byteLength + 2) : 0;

    if (totalLength > 127) {
      totalLength += 3;
    } else {
      totalLength += 2;
    }

    let data = new Uint8Array(totalLength);
    data[off++] = TLV_KEY_TEMPLATE;

    if (totalLength > 127) {
      data[off++] = 0x81;
      data[off++] = totalLength - 3;
    } else {
      data[off++] = totalLength - 2;
    }

    if (includePublic) {
      data[off++] = TLV_PUB_KEY;
      data[off++] = this.publicKey.byteLength;
      data.set(this.publicKey, off);
      off += this.publicKey.byteLength;
    }

    data[off++] = TLV_PRIV_KEY;
    data[off++] = privLen;
    data.set(this.privateKey.subarray(privOff), off);
    off += privLen;

    if (this.isExtended()) {
      data[off++] = TLV_CHAIN_CODE;
      data[off++] = this.chainCode.byteLength;
      data.set(this.chainCode, off);
    }

    return data;
  }

  toEthereumAddress() : Uint8Array {
    return Ethereum.toEthereumAddress(this.publicKey);
  }

  isPublicOnly() : boolean {
    return this.privateKey == null;
  }
}