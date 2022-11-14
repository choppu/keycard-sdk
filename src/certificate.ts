import { BERTLV } from "./ber-tlv";
import { BIP32KeyPair } from "./bip32key";
import { Constants } from "./constants";
import { CryptoUtils } from "./crypto-utils";
import { RecoverableSignature } from "./recoverable-signature";
import { error } from "console";

const CryptoJS = require('crypto-js');
const secp256k1 = require('secp256k1');


const TLV_CERT = 0x8a;

export class Certificate extends RecoverableSignature {
  identPriv: Uint8Array;
  identPub: Uint8Array;

  constructor(publicKey: Uint8Array, compressed: boolean, r: Uint8Array, s: Uint8Array, recId: number) {
    super(publicKey, compressed, r, s, recId);
  }

  public static generateIdentKeyPair(): BIP32KeyPair {
    let privKey = CryptoUtils.generateECPrivateKey();
    let publicKey = secp256k1.publicKeyCreate(privKey, false);
    return new BIP32KeyPair(privKey, new Uint8Array(0), publicKey);
  }

  public static createCertificate(caPair: BIP32KeyPair, identKeys: BIP32KeyPair): Certificate {
    let pub = secp256k1.publicKeyConvert(identKeys.publicKey, true, new Uint8Array(33));
    let hash = CryptoUtils.wordArrayToByteArray(CryptoJS.SHA256(pub));
    let signed = secp256k1.ecdsaSign(hash, caPair.privateKey);
    let r = signed.signature.subarray(0, 32);
    let s = signed.signature.subarray(32, 64);
    let cert = new Certificate(secp256k1.publicKeyConvert(caPair.publicKey, true, new Uint8Array(33)), true, r, s, signed.recid);
    cert.identPriv = Certificate.toUInt(identKeys.privateKey);
    cert.identPub = pub;

    return cert;
  }

  public static generateNewCertificate(caPair: BIP32KeyPair): Certificate {
    return Certificate.createCertificate(caPair, Certificate.generateIdentKeyPair());
  }

  fromTLV(certData: Uint8Array): Certificate {
      let pubKey = certData.subarray(0, 33);
      let r = certData.subarray(33, 65);
      let s = certData.subarray(65, 97);
      let recId = certData[97];

      let hash = CryptoUtils.wordArrayToByteArray(CryptoJS.SHA256(pubKey));
      let caPub = this.recoverFromSignature(recId, hash, r, s, true);

      let cert = new Certificate(caPub, true, r, s, recId);
      cert.identPub = pubKey;

      return cert;
  }

  verifyIdentity(hash: Uint8Array, tlvData: Uint8Array): Uint8Array {
    let tlv = new BERTLV(tlvData);
    tlv.enterConstructed(Constants.TLV_SIGNATURE_TEMPLATE);
    let certData = tlv.readPrimitive(TLV_CERT);
    let cert = this.fromTLV(certData);
    let signature = tlv.peekUnread();
    let verified = secp256k1.ecdsaVerify(signature, hash, cert.identPub);


    if (!verified) {
      return null;
    }

    return cert.publicKey;
  }

  toStoreData() : Uint8Array {
    if (this.identPriv == null) {
      throw new Error("The private key must be set.");
    }

    let storeDataLength = this.identPub.byteLength + this.r.byteLength + this.s.byteLength + this.identPriv.byteLength + 1;
    let storeData = new Uint8Array(storeDataLength);
    let off = 0;

    storeData.set(this.identPub, off);
    off += this.identPub.byteLength;
    storeData.set(this.r, off);
    off += this.r.byteLength;
    storeData.set(this.s, off);
    off += this.s.byteLength;
    storeData[off] = this.recId;
    off += 1;
    storeData.set(this.identPriv, off);
    return storeData;
  }

}