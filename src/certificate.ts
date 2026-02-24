import { BERTLV } from "./ber-tlv.ts";
import { BIP32KeyPair } from "./bip32key.ts";
import { Constants } from "./constants.ts";
import { CryptoUtils } from "./crypto-utils.ts";
import { RecoverableSignature } from "./recoverable-signature.ts";
import * as secp from '@noble/secp256k1';
import { sha256 } from '@noble/hashes/sha2'
import { hmac } from '@noble/hashes/hmac';
import { RecoverableSignatureProps } from "./types/recoverable-signature-types.ts";

const TLV_CERT = 0x8a;

secp.hashes.sha256 = sha256;
secp.hashes.hmacSha256 = (key, msg) => hmac(sha256, key, msg);

export class Certificate extends RecoverableSignature {
  identPriv!: Uint8Array;
  identPub!: Uint8Array;

  constructor(publicKey: Uint8Array, compressed: boolean, r: Uint8Array, s: Uint8Array, recId: number) {
    super({publicKey: publicKey, compressed: compressed, r: r, s: s, recId: recId} as RecoverableSignatureProps);
  }

  public static generateIdentKeyPair(): BIP32KeyPair {
    let privKey = CryptoUtils.generateECPrivateKey();
    let publicKey = secp.getPublicKey(privKey, false);
    return new BIP32KeyPair(privKey, new Uint8Array(0), publicKey);
  }

  public static createCertificate(caPair: BIP32KeyPair, identKeys: BIP32KeyPair): Certificate {
    let pub = CryptoUtils.compressPublicKey(identKeys.publicKey);
    let signature = secp.sign(pub, caPair.privateKey, {format: 'recovered'});
    let r = signature.subarray(1, 33);
    let s = signature.subarray(33, 65);
    let cert = new Certificate(CryptoUtils.compressPublicKey(caPair.publicKey), true, r, s, signature[0]);
    cert.identPriv = Certificate.toUInt(identKeys.privateKey);
    cert.identPub = pub;
    return cert;
  }

  public static generateNewCertificate(caPair: BIP32KeyPair): Certificate {
    return Certificate.createCertificate(caPair, Certificate.generateIdentKeyPair());
  }

  public static fromTLV(certData: Uint8Array): Certificate {
      let pubKey = certData.subarray(0, 33);
      let r = certData.subarray(33, 65);
      let s = certData.subarray(65, 97);
      let recId = certData[97];

      let hash = sha256(pubKey);
      let caPub = RecoverableSignature.recoverFromSignature(recId, hash, r, s, true);

      let cert = new Certificate(caPub, true, r, s, recId);
      cert.identPub = pubKey;

      return cert;
  }

  public static verifyIdentity(hash: Uint8Array, tlvData: Uint8Array): Uint8Array {
    let tlv = new BERTLV(tlvData);
    tlv.enterConstructed(Constants.TLV_SIGNATURE_TEMPLATE);
    let certData = tlv.readPrimitive(TLV_CERT);
    let cert = Certificate.fromTLV(certData);
    
    tlv.enterConstructed(Constants.TLV_ECDSA_TEMPLATE);

    const r = RecoverableSignature.toUInt(tlv.readPrimitive(Constants.TLV_INT));
    const s = RecoverableSignature.toUInt(tlv.readPrimitive(Constants.TLV_INT));

    const signature = new Uint8Array(64);
    signature.set(r, 0);
    signature.set(s, r.length);

    let verified = secp.verify(signature, hash, cert.identPub, { prehash: false, lowS: false });

    if (!verified) {
      throw new Error("Error verifying signature.");
    }

    return cert.publicKey!;
  }

  toStoreData() : Uint8Array {
    if (this.identPriv == null) {
      throw new Error("The private key must be set.");
    }

    let storeDataLength = this.identPub!.byteLength + this.r!.byteLength + this.s!.byteLength + this.identPriv.byteLength + 1;
    let storeData = new Uint8Array(storeDataLength);
    let off = 0;

    storeData.set(this.identPub, off);
    off += this.identPub.byteLength;
    storeData.set(this.r!, off);
    off += this.r!.byteLength;
    storeData.set(this.s!, off);
    off += this.s!.byteLength;
    storeData[off] = this.recId!;
    off += 1;
    storeData.set(this.identPriv, off);
    return storeData;
  }

}