import { BERTLV } from "./ber-tlv";
import { Constants } from "./constants";
import { CryptoUtils } from "./crypto-utils";
import { KeyPair } from "./keypair";
import { RecoverableSignature } from "./recoverable-signature";

const CryptoJS = require('crypto-js');
const secp256k1 = require('secp256k1');


const TLV_CERT = 0x8a;

export class Certificate extends RecoverableSignature {
  identPriv: Uint8Array;
  identPub: Uint8Array;

  constructor(publicKey: Uint8Array, compressed: boolean, r: Uint8Array, s: Uint8Array, recId: number) {
    super(publicKey, compressed, r, s, recId);
  }

  generateIdentKeyPair(): KeyPair {
    let privKey = CryptoUtils.generateECPrivateKey();
    let publicKey = secp256k1.publicKeyCreate(privKey, false);
    return new KeyPair(privKey, publicKey);
  }

  createCertificate(caPair: KeyPair, identKeys: KeyPair): Certificate {
    let pub = secp256k1.publicKeyConvert(identKeys.publicKey, true, new Uint8Array(33));
    let hash = CryptoJS.SHA256(pub);
    let signed = secp256k1.ecdsaSign(hash, caPair.privateKey);

    let tlv = new BERTLV(signed);
    tlv.enterConstructed(Constants.TLV_ECDSA_TEMPLATE);
    let r = this.toUInt(tlv.readPrimitive(Constants.TLV_INT));
    let s = this.toUInt(tlv.readPrimitive(Constants.TLV_INT));
    let cert = new Certificate(secp256k1.publicKeyConvert(caPair.publicKey, true, new Uint8Array(33)), true, r, s, -1);
    cert.calculateRecID(hash);
    cert.identPriv = this.toUInt(identKeys.privateKey);
    cert.identPub = pub;

    return cert;
  }

  generateNewCertificate(caPair: KeyPair): Certificate {
    return this.createCertificate(caPair, this.generateIdentKeyPair());
  }

  fromTLV(certData: Uint8Array): Certificate {
      let pubKey = certData.subarray(0, 33);
      let r = certData.subarray(33, 65);
      let s = certData.subarray(65, 97);
      let recId = certData[97];

      let hash = CryptoJS.SHA256(pubKey);
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

    storeData.set(this.identPub, 0);
    storeData.set(this.r, this.identPub.byteLength);
    storeData.set(this.s, this.r.byteLength);
    storeData[this.s.byteLength] = this.recId;
    storeData.set(this.identPriv, this.s.byteLength + 1);

    return storeData;
  }

}