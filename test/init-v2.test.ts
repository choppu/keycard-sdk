import * as secp from '@noble/secp256k1';
import { hkdf } from '@noble/hashes/hkdf';
import { sha256 } from '@noble/hashes/sha2';

import { AESCCM } from '../src/aes-ccm';
import { APDUCommand } from '../src/apdu-command';
import { APDUResponse } from '../src/apdu-response';
import { BIP32KeyPair } from '../src/bip32key';
import { CardChannel } from '../src/card-channel';
import { Certificate } from '../src/certificate';
import { Commandset } from '../src/commandset';
import { CryptoUtils } from '../src/crypto-utils';

const INS_SELECT = 0xa4;
const INS_OPEN_SECURE_CHANNEL = 0x10;
const INS_SECURED_APDU = 0x18;
const INS_INIT = 0xfe;

const LABEL = new Uint8Array(Array.from('sc_v2_ccm', c => c.charCodeAt(0)));
const OK = new Uint8Array([0x90, 0x00]);

function tlv(tag: number, value: Uint8Array | number[]): number[] {
  return [tag, value.length, ...value];
}

function concat(...parts: (Uint8Array | number[])[]): Uint8Array {
  return new Uint8Array(parts.flatMap(part => Array.from(part)));
}

/** An ASN.1 INTEGER: no leading zeros, and a zero byte in front of a set top bit. */
function derInteger(value: Uint8Array): number[] {
  let start = 0;
  while (start < value.length - 1 && value[start] === 0) {
    start++;
  }
  const bytes = Array.from(value.subarray(start));
  return tlv(0x02, bytes[0] & 0x80 ? [0, ...bytes] : bytes);
}

/** The card signs in DER, which this version of noble does not produce. */
function toDer(compact: Uint8Array): Uint8Array {
  return new Uint8Array(
    tlv(0x30, [...derInteger(compact.subarray(0, 32)), ...derInteger(compact.subarray(32, 64))]),
  );
}

/** A blank applet 4.0 card, as far as SELECT, the V2 handshake and INIT go. */
class BlankV4Card implements CardChannel {
  readonly received: APDUCommand[] = [];
  /** The INIT command as the card saw it, once decrypted. */
  init: { ins: number; data: Uint8Array } | null = null;

  private readonly identPriv = secp.utils.randomSecretKey();
  private readonly certificate: Uint8Array;
  private keyH2C: Uint8Array | null = null;
  private keyC2H: Uint8Array | null = null;
  private nonce = new Uint8Array(13);

  constructor(caPair: BIP32KeyPair) {
    const identPub = secp.getPublicKey(this.identPriv, false);
    const ident = new BIP32KeyPair(this.identPriv, new Uint8Array(0), identPub);
    this.certificate = Certificate.createCertificate(caPair, ident).toStoreData().subarray(0, 98);
  }

  isConnected(): boolean {
    return true;
  }

  // Asynchronous, like every real channel. That is what gives a missing await
  // in the caller room to go wrong.
  async send(cmd: APDUCommand): Promise<APDUResponse> {
    await new Promise(resolve => setTimeout(resolve, 0));
    this.received.push(cmd);

    switch (cmd.ins) {
      case INS_SELECT:
        return new APDUResponse(concat(this.selectTemplate(), OK));
      case INS_OPEN_SECURE_CHANNEL:
        return new APDUResponse(concat(this.handshake(cmd.data), OK));
      case INS_SECURED_APDU:
        return new APDUResponse(concat(this.secured(cmd.data), OK));
      default:
        // Outside the channel the applet answers nothing else.
        return new APDUResponse(new Uint8Array([0x69, 0x85]));
    }
  }

  private selectTemplate(): Uint8Array {
    const body = [
      ...tlv(0x02, [0x04, 0x00]), // applet version 4.0
      ...tlv(0x8c, [0x00]), // status: not initialized
      ...tlv(0x8e, []), // no key loaded
      ...tlv(0x8d, [0x1f]), // capabilities, secure channel included
      ...tlv(0x8a, this.certificate),
    ];
    return new Uint8Array(tlv(0xa4, body));
  }

  private handshake(request: Uint8Array): Uint8Array {
    const salt = request.subarray(0, 32);
    const clientPub = request.subarray(32);
    const ephPriv = secp.utils.randomSecretKey();
    const ephPub = secp.getPublicKey(ephPriv, false);

    const shared = secp.getSharedSecret(ephPriv, clientPub).subarray(1);
    const okm = hkdf(sha256, shared, salt, LABEL, 32);
    this.keyH2C = okm.subarray(0, 16);
    this.keyC2H = okm.subarray(16);
    this.nonce = new Uint8Array(13);

    const transcript = sha256(concat(LABEL, salt, clientPub, ephPub));
    const signature = secp.sign(transcript, this.identPriv, { prehash: false });
    return concat(ephPub, toDer(signature));
  }

  private secured(ciphertext: Uint8Array): Uint8Array {
    const inner = new AESCCM(this.keyH2C!).decrypt(ciphertext, this.nonce);
    this.init = { ins: inner[1], data: inner.subarray(5, 5 + inner[4]) };
    return new AESCCM(this.keyC2H!).encrypt(OK, this.nonce);
  }
}

function newCard() {
  const caPriv = secp.utils.randomSecretKey();
  const caPair = new BIP32KeyPair(caPriv, new Uint8Array(0), secp.getPublicKey(caPriv, false));
  const card = new BlankV4Card(caPair);
  const caPub = CryptoUtils.compressPublicKey(caPair.publicKey);
  return { card, cmdSet: new Commandset(card, [caPub]) };
}

const text = (bytes: Uint8Array) => String.fromCharCode(...bytes);

describe('Commandset.init on a Secure Channel V2 card', () => {
  test('waits for the handshake, then sends INIT inside the channel', async () => {
    const { card, cmdSet } = newCard();
    await cmdSet.select();

    const resp = await cmdSet.init('123456', '123456123456');

    expect(resp.sw).toBe(0x9000);
    expect(card.received.map(cmd => cmd.ins)).toEqual([
      INS_SELECT,
      INS_OPEN_SECURE_CHANNEL,
      INS_SECURED_APDU,
    ]);
    expect(card.init?.ins).toBe(INS_INIT);
    expect(text(card.init!.data)).toBe('123456123456123456');
  });

  // The PIN and the PUK are the payload. Sent outside the channel they cross
  // the air in the clear, and the card refuses them anyway.
  test('never puts the PIN and PUK on the wire unencrypted', async () => {
    const { card, cmdSet } = newCard();
    await cmdSet.select();

    await cmdSet.init('123456', '123456123456');

    expect(card.received.some(cmd => cmd.ins === INS_INIT)).toBe(false);
    for (const cmd of card.received) {
      expect(text(cmd.data)).not.toContain('123456');
    }
  });

  test('sends the retry limits and the alternative PIN when one is given', async () => {
    const { card, cmdSet } = newCard();
    await cmdSet.select();

    await cmdSet.init('123456', '123456123456', undefined, '654321');

    const data = card.init!.data;
    expect(data.length).toBe(26);
    expect(Array.from(data.subarray(18, 20))).toEqual([3, 5]);
    expect(text(data.subarray(20))).toBe('654321');
  });
});
