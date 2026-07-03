import { ctr, unsafe } from '@noble/ciphers/aes';
import { concatBytes, clean } from '@noble/ciphers/utils';
import { CryptoUtils } from './crypto-utils.ts';

const BLOCK_SIZE = 16;
const TAG_LENGTH = 8;
const FLAGS_BYTE = 0x19;
const CTR_FLAGS_Q2 = 0x01;

/**
 * AES-CCM (Counter with CBC-MAC) mode implementation.
 * Based on NIST SP 800-38C with customizable flags byte support.
 *
 * CCM combines:
 * - CBC-MAC for authentication
 * - CTR mode for encryption
 */
export class AESCCM {
  private encKey: Uint8Array;
  private xk: Uint32Array;

  constructor(key: Uint8Array) {
    if (key.length != 16 && key.length != 24 && key.length != 32) {
      throw new Error(`AES-CCM: invalid key size, must be 16, 24, or 32 bytes, got ${key.length}`);
    }

    this.encKey = key;
    this.xk = unsafe.expandKeyLE(key);
  }

  /**
   * Encrypt plaintext using AES-CCM.
   *
   * @param data - The data to encrypt
   * @param nonce - Nonce/IV (13 bytes, must not repeat under same key)
   * @returns Concatenation of ciphertext and authentication tag
   */
  encrypt(data: Uint8Array, nonce: Uint8Array): Uint8Array {
    this.validateNonce(nonce.length, data.length);

    const q = BLOCK_SIZE - 1 - nonce.length;
    const ctrNonce = new Uint8Array(16);
    ctrNonce[0] = CTR_FLAGS_Q2;
    ctrNonce.set(nonce, 1);

    // Step 1: Compute the authentication tag using CBC-MAC (over plaintext)
    const mac = this.computeCBCMAC(data, nonce, q);

    // Step 2: Encrypt using CTR mode
    const ciphertext = ctr(this.encKey, ctrNonce).encrypt(data);

    // Return ciphertext || tag (concat first, then clean sensitive data)
    const result = concatBytes(ciphertext, mac);

    console.log(result);

    clean(mac);
    return result;
  }

  /**
   * Decrypt ciphertext using AES-CCM.
   *
   * @param ciphertext - The data to decrypt (ciphertext + authentication tag appended)
   * @param nonce - Nonce/IV used during encryption
   * @returns Decrypted plaintext
   */
  decrypt(ciphertext: Uint8Array, nonce: Uint8Array): Uint8Array {
    if (ciphertext.length < TAG_LENGTH) {
      throw new Error('AES-CCM: ciphertext too short to contain authentication tag');
    }

    // Split ciphertext and tag
    const mac = ciphertext.subarray(ciphertext.length - TAG_LENGTH);
    const ct = ciphertext.subarray(0, ciphertext.length - TAG_LENGTH);

    const ctrNonce = new Uint8Array(16);
    ctrNonce[0] = CTR_FLAGS_Q2;
    ctrNonce.set(nonce, 1);

    this.validateNonce(nonce.length, ct.length);

    const q = BLOCK_SIZE - 1 - nonce.length;

    // Step 1: Decrypt using CTR mode (CTR decrypt = CTR encrypt)
    const plaintext = ctr(this.encKey, ctrNonce).decrypt(ct);

    // Step 2: Verify the authentication tag using CBC-MAC (over plaintext)
    // In CCM, the MAC is computed over the plaintext, so we must decrypt first
    const computedMac = this.computeCBCMAC(plaintext, nonce, q);

    // Constant-time comparison to prevent timing attacks
    if (!CryptoUtils.constantTimeCompare(computedMac, mac)) {
      clean(computedMac);
      throw new Error('AES-CCM: authentication failed');
    }
    clean(computedMac);

    return plaintext;
  }

  /**
   * Compute the CBC-MAC authentication tag per NIST SP 800-38C.
   * No AAD support in this variant.
   */
  private computeCBCMAC(data: Uint8Array, nonce: Uint8Array, q: number): Uint8Array {
    // Build block list: B_0, [P_1..P_m]
    const blocks: Uint8Array[] = [];

    // B_0: flags || nonce || length
    blocks.push(this.formatB0(data.length, nonce, q));

    // Data blocks
    if (data.length > 0) {
      blocks.push(...this.formatData(data));
    }

    console.log(blocks);

    // Compute CBC-MAC over all blocks
    let mac = new Uint8Array(BLOCK_SIZE);

    for (const block of blocks) {
      // XOR block with running MAC
      for (let i = 0; i < BLOCK_SIZE; i++) {
        mac[i] ^= block[i];
      }
      // Encrypt the result
      unsafe.encryptBlock(this.xk, mac);
    }

    // Truncate MAC to desired tag length
    return mac.subarray(0, TAG_LENGTH);
  }

  /**
   * Format the B_0 block: flags || nonce || length
   */
  private formatB0(dataLen: number, nonce: Uint8Array, q: number): Uint8Array {
    const block = new Uint8Array(BLOCK_SIZE);

    // Flags byte
    block[0] = FLAGS_BYTE;

    // Nonce (bytes 1..L, where L = nonce length)
    block.set(nonce, 1);

    // Length field (last q bytes, big-endian)
    const lenOffset = BLOCK_SIZE - q;
    for (let i = 0; i < q; i++) {
      block[lenOffset + i] = (dataLen >> (8 * (q - 1 - i))) & 0xff;
    }

    return block;
  }

  /**
   * Format plaintext/ciphertext into 16-byte blocks (final block zero-padded).
   */
  private formatData(data: Uint8Array): Uint8Array[] {
    const blocks: Uint8Array[] = [];
    let offset = 0;

    while (offset < data.length) {
      const end = Math.min(offset + BLOCK_SIZE, data.length);
      const chunk = data.subarray(offset, end);

      if (chunk.length === BLOCK_SIZE) {
        blocks.push(chunk);
      } else {
        const block = new Uint8Array(BLOCK_SIZE);
        block.set(chunk);
        blocks.push(block);
      }
      offset += BLOCK_SIZE;
    }

    return blocks;
  }

  private validateNonce(nonceLength: number, dataLen: number): void {
    if (nonceLength != 13) {
      throw new Error(`AES-CCM: invalid nonce length, must be 13 bytes, got ${nonceLength}`);
    }

    const q = BLOCK_SIZE - 1 - nonceLength;
    const maxMsgLen = 256 ** q;

    if (dataLen > maxMsgLen) {
      throw new Error(`AES-CCM: data too long, max ${maxMsgLen} bytes for nonce length ${nonceLength}`);
    }
  }
}
