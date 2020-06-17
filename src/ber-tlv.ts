const TLV_BOOL = 0x01;
export const TLV_INT = 0x02;
export const END_OF_TLV = 0xffffffff;

export class BERTLV {
  buffer: Uint8Array;
  position: number;

  constructor(buffer: Uint8Array) {
    this.buffer = buffer;
    this.position = 0;
  }

  enterConstructed(tag: number) : number {
    this.checkTag(tag, this.readTag());
    return this.readLength();
  }

  readPrimitive(tag: number) : Uint8Array {
    this.checkTag(tag, this.readTag());
    let len = this.readLength();
    this.position += len;
    return this.buffer.subarray((this.position - len), this.position);
  }

  readBoolean() : boolean {
    let val = this.readPrimitive(TLV_BOOL);
    return val[0] == 0xff;
  }

  readInt() : number {
    let val = this.readPrimitive(TLV_INT);

    switch (val.byteLength) {
      case 1:
        return val[0];
      case 2:
        return (val[0] << 8) | val[1];
      case 3:
        return (val[0] << 16) | (val[1] << 8) | val[2];
      case 4:
        return (val[0] << 24) | (val[1] << 16) | (val[2] << 8) | val[3];
      default:
        throw new Error("Integers of length " + val.byteLength + " are unsupported");
    }
  }

  readTag() : number {
    return (this.position < this.buffer.byteLength) ? this.buffer[this.position++] : END_OF_TLV;
  }

  readLength() : number {
    let len = this.buffer[this.position++];

    if (len == 0x81) {
      len = this.buffer[this.position++];
    }

    return len;
  }

  unreadLastTag() : void {
    if (this.position < this.buffer.byteLength) {
      this.position--;
    }
  }

  checkTag(expected: number, actual: number) : void {
    if (expected != actual) {
      this.unreadLastTag();
      throw new Error("Expected tag: 0x" + expected.toString(16) + ", received: 0x" + actual.toString(16));
    }
  }
}