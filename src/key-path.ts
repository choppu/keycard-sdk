import { Constants } from "./constants";
import { CryptoUtils } from "./crypto-utils";

export class KeyPath {
  source: number;
  data: Uint8Array;

  parseComponent(num: string) : number {
    let sign;

    if (num.endsWith("'")) {
      sign = 0x80000000;
      num = num.substring(0, (num.length - 1));
    } else {
      sign = 0;
    }

    if (!CryptoUtils.checkAllDigits(num)) {
      throw new Error ("Error: Only digits allowed");
    }

    return (sign | parseInt(num));
  }

  writeComponent(component: number, i: number) : void {
    let off = i * 4;

    this.data[off] = component >> 24;
    this.data[off + 1] = component >> 16;
    this.data[off + 2] = component >> 8;
    this.data[off + 3] = component;
  }

  constructor(data: string | Uint8Array, source = Constants.DERIVE_SOURCE.deriveP1SourceMaster) {
    if(typeof data === "string") {
      let i = 0;
      let dataArr = data.split("/");
      let sourceOrFirstElement = dataArr[i++];
      let len = dataArr.length;

      switch(sourceOrFirstElement) {
      case "m":
        this.source = Constants.DERIVE_SOURCE.deriveP1SourceMaster;
        len--;
        break;
      case "..":
        this.source = Constants.DERIVE_SOURCE.deriveP1SourceParent;
        len--;
        break;
      case ".":
        this.source = Constants.DERIVE_SOURCE.deriveP1SourceCurrent;
        len--;
        break;
      default:
        this.source = Constants.DERIVE_SOURCE.deriveP1SourceCurrent;
        i--;
        break;
      }

      if (len > 10) {
        throw new Error("Error: Too many components");
      }

      this.data = new Uint8Array(4 * len);

      for(let y = 0; y < len; i++, y++) {
        let component = this.parseComponent(dataArr[i]);
        this.writeComponent(component, y);
      }
    } else {
      this.source = source;
      this.data = data;
    }
  }

  appendComponent(sb: string[], i: number) : void {
    let num = ((this.data[i] & 0x7f) << 24) | (this.data[i+1] << 16) | (this.data[i+2] << 8) | this.data[i+3];
    sb.push(num.toString());

    if ((this.data[i] & 0x80) == 0x80) {
      sb.push("'");
    }
  }

  toString() : string {
    let sb = [];

    switch(this.source) {
      case Constants.DERIVE_SOURCE.deriveP1SourceMaster:
        sb.push("m");
        break;
      case Constants.DERIVE_SOURCE.deriveP1SourceParent:
        sb.push("..");
        break;
      case Constants.DERIVE_SOURCE.deriveP1SourceCurrent:
        sb.push(".");
        break;
    }

    for (let i = 0; i < this.data.byteLength; i += 4) {
      sb.push('/');
      this.appendComponent(sb, i);
    }

    return sb.join('');
  }
}