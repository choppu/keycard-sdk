import { Commandset } from "./commandset"
import { Pairing } from "./pairing"
import { ApplicationInfo } from "./application-info"
import { ApplicationStatus } from "./application-status"
import { APDUCommand } from "./apdu-command"
import { BERTLV } from "./ber-tlv"
import { BIP32KeyPair } from "./bip32key"
import { CashApplicationInfo } from "./cash-application-info"
import { CashCommandset } from "./cash-commandset"
import { Ethereum } from "./ethereum"
import { KeyPath } from "./key-path"
import { Mnemonic } from "./mnemonic"
import { RecoverableSignature } from "./recoverable-signature"


export let Keycard = {
  Commandset: Commandset,
  Pairing: Pairing,
  ApplicationInfo: ApplicationInfo,
  ApplicationStatus: ApplicationStatus,
  APDUCommand: APDUCommand,
  BERTLV: BERTLV,
  BIP32KeyPair: BIP32KeyPair,
  CashApplicationInfo: CashApplicationInfo,
  CashCommandset: CashCommandset,
  Ethereum: Ethereum,
  KeyPath: KeyPath,
  Mnemonic: Mnemonic,
  RecoverableSignature: RecoverableSignature
}

export default Keycard;
Object.assign(module.exports, Keycard);