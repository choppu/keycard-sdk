import { GlobalPlatformCommandset } from "./global-platform-commandset";
import { GlobalPlatformCrypto } from "./global-platform-crypto";
import { GlobalPlatformConstants } from "./global-platform-constants";
import { SCP02Channel } from "./SCP02-channel";
import { SCP02Keys } from "./scp02-keys";
import { SCP02Session } from "./scp02-session";
import { SCP02Wrapper } from "./scp02-wrapper";
import { Load } from "./load";

export let GlobalPlatform = {
  GlobalPlatformCommandset: GlobalPlatformCommandset,
  GlobalPlatformCrypto: GlobalPlatformCrypto,
  GlobalPlatformConstants: GlobalPlatformConstants,
  SCP02Channel: SCP02Channel,
  SCP02Keys: SCP02Keys,
  SCP02Session: SCP02Session,
  SCP02Wrapper: SCP02Wrapper,
  Load: Load
}

export default GlobalPlatform;
Object.assign(module.exports, GlobalPlatform);