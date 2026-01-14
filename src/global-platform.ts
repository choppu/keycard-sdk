import { GlobalPlatformCommandset } from "./global-platform-commandset.ts";
import { GlobalPlatformCrypto } from "./global-platform-crypto.ts";
import { GlobalPlatformConstants } from "./global-platform-constants.ts";
import { SCP02Channel } from "./scp02-channel.ts";
import { SCP02Keys } from "./scp02-keys.ts";
import { SCP02Session } from "./scp02-session.ts";
import { SCP02Wrapper } from "./scp02-wrapper.ts";
import { Load } from "./load.ts";

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