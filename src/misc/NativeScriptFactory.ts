import { Buffer } from "buffer";
import * as cbors from "@stricahq/cbors";
import { CLINativeScript, NativeScript } from "../types";
import { hash28 } from "../utils/crypto";
import { encodeNativeScript } from "../utils/encoder";

export class NativeScriptFactory {
  private nativeScript: NativeScript;
  private _cbor: Buffer;
  private _policyId: Buffer;

  /**
   *
   * @param nativeScript - the native script json as per the CDDL schema, use fromCliJSON to convert from the CLI format
   */
  constructor(nativeScript: NativeScript) {
    this.nativeScript = nativeScript;
    const encodedNativeScript = encodeNativeScript(nativeScript);
    this._cbor = cbors.Encoder.encode(encodedNativeScript);
    this._policyId = hash28(Buffer.from(`00${this._cbor.toString("hex")}`, "hex"));
  }

  cbor(): Buffer {
    return this._cbor;
  }

  policyId(): Buffer {
    return this._policyId;
  }

  json(): NativeScript {
    return this.nativeScript;
  }

  static fromCliJSON(cliNativeScript: CLINativeScript): NativeScriptFactory {
    const convert = (script: CLINativeScript): NativeScript => {
      if ("type" in script) {
        switch (script.type) {
          case "sig":
            return { pubKeyHash: script.keyHash };
          case "all":
            return {
              all: script.scripts.map((s) => convert(s)),
            };
          case "any":
            return {
              any: script.scripts.map((s) => convert(s)),
            };
          case "atLeast":
            return {
              n: script.required,
              k: script.scripts.map((s) => convert(s)),
            };
          case "after":
            return { invalidBefore: script.slot };
          case "before":
            return { invalidAfter: script.slot };
          default:
            throw new Error(`Unknown script type: ${(script as any).type}`);
        }
      }
      throw new Error("Invalid script format");
    };

    const nativeScript = convert(cliNativeScript);
    return new NativeScriptFactory(nativeScript);
  }
}

export default NativeScriptFactory;
