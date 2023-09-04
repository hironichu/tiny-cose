import {
  EC2_CRV_ALL,
  EC2_CRV_P256,
  EC2_CRV_P384,
  EC2_CRV_P521,
  ECDSA_ALG,
  ECDSA_SHA_256,
  ECDSA_SHA_384,
  ECDSA_SHA_512,
  EDDSA,
  HMAC_SHA_256,
  HMAC_SHA_384,
  HMAC_SHA_512,
  KEY_OP_MAC_CREATE,
  KEY_OP_MAC_VERIFY,
  KEY_OP_SIGN,
  KEY_OP_VERIFY,
  KEY_OPS_ALL,
  KTY_EC2,
  KTY_OKP,
  KTY_RSA,
  KTY_SYMMETRIC,
  OKP_CRV_ED25519,
  RSASSA_PKCS1_v1_5_SHA_256,
  RSASSA_PKCS1_v1_5_SHA_384,
  RSASSA_PKCS1_v1_5_SHA_512,
  RSASSA_PSS_SHA_256,
  RSASSA_PSS_SHA_384,
  RSASSA_PSS_SHA_512,
} from "./constants.ts";
import { CBORType } from "./deps.ts";
import { COSEKeyAll } from "./index.ts";
import {
  ECDSA_Private_COSE_Key,
  ECDSA_Public_COSE_Key,
  EDDSA_Private_COSE_Key,
  EDDSA_Public_COSE_Key,
  HMAC_COSE_Key,
  RSAPrivateKey,
  RSAPublicKey,
  RSASSA_PKCS1_v1_5_Private_COSE_Key,
  RSASSA_PKCS1_v1_5_Public_COSE_Key,
  RSASSA_PSS_Private_COSE_Key,
  RSASSA_PSS_Public_COSE_Key,
} from "./types.ts";

export function parseCBORToCOSEKey(cbor: CBORType): COSEKeyAll {
  if (!(cbor instanceof Map)) {
    throw new Error("Unsupported CBOR input");
  }
  const kid = cbor.get(2);
  const alg = cbor.get(3);
  const crv = cbor.get(-1);
  const key_ops = cbor.get(4);
  const kty = cbor.get(1);
  let keyOps: undefined | KEY_OPS_ALL[];
  if (kid && !(kid instanceof Uint8Array)) {
    throw new Error('Unsupported "kid"');
  }
  if (key_ops) {
    if (!Array.isArray(key_ops)) {
      throw new Error('Unsupported "key_ops"');
    }
    keyOps = [];
    for (const op of key_ops) {
      if (
        op == KEY_OP_MAC_CREATE || op == KEY_OP_MAC_VERIFY ||
        op == KEY_OP_SIGN || op == KEY_OP_VERIFY
      ) {
        keyOps.push(op);
      } else {
        throw new Error(`Unsupported "key_ops" operation ${op}`);
      }
    }
  }
  if (
    kty == KTY_RSA &&
    (alg == RSASSA_PKCS1_v1_5_SHA_256 || alg == RSASSA_PKCS1_v1_5_SHA_384 ||
      alg == RSASSA_PKCS1_v1_5_SHA_512 || alg == RSASSA_PSS_SHA_256 ||
      alg == RSASSA_PSS_SHA_384 || alg == RSASSA_PSS_SHA_512)
  ) {
    const n = cbor.get(-1);
    const e = cbor.get(-2);

    if (!(n instanceof Uint8Array) || !(e instanceof Uint8Array)) {
      throw new Error("Malformed COSE key");
    }
    const publicKey: RSAPublicKey = {
      n,
      e,
    };
    const d = cbor.get(-3);
    const p = cbor.get(-4);
    const q = cbor.get(-5);
    const dP = cbor.get(-6);
    const dQ = cbor.get(-7);
    const qInv = cbor.get(-8);
    if (d || p || q || dP || dQ || qInv) {
      if (
        !(d instanceof Uint8Array) || !(p instanceof Uint8Array) ||
        !(q instanceof Uint8Array) || !(dP instanceof Uint8Array) ||
        !(dQ instanceof Uint8Array) || !(qInv instanceof Uint8Array)
      ) {
        throw new Error("Malformed COSE key");
      }
      const privateKey: RSAPrivateKey = {
        ...publicKey,
        d,
        p,
        q,
        dP,
        dQ,
        qInv,
      };
      if (keyOps) {
        for (const op of keyOps) {
          if (op != KEY_OP_SIGN && op != KEY_OP_VERIFY) {
            throw new Error(
              `Unsupported "key_ops" operation ${op} on private RSA key`,
            );
          }
        }
      }

      const result:
        | RSASSA_PKCS1_v1_5_Private_COSE_Key
        | RSASSA_PSS_Private_COSE_Key = {
          ...privateKey,
          alg,
          kty: KTY_RSA,
          kid: kid as Uint8Array,
          key_ops: keyOps as
            | (typeof KEY_OP_SIGN | typeof KEY_OP_VERIFY)[]
            | undefined,
        };
      return result;
    } else {
      if (keyOps) {
        for (const op of keyOps) {
          if (op != KEY_OP_VERIFY) {
            throw new Error(
              `Unsupported "key_ops" operation ${op} on public RSA key`,
            );
          }
        }
      }
      const result:
        | RSASSA_PKCS1_v1_5_Public_COSE_Key
        | RSASSA_PSS_Public_COSE_Key = {
          ...publicKey,
          alg,
          kty: KTY_RSA,
          kid: kid as Uint8Array,
          key_ops: keyOps as (typeof KEY_OP_VERIFY)[] | undefined,
        };
      return result;
    }
  } else if (
    kty == KTY_EC2 &&
    (alg == ECDSA_SHA_256 || alg == ECDSA_SHA_384 || alg == ECDSA_SHA_512 ||
      crv == EC2_CRV_P256 || crv == EC2_CRV_P384 || crv == EC2_CRV_P521)
  ) {
    const crv = cbor.get(-1); // Elliptic curve
    const x = cbor.get(-2); // X coordinate
    const y = cbor.get(-3); // Y coordinate
    let ecdsaAlg: ECDSA_ALG;
    let ecdsaCrv: EC2_CRV_ALL;
    if (!alg && crv) {
      ecdsaCrv = crv as EC2_CRV_ALL;
      switch (crv) {
        case EC2_CRV_P256:
          ecdsaAlg = ECDSA_SHA_256;
          break;
        case EC2_CRV_P384:
          ecdsaAlg = ECDSA_SHA_384;
          break;
        case EC2_CRV_P521:
          ecdsaAlg = ECDSA_SHA_512;
          break;
        default:
          throw new Error("Unreachable");
      }
    } else {
      ecdsaAlg = alg as ECDSA_ALG;
      switch (alg) {
        case ECDSA_SHA_256:
          ecdsaCrv = EC2_CRV_P256;
          break;
        case ECDSA_SHA_384:
          ecdsaCrv = EC2_CRV_P384;
          break;
        case ECDSA_SHA_512:
          ecdsaCrv = EC2_CRV_P521;
          break;
        default:
          throw new Error("Unreachable");
      }
    }

    if (!(x instanceof Uint8Array) || !(y instanceof Uint8Array)) {
      throw new Error("Malformed COSE key");
    }
    if (
      ecdsaCrv != EC2_CRV_P256 && ecdsaCrv != EC2_CRV_P384 &&
      ecdsaCrv != EC2_CRV_P521
    ) {
      throw new Error(`Unsupported elliptic curve ${ecdsaCrv}`);
    }
    const d = cbor.get(-4); // Private key
    if (d) {
      if (keyOps) {
        for (const op of keyOps) {
          if (op != KEY_OP_VERIFY && op != KEY_OP_SIGN) {
            throw new Error(
              `Unsupported "key_ops" operation ${op} on private EC2 key`,
            );
          }
        }
      }
      if (!(d instanceof Uint8Array)) {
        throw new Error("Malformed COSE key");
      }
      const privateKey: ECDSA_Private_COSE_Key = {
        x,
        y,
        d,
        alg: ecdsaAlg,
        kty: KTY_EC2,
        kid: kid as Uint8Array,
        key_ops: keyOps as
          | (typeof KEY_OP_VERIFY | typeof KEY_OP_VERIFY)[]
          | undefined,
        crv: ecdsaCrv,
      };
      return privateKey;
    } else {
      if (keyOps) {
        for (const op of keyOps) {
          if (op != KEY_OP_VERIFY) {
            throw new Error(
              `Unsupported "key_ops" operation ${op} on public EC2 key`,
            );
          }
        }
      }
      const publicKey: ECDSA_Public_COSE_Key = {
        x,
        y,
        alg: ecdsaAlg,
        kty: KTY_EC2,
        kid: kid as Uint8Array,
        key_ops: keyOps as (typeof KEY_OP_VERIFY)[] | undefined,
        crv: ecdsaCrv,
      };
      return publicKey;
    }
  } else if (
    kty == KTY_SYMMETRIC &&
    (alg == HMAC_SHA_256 || alg == HMAC_SHA_384 || alg == HMAC_SHA_512)
  ) {
    const k = cbor.get(-1); // Key value
    if (!(k instanceof Uint8Array)) {
      throw new Error("Malformed COSE key");
    }
    if (keyOps) {
      for (const op of keyOps) {
        if (op != KEY_OP_MAC_VERIFY && op != KEY_OP_MAC_CREATE) {
          throw new Error(
            `Unsupported "key_ops" operation ${op} on public EC2 key`,
          );
        }
      }
    }

    const symmetricKey: HMAC_COSE_Key = {
      k,
      alg,
      kty: KTY_SYMMETRIC,
      kid: kid as Uint8Array,
      key_ops: keyOps as
        | (typeof KEY_OP_MAC_CREATE | typeof KEY_OP_MAC_VERIFY)[]
        | undefined,
    };
    return symmetricKey;
  } else if (kty == KTY_OKP && alg == EDDSA) {
    const crv = cbor.get(-1); // Elliptic curve
    const x = cbor.get(-2); // Public X coordinate

    if (!(x instanceof Uint8Array)) {
      throw new Error("Malformed COSE key");
    }
    if (crv != OKP_CRV_ED25519) {
      throw new Error(`Unsupported elliptic curve ${crv}`);
    }
    const d = cbor.get(-4); // Private key
    if (d) {
      if (keyOps) {
        for (const op of keyOps) {
          if (op != KEY_OP_VERIFY && op != KEY_OP_SIGN) {
            throw new Error(
              `Unsupported "key_ops" operation ${op} on private EdDSA key`,
            );
          }
        }
      }
      if (!(d instanceof Uint8Array)) {
        throw new Error("Malformed COSE key");
      }
      const privateKey: EDDSA_Private_COSE_Key = {
        x,
        d,
        alg,
        kty: KTY_OKP,
        kid: kid as Uint8Array,
        key_ops: keyOps as [typeof KEY_OP_VERIFY] | undefined,
        crv,
      };
      return privateKey;
    } else {
      if (keyOps) {
        for (const op of keyOps) {
          if (op != KEY_OP_VERIFY) {
            throw new Error(
              `Unsupported "key_ops" operation ${op} on public EdDSA key`,
            );
          }
        }
      }
      const publicKey: EDDSA_Public_COSE_Key = {
        x,
        alg,
        kty: KTY_OKP,
        kid: kid as Uint8Array,
        key_ops: keyOps as [typeof KEY_OP_VERIFY] | undefined,
        crv,
      };
      return publicKey;
    }
  } else {
    throw new Error("Unsupported algorithm");
  }
}
