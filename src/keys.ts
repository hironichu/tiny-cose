import { encodeBase64Url } from "https://deno.land/x/tiny_encodings@0.2.1/encoding.ts";
import {
  EC2_CRV_P256,
  EC2_CRV_P384,
  EC2_CRV_P521,
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
import { CBORType, decodeBase64Url } from "./deps.ts";
import {
  COSEPrivateKey,
  COSEPublicKey,
  COSESymmetricKey,
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
import { COSEKeyAll } from "./index.ts";

function keyOps(
  ops: string[],
  mac: boolean,
): KEY_OPS_ALL[] {
  const out: KEY_OPS_ALL[] = [];
  for (const op of ops) {
    if (op == "sign") {
      out.push(mac ? KEY_OP_MAC_CREATE : KEY_OP_SIGN);
    } else if (op == "verify") {
      out.push(mac ? KEY_OP_MAC_VERIFY : KEY_OP_VERIFY);
    }
  }
  return out;
}

type JWK_RSA_Public = { n: string; e: string };
type JWK_RSA_Private = {
  d: string;
  p: string;
  q: string;
  dp: string;
  dq: string;
  qi: string;
};
type JWK_EC2_Public = { x: string; y: string };

export interface ImportedKey {
  key: CryptoKey;
  kid?: Uint8Array;
}

function rsaPublic(jwk: JWK_RSA_Public): { n: Uint8Array; e: Uint8Array } {
  return {
    n: decodeBase64Url(jwk.n),
    e: decodeBase64Url(jwk.e),
  };
}
function rsaPrivate(
  jwk: JWK_RSA_Private,
): {
  d: Uint8Array;
  p: Uint8Array;
  q: Uint8Array;
  dP: Uint8Array;
  dQ: Uint8Array;
  qInv: Uint8Array;
} {
  return {
    d: decodeBase64Url(jwk.d),
    p: decodeBase64Url(jwk.p),
    q: decodeBase64Url(jwk.q),
    dP: decodeBase64Url(jwk.dp),
    dQ: decodeBase64Url(jwk.dq),
    qInv: decodeBase64Url(jwk.qi),
  };
}
function ec2Public(jwk: JWK_EC2_Public): { x: Uint8Array; y: Uint8Array } {
  return {
    x: decodeBase64Url(jwk.x),
    y: decodeBase64Url(jwk.y),
  };
}

export async function exportPrivateKey(
  key: CryptoKey,
  kid?: Uint8Array,
): Promise<COSEPrivateKey> {
  if (!key.extractable) {
    throw new Error("Key is not extractable");
  }
  const jwk = await crypto.subtle.exportKey("jwk", key);
  if (
    jwk.alg == "RS256" || jwk.alg == "RS384" || jwk.alg == "RS512"
  ) {
    const alg = jwk.alg == "RS256"
      ? RSASSA_PKCS1_v1_5_SHA_256
      : jwk.alg == "RS384"
      ? RSASSA_PKCS1_v1_5_SHA_384
      : RSASSA_PKCS1_v1_5_SHA_512;
    const out: RSASSA_PKCS1_v1_5_Private_COSE_Key = {
      kty: KTY_RSA,
      alg,
      kid,
      key_ops: keyOps(
        jwk.key_ops as string[],
        false,
      ) as (typeof KEY_OP_SIGN | typeof KEY_OP_VERIFY)[],
      ...rsaPublic(jwk as JWK_RSA_Public),
      ...rsaPrivate(jwk as JWK_RSA_Private),
    };
    return out;
  } else if (jwk.alg == "PS256" || jwk.alg == "PS384" || jwk.alg == "PS512") {
    const alg = jwk.alg == "PS256"
      ? RSASSA_PSS_SHA_256
      : jwk.alg == "PS384"
      ? RSASSA_PSS_SHA_384
      : RSASSA_PSS_SHA_512;
    const out: RSASSA_PSS_Private_COSE_Key = {
      kty: KTY_RSA,
      alg,
      kid,
      key_ops: keyOps(
        jwk.key_ops as string[],
        false,
      ) as (typeof KEY_OP_VERIFY)[],
      ...rsaPublic(jwk as JWK_RSA_Public),
      ...rsaPrivate(jwk as JWK_RSA_Private),
    };
    return out;
  } else if (
    (jwk.alg == "ES256" || jwk.alg == "ES384") && jwk.d
  ) {
    // ES512 is not yet supported in Deno
    // https://github.com/denoland/deno/issues/13449
    const alg = jwk.alg == "ES256" ? ECDSA_SHA_256 : ECDSA_SHA_384;
    const crv = jwk.alg == "ES256" ? EC2_CRV_P256 : EC2_CRV_P384;
    const out: ECDSA_Private_COSE_Key = {
      kty: KTY_EC2,
      alg,
      kid,
      crv,
      key_ops: keyOps(
        jwk.key_ops as string[],
        false,
      ) as (typeof KEY_OP_SIGN | typeof KEY_OP_VERIFY)[],
      ...ec2Public(jwk as JWK_EC2_Public),
      d: decodeBase64Url(jwk.d),
    };
    return out;
  }
  throw new Error(`Unsupported key ${jwk.alg}`);
}

// deno-lint-ignore require-await
export async function importPrivateKey(
  _key: COSEPrivateKey,
  _extractable?: boolean,
): Promise<ImportedKey> {
  throw new Error("Unimplemented");
}

export async function exportPublicKey(
  key: CryptoKey,
  kid?: Uint8Array,
): Promise<COSEPublicKey> {
  const jwk = await crypto.subtle.exportKey("jwk", key);
  if (jwk.alg == "RS256" || jwk.alg == "RS384" || jwk.alg == "RS512") {
    const alg = jwk.alg == "RS256"
      ? RSASSA_PKCS1_v1_5_SHA_256
      : jwk.alg == "RS384"
      ? RSASSA_PKCS1_v1_5_SHA_384
      : RSASSA_PKCS1_v1_5_SHA_512;
    const out: RSASSA_PKCS1_v1_5_Public_COSE_Key = {
      kty: KTY_RSA,
      alg,
      kid,
      key_ops: keyOps(
        jwk.key_ops as string[],
        false,
      ) as (typeof KEY_OP_VERIFY)[],
      ...rsaPublic(jwk as JWK_RSA_Public),
    };
    return out;
  } else if (jwk.alg == "PS256" || jwk.alg == "PS384" || jwk.alg == "PS512") {
    const alg = jwk.alg == "PS256"
      ? RSASSA_PSS_SHA_256
      : jwk.alg == "PS384"
      ? RSASSA_PSS_SHA_384
      : RSASSA_PSS_SHA_512;
    const out: RSASSA_PSS_Public_COSE_Key = {
      kty: KTY_RSA,
      alg,
      kid,
      key_ops: keyOps(
        jwk.key_ops as string[],
        false,
      ) as (typeof KEY_OP_VERIFY)[],
      ...rsaPublic(jwk as JWK_RSA_Public),
    };
    return out;
  } else if (jwk.alg == "ES256" || jwk.alg == "ES384") {
    // ES512 is not yet supported in Deno
    // https://github.com/denoland/deno/issues/13449
    const alg = jwk.alg == "ES256" ? ECDSA_SHA_256 : ECDSA_SHA_384;
    const crv = jwk.alg == "ES256" ? EC2_CRV_P256 : EC2_CRV_P384;
    const out: ECDSA_Public_COSE_Key = {
      kty: KTY_EC2,
      alg,
      kid,
      crv,
      key_ops: keyOps(
        jwk.key_ops as string[],
        false,
      ) as (typeof KEY_OP_VERIFY)[],
      ...ec2Public(jwk as JWK_EC2_Public),
    };
    return out;
  }
  throw new Error(`Unsupported key ${jwk.alg}`);
}

// deno-lint-ignore require-await
export async function importPublicKey(_cbor: CBORType): Promise<ImportedKey> {
  throw new Error("Unimplemented");
}

export async function exportSymmetricKey(
  key: CryptoKey,
  kid?: Uint8Array,
): Promise<COSESymmetricKey> {
  if (!key.extractable) {
    throw new Error("Key is not extractable");
  }
  const jwk = await crypto.subtle.exportKey("jwk", key);
  if (
    (jwk.alg == "HS256" || jwk.alg == "HS384" || jwk.alg == "HS512") && jwk.k
  ) {
    const alg = jwk.alg == "HS256"
      ? HMAC_SHA_256
      : jwk.alg == "HS384"
      ? HMAC_SHA_384
      : HMAC_SHA_512;
    const out: HMAC_COSE_Key = {
      kty: KTY_SYMMETRIC,
      alg,
      kid,
      key_ops: keyOps(
        jwk.key_ops as string[],
        true,
      ) as (typeof KEY_OP_MAC_CREATE | typeof KEY_OP_MAC_VERIFY)[],
      k: decodeBase64Url(jwk.k),
    };
    return out;
  }
  throw new Error(`Unsupported key ${jwk.alg}`);
}

function cborTypeToCOSEKey(cbor: CBORType): COSEKeyAll {
  if (!(cbor instanceof Map)) {
    throw new Error("Unsupported CBOR input");
  }
  const kid = cbor.get(2);
  const alg = cbor.get(3);
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
    (alg == ECDSA_SHA_256 || alg == ECDSA_SHA_384 || alg == ECDSA_SHA_512)
  ) {
    const crv = cbor.get(-1); // Elliptic curve
    const x = cbor.get(-2); // X coordinate
    const y = cbor.get(-3); // Y coordinate

    if (!(x instanceof Uint8Array) || !(y instanceof Uint8Array)) {
      throw new Error("Malformed COSE key");
    }
    if (crv != EC2_CRV_P256 && crv != EC2_CRV_P384 && crv != EC2_CRV_P521) {
      throw new Error(`Unsupported elliptic curve ${crv}`);
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
        alg,
        kty: KTY_EC2,
        kid: kid as Uint8Array,
        key_ops: keyOps as
          | (typeof KEY_OP_VERIFY | typeof KEY_OP_VERIFY)[]
          | undefined,
        crv,
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
        alg,
        kty: KTY_EC2,
        kid: kid as Uint8Array,
        key_ops: keyOps as (typeof KEY_OP_VERIFY)[] | undefined,
        crv,
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

export async function importSymmetricKey(
  cbor: CBORType,
  extractable?: boolean,
): Promise<ImportedKey> {
  const key = cborTypeToCOSEKey(cbor);

  if (
    key.alg != HMAC_SHA_256 && key.alg != HMAC_SHA_384 &&
    key.alg != HMAC_SHA_512
  ) {
    throw new Error("Key algorithm not supported");
  }
  const alg = key.alg == HMAC_SHA_256
    ? "HS256"
    : key.alg == HMAC_SHA_384
    ? "HS384"
    : "HS512";
  const key_ops: KeyUsage[] = [];
  if (key.key_ops) {
    for (const op of key.key_ops) {
      if (op == KEY_OP_MAC_CREATE) {
        key_ops.push("sign");
      } else if (op == KEY_OP_MAC_VERIFY) {
        key_ops.push("verify");
      }
    }
  } else {
    key_ops.push("sign");
    key_ops.push("verify");
  }

  const jwk: JsonWebKey = {
    alg,
    kty: "oct",
    key_ops,
    k: encodeBase64Url(key.k),
  };
  const hashName = key.alg == HMAC_SHA_256
    ? "SHA-256"
    : key.alg == HMAC_SHA_384
    ? "SHA-384"
    : "SHA-512";

  const cryptoKey = await crypto.subtle.importKey(
    "jwk",
    jwk,
    {
      name: "HMAC",
      hash: { name: hashName },
    },
    extractable || false,
    key_ops,
  );
  return { key: cryptoKey, kid: key.kid };
}
