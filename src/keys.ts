import {
  EC2_CRV_P256,
  EC2_CRV_P384,
  EC2_CRV_P521,
  ECDSA_SHA_256,
  ECDSA_SHA_384,
  ECDSA_SHA_512,
  HMAC_SHA_256,
  HMAC_SHA_384,
  HMAC_SHA_512,
  KEY_OP_MAC_CREATE,
  KEY_OP_MAC_VERIFY,
  KEY_OP_SIGN,
  KEY_OP_VERIFY,
  KEY_OPS_ALL,
  KTY_EC2,
  KTY_RSA,
  KTY_SYMMETRIC,
  RSASSA_PKCS1_v1_5_SHA_256,
  RSASSA_PKCS1_v1_5_SHA_384,
  RSASSA_PKCS1_v1_5_SHA_512,
  RSASSA_PSS_SHA_256,
  RSASSA_PSS_SHA_384,
  RSASSA_PSS_SHA_512,
} from "./constants.ts";
import { decodeBase64Url } from "./deps.ts";
import {
  COSE_Private_Key,
  COSE_Public_Key,
  COSE_Symmetric_Key,
  ECDSA_Private_COSE_Key,
  ECDSA_Public_COSE_Key,
  HMAC_COSE_Key,
  RSASSA_PKCS1_v1_5_Private_COSE_Key,
  RSASSA_PKCS1_v1_5_Public_COSE_Key,
  RSASSA_PSS_Private_COSE_Key,
  RSASSA_PSS_Public_COSE_Key,
} from "./types.ts";

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
  p: string;
  q: string;
  dp: string;
  dq: string;
  qi: string;
};
type JWK_EC2_Public = { x: string; y: string };

function rsaPublic(jwk: JWK_RSA_Public): { n: Uint8Array; e: Uint8Array } {
  return {
    n: decodeBase64Url(jwk.n),
    e: decodeBase64Url(jwk.e),
  };
}
function rsaPrivate(
  jwk: JWK_RSA_Private,
): {
  p: Uint8Array;
  q: Uint8Array;
  dP: Uint8Array;
  dQ: Uint8Array;
  qInv: Uint8Array;
} {
  return {
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
): Promise<COSE_Private_Key> {
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

export async function exportPublicKey(
  key: CryptoKey,
  kid?: Uint8Array,
): Promise<COSE_Public_Key> {
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

export async function exportSymmetricKey(
  key: CryptoKey,
  kid?: Uint8Array,
): Promise<COSE_Symmetric_Key> {
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
