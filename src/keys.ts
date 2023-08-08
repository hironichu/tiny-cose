import {
  EC2_CRV_P256,
  ECDSA_SHA_256,
  HMAC_SHA_256,
  KEY_OP_MAC_CREATE,
  KEY_OP_MAC_VERIFY,
  KEY_OP_SIGN,
  KEY_OP_VERIFY,
  KEY_OPS_ALL,
  KTY_EC2,
  KTY_RSA,
  KTY_SYMMETRIC,
  RSASSA_PKCS1_v1_5_SHA_256,
  RSASSA_PSS_SHA_256,
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
    jwk.alg == "RS256"
  ) {
    const out: RSASSA_PKCS1_v1_5_Private_COSE_Key = {
      kty: KTY_RSA,
      alg: RSASSA_PKCS1_v1_5_SHA_256,
      kid,
      key_ops: keyOps(
        jwk.key_ops as string[],
        false,
      ) as (typeof KEY_OP_SIGN | typeof KEY_OP_VERIFY)[],
      ...rsaPublic(jwk as JWK_RSA_Public),
      ...rsaPrivate(jwk as JWK_RSA_Private),
    };
    return out;
  } else if (jwk.alg == "PS256") {
    const out: RSASSA_PSS_Private_COSE_Key = {
      kty: KTY_RSA,
      alg: RSASSA_PSS_SHA_256,
      kid,
      key_ops: keyOps(
        jwk.key_ops as string[],
        false,
      ) as (typeof KEY_OP_VERIFY)[],
      ...rsaPublic(jwk as JWK_RSA_Public),
      ...rsaPrivate(jwk as JWK_RSA_Private),
    };
    return out;
  } else if (jwk.alg == "ES256" && jwk.d) {
    const out: ECDSA_Private_COSE_Key = {
      kty: KTY_EC2,
      alg: ECDSA_SHA_256,
      kid,
      crv: EC2_CRV_P256,
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
  if (jwk.alg == "RS256") {
    const out: RSASSA_PKCS1_v1_5_Public_COSE_Key = {
      kty: KTY_RSA,
      alg: RSASSA_PKCS1_v1_5_SHA_256,
      kid,
      key_ops: keyOps(
        jwk.key_ops as string[],
        false,
      ) as (typeof KEY_OP_VERIFY)[],
      ...rsaPublic(jwk as JWK_RSA_Public),
    };
    return out;
  } else if (jwk.alg == "PS256") {
    const out: RSASSA_PSS_Public_COSE_Key = {
      kty: KTY_RSA,
      alg: RSASSA_PSS_SHA_256,
      kid,
      key_ops: keyOps(
        jwk.key_ops as string[],
        false,
      ) as (typeof KEY_OP_VERIFY)[],
      ...rsaPublic(jwk as JWK_RSA_Public),
    };
    return out;
  } else if (jwk.alg == "ES256") {
    const out: ECDSA_Public_COSE_Key = {
      kty: KTY_EC2,
      alg: ECDSA_SHA_256,
      kid,
      crv: EC2_CRV_P256,
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
    jwk.alg == "HS256" && jwk.k
  ) {
    const out: HMAC_COSE_Key = {
      kty: KTY_SYMMETRIC,
      alg: HMAC_SHA_256,
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
