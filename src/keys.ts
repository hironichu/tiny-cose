import {
  EC2_CRV_P256,
  EC2_CRV_P384,
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
import { decodeBase64Url, encodeBase64Url } from "./deps.ts";
import {
  COSEPrivateKey,
  COSEPublicKey,
  COSESymmetricKey,
  ECDSA_Private_COSE_Key,
  ECDSA_Public_COSE_Key,
  EDDSA_Private_COSE_Key,
  EDDSA_Public_COSE_Key,
  HMAC_COSE_Key,
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
  } else if (jwk.x && jwk.d && jwk.kty == "OKP" && jwk.crv == "Ed25519") {
    const out: EDDSA_Private_COSE_Key = {
      kty: KTY_OKP,
      crv: OKP_CRV_ED25519,
      alg: EDDSA,
      x: decodeBase64Url(jwk.x),
      d: decodeBase64Url(jwk.d),
      key_ops: keyOps(
        jwk.key_ops as string[],
        false,
      ) as (typeof KEY_OP_SIGN | typeof KEY_OP_VERIFY)[],
    };
    return out;
  }
  throw new Error(`Unsupported key ${jwk.alg}`);
}

export async function importPrivateKey(
  key: COSEKeyAll,
  extractable?: boolean,
): Promise<ImportedKey> {
  const key_ops: KeyUsage[] = [];
  if (key.key_ops) {
    for (const op of key.key_ops) {
      if (op == KEY_OP_VERIFY) {
        key_ops.push("verify");
      } else if (op == KEY_OP_SIGN) {
        key_ops.push("sign");
      }
    }
  } else {
    key_ops.push("verify");
    key_ops.push("sign");
  }

  if (
    key.alg == RSASSA_PKCS1_v1_5_SHA_256 ||
    key.alg == RSASSA_PKCS1_v1_5_SHA_384 ||
    key.alg == RSASSA_PKCS1_v1_5_SHA_512 || key.alg == RSASSA_PSS_SHA_256 ||
    key.alg == RSASSA_PSS_SHA_384 || key.alg == RSASSA_PSS_SHA_512
  ) {
    const privateKey = key as
      | RSASSA_PKCS1_v1_5_Private_COSE_Key
      | RSASSA_PSS_Private_COSE_Key;
    let alg: string;
    let hashName: string;
    let name: string;
    switch (key.alg) {
      case RSASSA_PKCS1_v1_5_SHA_256:
        alg = "RS256";
        hashName = "SHA-256";
        name = "RSASSA-PKCS1-v1_5";
        break;
      case RSASSA_PKCS1_v1_5_SHA_384:
        alg = "RS384";
        hashName = "SHA-384";
        name = "RSASSA-PKCS1-v1_5";
        break;
      case RSASSA_PKCS1_v1_5_SHA_512:
        alg = "RS512";
        hashName = "SHA-512";
        name = "RSASSA-PKCS1-v1_5";
        break;
      case RSASSA_PSS_SHA_256:
        alg = "PS256";
        hashName = "SHA-256";
        name = "RSA-PSS";
        break;
      case RSASSA_PSS_SHA_384:
        alg = "PS384";
        hashName = "SHA-384";
        name = "RSA-PSS";
        break;
      case RSASSA_PSS_SHA_512:
        alg = "PS512";
        hashName = "SHA-512";
        name = "RSA-PSS";
        break;
    }
    if (
      !privateKey.d || !privateKey.d || !privateKey.q || !privateKey.dP ||
      !privateKey.dQ || !privateKey.qInv
    ) {
      throw new Error("Cannot import RSA private key, components are missing");
    }
    const jwk: JsonWebKey = {
      alg,
      kty: "RSA",
      key_ops,
      e: encodeBase64Url(key.e),
      n: encodeBase64Url(key.n),
      d: encodeBase64Url(privateKey.d),
      p: encodeBase64Url(privateKey.p),
      q: encodeBase64Url(privateKey.q),
      dp: encodeBase64Url(privateKey.dP),
      dq: encodeBase64Url(privateKey.dQ),
      qi: encodeBase64Url(privateKey.qInv),
    };
    const cryptoKey = await crypto.subtle.importKey(
      "jwk",
      jwk,
      {
        name,
        hash: { name: hashName },
      },
      extractable || false,
      key_ops,
    );
    return { key: cryptoKey, kid: key.kid };
  } else if (
    key.alg == ECDSA_SHA_256 || key.alg == ECDSA_SHA_384 ||
    key.alg == ECDSA_SHA_512
  ) {
    const privateKey = key as ECDSA_Private_COSE_Key;
    if (!privateKey.d) {
      throw new Error(
        "Cannot import ECDSA private key, components are missing",
      );
    }
    let alg: string;
    let namedCurve: string;
    switch (key.alg) {
      case ECDSA_SHA_256:
        alg = "ES256";
        namedCurve = "P-256";
        break;
      case ECDSA_SHA_384:
        alg = "ES384";
        namedCurve = "P-384";
        break;
      case ECDSA_SHA_512:
        alg = "ES512";
        namedCurve = "P-521";
        break;
    }
    const jwk: JsonWebKey = {
      alg,
      kty: "EC",
      key_ops,
      x: encodeBase64Url(key.x),
      y: encodeBase64Url(key.y),
      d: encodeBase64Url(privateKey.d),
    };
    const cryptoKey = await crypto.subtle.importKey(
      "jwk",
      jwk,
      {
        name: "ECDSA",
        namedCurve,
      },
      extractable || false,
      key_ops,
    );
    return { key: cryptoKey, kid: key.kid };
  } else if (key.alg == EDDSA) {
    if (key.crv != OKP_CRV_ED25519) {
      throw new Error("Unsupported EDDSA curve");
    }
    const privateKey = key as EDDSA_Private_COSE_Key;
    const jwk: JsonWebKey = {
      crv: "Ed25519",
      kty: "OKP",
      key_ops,
      x: encodeBase64Url(key.x),
      d: encodeBase64Url(privateKey.d),
    };
    const cryptoKey = await crypto.subtle.importKey(
      "jwk",
      jwk,
      { name: "Ed25519" },
      extractable || false,
      key_ops,
    );
    return { key: cryptoKey, kid: key.kid };
  } else {
    throw new Error("Key algorithm not supported");
  }
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
  } else if (jwk.kty == "OKP" && jwk.crv == "Ed25519" && jwk.x) {
    const out: EDDSA_Public_COSE_Key = {
      kty: KTY_OKP,
      crv: OKP_CRV_ED25519,
      alg: EDDSA,
      x: decodeBase64Url(jwk.x),
      key_ops: keyOps(
        jwk.key_ops as string[],
        false,
      ) as (typeof KEY_OP_VERIFY)[],
    };
    return out;
  }
  throw new Error(`Unsupported key ${jwk.alg}`);
}

export async function importPublicKey(key: COSEKeyAll): Promise<ImportedKey> {
  const key_ops: KeyUsage[] = [];
  if (key.key_ops) {
    for (const op of key.key_ops) {
      if (op == KEY_OP_VERIFY) {
        key_ops.push("verify");
      }
    }
  } else {
    key_ops.push("verify");
  }

  if (
    key.alg == RSASSA_PKCS1_v1_5_SHA_256 ||
    key.alg == RSASSA_PKCS1_v1_5_SHA_384 ||
    key.alg == RSASSA_PKCS1_v1_5_SHA_512 || key.alg == RSASSA_PSS_SHA_256 ||
    key.alg == RSASSA_PSS_SHA_384 || key.alg == RSASSA_PSS_SHA_512
  ) {
    let alg: string;
    let hashName: string;
    let name: string;
    switch (key.alg) {
      case RSASSA_PKCS1_v1_5_SHA_256:
        alg = "RS256";
        hashName = "SHA-256";
        name = "RSASSA-PKCS1-v1_5";
        break;
      case RSASSA_PKCS1_v1_5_SHA_384:
        alg = "RS384";
        hashName = "SHA-384";
        name = "RSASSA-PKCS1-v1_5";
        break;
      case RSASSA_PKCS1_v1_5_SHA_512:
        alg = "RS512";
        hashName = "SHA-512";
        name = "RSASSA-PKCS1-v1_5";
        break;
      case RSASSA_PSS_SHA_256:
        alg = "PS256";
        hashName = "SHA-256";
        name = "RSA-PSS";
        break;
      case RSASSA_PSS_SHA_384:
        alg = "PS384";
        hashName = "SHA-384";
        name = "RSA-PSS";
        break;
      case RSASSA_PSS_SHA_512:
        alg = "PS512";
        hashName = "SHA-512";
        name = "RSA-PSS";
        break;
    }
    const jwk: JsonWebKey = {
      alg,
      kty: "RSA",
      key_ops,
      e: encodeBase64Url(key.e),
      n: encodeBase64Url(key.n),
    };
    const cryptoKey = await crypto.subtle.importKey(
      "jwk",
      jwk,
      {
        name,
        hash: { name: hashName },
      },
      true,
      key_ops,
    );
    return { key: cryptoKey, kid: key.kid };
  } else if (
    key.alg == ECDSA_SHA_256 || key.alg == ECDSA_SHA_384 ||
    key.alg == ECDSA_SHA_512
  ) {
    let alg: string;
    let namedCurve: string;
    switch (key.alg) {
      case ECDSA_SHA_256:
        alg = "ES256";
        namedCurve = "P-256";
        break;
      case ECDSA_SHA_384:
        alg = "ES384";
        namedCurve = "P-384";
        break;
      case ECDSA_SHA_512:
        alg = "ES512";
        namedCurve = "P-521";
        break;
    }
    const jwk: JsonWebKey = {
      alg,
      kty: "EC",
      key_ops,
      x: encodeBase64Url(key.x),
      y: encodeBase64Url(key.y),
    };
    const cryptoKey = await crypto.subtle.importKey(
      "jwk",
      jwk,
      {
        name: "ECDSA",
        namedCurve,
      },
      true,
      key_ops,
    );
    return { key: cryptoKey, kid: key.kid };
  } else if (key.alg == EDDSA) {
    if (key.crv != OKP_CRV_ED25519) {
      throw new Error("Unsupported EDDSA curve");
    }
    const jwk: JsonWebKey = {
      crv: "Ed25519",
      kty: "OKP",
      key_ops,
      x: encodeBase64Url(key.x),
    };
    const cryptoKey = await crypto.subtle.importKey(
      "jwk",
      jwk,
      { name: "Ed25519" },
      true,
      key_ops,
    );
    return { key: cryptoKey, kid: key.kid };
  } else {
    throw new Error("Key algorithm not supported");
  }
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

export async function importSymmetricKey(
  key: COSEKeyAll,
  extractable?: boolean,
): Promise<ImportedKey> {
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
