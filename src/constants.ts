// These constants come from
// https://www.iana.org/assignments/cose/cose.xhtml

// COSE Algorithms
export const ECDSA_SHA_256 = -7;
export const ECDSA_SHA_384 = -35;
export const ECDSA_SHA_512 = -36;
export type ECDSA_ALG =
  | typeof ECDSA_SHA_256
  | typeof ECDSA_SHA_384
  | typeof ECDSA_SHA_512;

// EdDSA
export const EDDSA = -8;

export const RSASSA_PSS_SHA_256 = -37;
export const RSASSA_PSS_SHA_384 = -38;
export const RSASSA_PSS_SHA_512 = -39;
export type RSASSA_PSS_ALG =
  | typeof RSASSA_PSS_SHA_256
  | typeof RSASSA_PSS_SHA_384
  | typeof RSASSA_PSS_SHA_512;

export const RSASSA_PKCS1_v1_5_SHA_256 = -257;
export const RSASSA_PKCS1_v1_5_SHA_384 = -256;
export const RSASSA_PKCS1_v1_5_SHA_512 = -259;
export type RSASSA_PKCS1_v1_5_ALG =
  | typeof RSASSA_PKCS1_v1_5_SHA_256
  | typeof RSASSA_PKCS1_v1_5_SHA_384
  | typeof RSASSA_PKCS1_v1_5_SHA_512;

export const HMAC_SHA_256 = 5;
export const HMAC_SHA_384 = 6;
export const HMAC_SHA_512 = 7;
export type HMAC_SHA_ALG =
  | typeof HMAC_SHA_256
  | typeof HMAC_SHA_384
  | typeof HMAC_SHA_512;

export type ALG_ALL =
  | ECDSA_ALG
  | typeof EDDSA
  | RSASSA_PSS_ALG
  | RSASSA_PKCS1_v1_5_ALG
  | HMAC_SHA_ALG;

// COSE Key Common Parameters
export const KTY = 1;
export const KID = 2;
export const ALG = 3;
export const KEY_OPS = 4;
export const BASE_IV = 5;

// COSE Key Type Parameters
export const OKP_CURVE = -1;
export const OKP_X = -2;
export const OKP_D = -4;

export const EC2_CURVE = -1;
export const EC2_X = -2;
export const EC2_Y = -3;
export const EC2_D = -4;

export const RSA_N = -1;
export const RSA_E = -2;
export const RSA_D = -3;
export const RSA_P = -4;
export const RSA_Q = -5;
export const RSA_DP = -6;
export const RSA_DQ = -7;
export const RSA_QI = -8;

export const OCTET_KEY = -1;

// COSE Key Types
export const KTY_OKP = 1;
export const KTY_EC2 = 2;
export const KTY_RSA = 3;
export const KTY_SYMMETRIC = 4;
export type KTY_ALL =
  | typeof KTY_OKP
  | typeof KTY_EC2
  | typeof KTY_SYMMETRIC
  | typeof KTY_RSA;

// COSE Elliptic Curves
export const EC2_CRV_P256 = 1;
export const EC2_CRV_P384 = 2;
export const EC2_CRV_P521 = 3;
export type EC2_CRV_ALL =
  | typeof EC2_CRV_P256
  | typeof EC2_CRV_P384
  | typeof EC2_CRV_P521;

// export const OKP_CRV_X25519 = 4;
// export const OKP_CRV_X448 = 5;
export const OKP_CRV_ED25519 = 6;
export const OKP_CRV_ED448 = 7;
// export type OKP_CRV_ECDH =
//   | typeof OKP_CRV_X25519
//   | typeof OKP_CRV_X448;
export type OKP_CRV_EDDSA =
  | typeof OKP_CRV_ED25519
  | typeof OKP_CRV_ED448;

export const KEY_OP_SIGN = 1;
export const KEY_OP_VERIFY = 2;
// export const KEY_OP_ENCRYPT = 3;
// export const KEY_OP_DECRYPT = 4;
// export const KEY_OP_WRAP_KEY = 5;
// export const KEY_OP_UNWRAP_KEY = 6;
// export const KEY_OP_DERIVE_KEY = 7;
// export const KEY_OP_DERIVE_BITS = 8;
export const KEY_OP_MAC_CREATE = 9;
export const KEY_OP_MAC_VERIFY = 10;

export type KEY_OPS_ALL =
  | typeof KEY_OP_SIGN
  | typeof KEY_OP_VERIFY
  // | typeof KEY_OP_ENCRYPT
  // | typeof KEY_OP_DECRYPT
  // | typeof KEY_OP_WRAP_KEY
  // | typeof KEY_OP_UNWRAP_KEY
  // | typeof KEY_OP_DERIVE_KEY
  // | typeof KEY_OP_DERIVE_BITS
  | typeof KEY_OP_MAC_CREATE
  | typeof KEY_OP_MAC_VERIFY;
