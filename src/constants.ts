// These constants come from
// https://www.iana.org/assignments/cose/cose.xhtml

// COSE Algorithms
export const ECDSA_SHA_256 = -7;
export const EDDSA = -8;
export const ECDSA_SHA_384 = -35;
export const ECDSA_SHA_512 = -36;

export const RSASSA_PSS_SHA_256 = -37;
export const RSASSA_PSS_SHA_384 = -38;
export const RSASSA_PSS_SHA_512 = -39;

export const RSASSA_PKCS1_v1_5_SHA_256 = -257;
export const RSASSA_PKCS1_v1_5_SHA_384 = -256;
export const RSASSA_PKCS1_v1_5_SHA_512 = -259;

export const HMAC_SHA_256 = 5;
export const HMAC_SHA_384 = 6;
export const HMAC_SHA_512 = 7;

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

export const EC_CURVE = -1;
export const EC_X = -2;
export const EC_Y = -3;
export const EC_D = -4;

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
export const KTY_EC = 2;
export const KTY_RSA = 3;
export const KTY_OCTET = 4;

// COSE Elliptic Curves
export const EC_CURVE_P256 = 1;
export const EC_CURVE_P384 = 2;
export const EC_CURVE_P521 = 3;

export const OKP_CURVE_X25519 = 4;
export const OKP_CURVE_X448 = 5;
export const OKP_CURVE_ED25519 = 6;
export const OKP_CURVE_ED448 = 7;
