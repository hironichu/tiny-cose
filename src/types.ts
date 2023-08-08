import {
  ALG_ALL,
  EC2_CRV_ALL,
  ECDSA_ALG,
  EDDSA,
  HMAC_SHA_ALG,
  KEY_OP_MAC_CREATE,
  KEY_OP_MAC_VERIFY,
  KEY_OP_SIGN,
  KEY_OP_VERIFY,
  KEY_OPS_ALL,
  KTY_ALL,
  KTY_EC2,
  KTY_OKP,
  KTY_RSA,
  KTY_SYMMETRIC,
  OKP_CRV_EDDSA,
  RSASSA_PKCS1_v1_5_ALG,
  RSASSA_PSS_ALG,
} from "./constants.ts";

export interface COSE_Key {
  kty: KTY_ALL;
  kid?: Uint8Array;
  alg?: ALG_ALL;
  key_ops?: KEY_OPS_ALL[];
  // base_iv?: Uint8Array
}

export interface ECDSA_Public_COSE_Key extends COSE_Key {
  kty: typeof KTY_EC2;
  alg: ECDSA_ALG;
  crv: EC2_CRV_ALL;
  key_ops?: (typeof KEY_OP_VERIFY)[];
  x: Uint8Array;
  y: Uint8Array;
}

export interface ECDSA_Private_COSE_Key extends COSE_Key {
  kty: typeof KTY_EC2;
  alg: ECDSA_ALG;
  crv: EC2_CRV_ALL;
  key_ops?: (typeof KEY_OP_VERIFY | typeof KEY_OP_SIGN)[];
  x?: Uint8Array;
  y?: Uint8Array;
  d: Uint8Array;
}

export interface EDDSA_Public_COSE_Key extends COSE_Key {
  kty: typeof KTY_OKP;
  alg: typeof EDDSA;
  crv: OKP_CRV_EDDSA;
  key_ops?: (typeof KEY_OP_VERIFY)[];
  x: Uint8Array;
}

export interface EDDSA_Private_COSE_Key extends COSE_Key {
  kty: typeof KTY_OKP;
  alg: typeof EDDSA;
  crv: OKP_CRV_EDDSA;
  key_ops?: (typeof KEY_OP_VERIFY | typeof KEY_OP_SIGN)[];
  x?: Uint8Array;
  d: Uint8Array;
}

export interface RSA_Public_Key {
  n: Uint8Array;
  e: Uint8Array;
}

export interface RSA_Private_Key extends RSA_Public_Key {
  p: Uint8Array;
  q: Uint8Array;
  dP: Uint8Array;
  dQ: Uint8Array;
  qInv: Uint8Array;
  // Multi prime private keys are not supported.
}

export interface RSASSA_PKCS1_v1_5_Public_COSE_Key
  extends COSE_Key, RSA_Public_Key {
  kty: typeof KTY_RSA;
  alg: RSASSA_PKCS1_v1_5_ALG;
  key_ops?: (typeof KEY_OP_VERIFY)[];
}

export interface RSASSA_PKCS1_v1_5_Private_COSE_Key
  extends COSE_Key, RSA_Private_Key {
  kty: typeof KTY_RSA;
  alg: RSASSA_PKCS1_v1_5_ALG;
  key_ops?: (typeof KEY_OP_VERIFY | typeof KEY_OP_SIGN)[];
}

export interface RSASSA_PSS_Public_COSE_Key extends COSE_Key, RSA_Public_Key {
  kty: typeof KTY_RSA;
  alg: RSASSA_PSS_ALG;
  key_ops?: (typeof KEY_OP_VERIFY)[];
}

export interface RSASSA_PSS_Private_COSE_Key extends COSE_Key, RSA_Private_Key {
  kty: typeof KTY_RSA;
  alg: RSASSA_PSS_ALG;
  key_ops?: (typeof KEY_OP_VERIFY | typeof KEY_OP_SIGN)[];
}

export interface HMAC_COSE_Key extends COSE_Key {
  kty: typeof KTY_SYMMETRIC;
  alg: HMAC_SHA_ALG;
  key_ops?: (typeof KEY_OP_MAC_CREATE | typeof KEY_OP_MAC_VERIFY)[];
  k: Uint8Array;
}

export type COSE_Key_ALL =
  | ECDSA_Public_COSE_Key
  | ECDSA_Private_COSE_Key
  | EDDSA_Public_COSE_Key
  | EDDSA_Private_COSE_Key
  | RSASSA_PKCS1_v1_5_Public_COSE_Key
  | RSASSA_PKCS1_v1_5_Private_COSE_Key
  | RSASSA_PSS_Public_COSE_Key
  | RSASSA_PSS_Private_COSE_Key
  | HMAC_COSE_Key;
