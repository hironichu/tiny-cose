import {
  assert,
  assertEquals,
  assertNotEquals,
  assertRejects,
} from "https://deno.land/std@0.195.0/assert/mod.ts";
import { describe, it } from "https://deno.land/std@0.195.0/testing/bdd.ts";
import {
  exportPrivateKey,
  exportPublicKey,
  exportSymmetricKey,
  importPrivateKey,
  importPublicKey,
  importSymmetricKey,
} from "./keys.ts";
import {
  EC2_CRV_P256,
  EC2_CRV_P384,
  ECDSA_SHA_256,
  ECDSA_SHA_384,
  EDDSA,
  HMAC_SHA_256,
  HMAC_SHA_384,
  HMAC_SHA_512,
  KEY_OP_MAC_CREATE,
  KEY_OP_MAC_VERIFY,
  KEY_OP_SIGN,
  KEY_OP_VERIFY,
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
import {
  decodeBase64,
  decodeBase64Url,
} from "https://deno.land/x/tiny_encodings@0.2.1/encoding.ts";
import { decodeCBOR } from "https://deno.land/x/tiny_cbor@0.2.1/cbor/cbor.ts";
import { parseCBORToCOSEKey } from "./parse.ts";

const ENCODER = new TextEncoder();

describe("Generating keys", () => {
  it("Export a dynamically RS256 generated key", async () => {
    const key = await crypto.subtle.generateKey(
      {
        name: "RSASSA-PKCS1-v1_5",
        modulusLength: 2048,
        publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
        hash: { name: "SHA-256" },
      },
      true,
      ["sign", "verify"],
    );
    const exportedPrivate = await exportPrivateKey(
      key.privateKey,
      ENCODER.encode("test@example.com"),
    );
    assertEquals(exportedPrivate.kty, KTY_RSA);
    assertEquals(exportedPrivate.key_ops, [KEY_OP_SIGN]);
    assertEquals(exportedPrivate.alg, RSASSA_PKCS1_v1_5_SHA_256);
    const exportedPublic = await exportPublicKey(
      key.publicKey,
      ENCODER.encode("test@example.com"),
    );
    assertEquals(exportedPublic.kty, KTY_RSA);
    assertEquals(exportedPublic.key_ops, [KEY_OP_VERIFY]);
    assertEquals(exportedPublic.alg, RSASSA_PKCS1_v1_5_SHA_256);
  });
  it("Export a dynamically RS384 generated key", async () => {
    const key = await crypto.subtle.generateKey(
      {
        name: "RSASSA-PKCS1-v1_5",
        modulusLength: 2048,
        publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
        hash: { name: "SHA-384" },
      },
      true,
      ["sign", "verify"],
    );
    const exportedPrivate = await exportPrivateKey(
      key.privateKey,
      ENCODER.encode("test@example.com"),
    );
    assertEquals(exportedPrivate.kty, KTY_RSA);
    assertEquals(exportedPrivate.key_ops, [KEY_OP_SIGN]);
    assertEquals(exportedPrivate.alg, RSASSA_PKCS1_v1_5_SHA_384);
    const exportedPublic = await exportPublicKey(
      key.publicKey,
      ENCODER.encode("test@example.com"),
    );
    assertEquals(exportedPublic.kty, KTY_RSA);
    assertEquals(exportedPublic.key_ops, [KEY_OP_VERIFY]);
    assertEquals(exportedPublic.alg, RSASSA_PKCS1_v1_5_SHA_384);
  });
  it("Export a dynamically RS512 generated key", async () => {
    const key = await crypto.subtle.generateKey(
      {
        name: "RSASSA-PKCS1-v1_5",
        modulusLength: 2048,
        publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
        hash: { name: "SHA-512" },
      },
      true,
      ["sign", "verify"],
    );
    const exportedPrivate = await exportPrivateKey(
      key.privateKey,
      ENCODER.encode("test@example.com"),
    );
    assertEquals(exportedPrivate.kty, KTY_RSA);
    assertEquals(exportedPrivate.key_ops, [KEY_OP_SIGN]);
    assertEquals(exportedPrivate.alg, RSASSA_PKCS1_v1_5_SHA_512);
    const exportedPublic = await exportPublicKey(
      key.publicKey,
      ENCODER.encode("test@example.com"),
    );
    assertEquals(exportedPublic.kty, KTY_RSA);
    assertEquals(exportedPublic.key_ops, [KEY_OP_VERIFY]);
    assertEquals(exportedPublic.alg, RSASSA_PKCS1_v1_5_SHA_512);
  });

  it("Export a dynamically PS256 generated key", async () => {
    const key = await crypto.subtle.generateKey(
      {
        name: "RSA-PSS",
        modulusLength: 2048,
        publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
        hash: { name: "SHA-256" },
      },
      true,
      ["sign", "verify"],
    );
    const exportedPrivate = await exportPrivateKey(
      key.privateKey,
      ENCODER.encode("test@example.com"),
    );
    assertEquals(exportedPrivate.kty, KTY_RSA);
    assertEquals(exportedPrivate.key_ops, [KEY_OP_SIGN]);
    assertEquals(exportedPrivate.alg, RSASSA_PSS_SHA_256);
    const exportedPublic = await exportPublicKey(
      key.publicKey,
      ENCODER.encode("test@example.com"),
    );
    assertEquals(exportedPublic.kty, KTY_RSA);
    assertEquals(exportedPublic.key_ops, [KEY_OP_VERIFY]);
    assertEquals(exportedPublic.alg, RSASSA_PSS_SHA_256);
  });

  it("Export a dynamically PS384 generated key", async () => {
    const key = await crypto.subtle.generateKey(
      {
        name: "RSA-PSS",
        modulusLength: 2048,
        publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
        hash: { name: "SHA-384" },
      },
      true,
      ["sign", "verify"],
    );
    const exportedPrivate = await exportPrivateKey(
      key.privateKey,
      ENCODER.encode("test@example.com"),
    );
    assertEquals(exportedPrivate.kty, KTY_RSA);
    assertEquals(exportedPrivate.key_ops, [KEY_OP_SIGN]);
    assertEquals(exportedPrivate.alg, RSASSA_PSS_SHA_384);
    const exportedPublic = await exportPublicKey(
      key.publicKey,
      ENCODER.encode("test@example.com"),
    );
    assertEquals(exportedPublic.kty, KTY_RSA);
    assertEquals(exportedPublic.key_ops, [KEY_OP_VERIFY]);
    assertEquals(exportedPublic.alg, RSASSA_PSS_SHA_384);
  });
  it("Export a dynamically PS512 generated key", async () => {
    const key = await crypto.subtle.generateKey(
      {
        name: "RSA-PSS",
        modulusLength: 2048,
        publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
        hash: { name: "SHA-512" },
      },
      true,
      ["sign", "verify"],
    );
    const exportedPrivate = await exportPrivateKey(
      key.privateKey,
      ENCODER.encode("test@example.com"),
    );
    assertEquals(exportedPrivate.kty, KTY_RSA);
    assertEquals(exportedPrivate.key_ops, [KEY_OP_SIGN]);
    assertEquals(exportedPrivate.alg, RSASSA_PSS_SHA_512);
    const exportedPublic = await exportPublicKey(
      key.publicKey,
      ENCODER.encode("test@example.com"),
    );
    assertEquals(exportedPublic.kty, KTY_RSA);
    assertEquals(exportedPublic.key_ops, [KEY_OP_VERIFY]);
    assertEquals(exportedPublic.alg, RSASSA_PSS_SHA_512);
  });

  it("Export a dynamically ES256 generated key", async () => {
    const key = await crypto.subtle.generateKey(
      {
        name: "ECDSA",
        namedCurve: "P-256",
      },
      true,
      ["sign", "verify"],
    );
    const exportedPrivate = await exportPrivateKey(
      key.privateKey,
      ENCODER.encode("test@example.com"),
    );
    assertEquals(exportedPrivate.kty, KTY_EC2);
    assertEquals(exportedPrivate.key_ops, [KEY_OP_SIGN]);
    assertEquals(exportedPrivate.alg, ECDSA_SHA_256);
    if (exportedPrivate.alg == ECDSA_SHA_256) {
      assertEquals(exportedPrivate.crv, EC2_CRV_P256);
    }

    const exportedPublic = await exportPublicKey(
      key.publicKey,
      ENCODER.encode("test@example.com"),
    );
    assertEquals(exportedPublic.kty, KTY_EC2);
    assertEquals(exportedPublic.key_ops, [KEY_OP_VERIFY]);
    assertEquals(exportedPublic.alg, ECDSA_SHA_256);
    if (exportedPublic.alg == ECDSA_SHA_256) {
      assertEquals(exportedPublic.crv, EC2_CRV_P256);
    }
  });
  it("Export a dynamically ES384 generated key", async () => {
    const key = await crypto.subtle.generateKey(
      {
        name: "ECDSA",
        namedCurve: "P-384",
      },
      true,
      ["sign", "verify"],
    );
    const exportedPrivate = await exportPrivateKey(
      key.privateKey,
      ENCODER.encode("test@example.com"),
    );
    assertEquals(exportedPrivate.kty, KTY_EC2);
    assertEquals(exportedPrivate.key_ops, [KEY_OP_SIGN]);
    assertEquals(exportedPrivate.alg, ECDSA_SHA_384);
    if (exportedPrivate.alg == ECDSA_SHA_384) {
      assertEquals(exportedPrivate.crv, EC2_CRV_P384);
    }

    const exportedPublic = await exportPublicKey(
      key.publicKey,
      ENCODER.encode("test@example.com"),
    );
    assertEquals(exportedPublic.kty, KTY_EC2);
    assertEquals(exportedPublic.key_ops, [KEY_OP_VERIFY]);
    assertEquals(exportedPublic.alg, ECDSA_SHA_384);
    if (exportedPublic.alg == ECDSA_SHA_384) {
      assertEquals(exportedPublic.crv, EC2_CRV_P384);
    }
  });

  it("Does not yet support ES512", () => {
    // ES512 is not supported yet in Deno.
    // https://github.com/denoland/deno/issues/13449
  });

  it("Export a dynamically HS256 generated key", async () => {
    const key = await crypto.subtle.generateKey(
      {
        name: "HMAC",
        hash: { name: "SHA-256" },
      },
      true,
      ["sign", "verify"],
    );
    const exportedSymmetric = await exportSymmetricKey(
      key,
      ENCODER.encode("test@example.com"),
    );
    assertEquals(exportedSymmetric.kty, KTY_SYMMETRIC);
    assertEquals(exportedSymmetric.key_ops, [
      KEY_OP_MAC_CREATE,
      KEY_OP_MAC_VERIFY,
    ]);
    assertEquals(exportedSymmetric.alg, HMAC_SHA_256);
    if (exportedSymmetric.alg == HMAC_SHA_256) {
      assertNotEquals(exportedSymmetric.k, null);
    }
  });

  it("Export a dynamically HS384 generated key", async () => {
    const key = await crypto.subtle.generateKey(
      {
        name: "HMAC",
        hash: { name: "SHA-384" },
      },
      true,
      ["sign", "verify"],
    );
    const exportedSymmetric = await exportSymmetricKey(
      key,
      ENCODER.encode("test@example.com"),
    );
    assertEquals(exportedSymmetric.kty, KTY_SYMMETRIC);
    assertEquals(exportedSymmetric.key_ops, [
      KEY_OP_MAC_CREATE,
      KEY_OP_MAC_VERIFY,
    ]);
    assertEquals(exportedSymmetric.alg, HMAC_SHA_384);
    if (exportedSymmetric.alg == HMAC_SHA_384) {
      assertNotEquals(exportedSymmetric.k, null);
    }
  });

  it("Export a dynamically HS512 generated key", async () => {
    const key = await crypto.subtle.generateKey(
      {
        name: "HMAC",
        hash: { name: "SHA-512" },
      },
      true,
      ["sign", "verify"],
    );
    const exportedSymmetric = await exportSymmetricKey(
      key,
      ENCODER.encode("test@example.com"),
    );
    assertEquals(exportedSymmetric.kty, KTY_SYMMETRIC);
    assertEquals(exportedSymmetric.key_ops, [
      KEY_OP_MAC_CREATE,
      KEY_OP_MAC_VERIFY,
    ]);
    assertEquals(exportedSymmetric.alg, HMAC_SHA_512);
    if (exportedSymmetric.alg == HMAC_SHA_512) {
      assertNotEquals(exportedSymmetric.k, null);
    }
  });

  it("Refuses a non-extractable private key", async () => {
    const key = await crypto.subtle.generateKey(
      {
        name: "ECDSA",
        namedCurve: "P-256",
      },
      false,
      ["sign", "verify"],
    );
    assertRejects(async () => {
      await exportPrivateKey(
        key.privateKey,
        ENCODER.encode("test@example.com"),
      );
    });
    // Public keys are still extractable
  });
  it("Refuses a non-extractable symmetric key", async () => {
    const key = await crypto.subtle.generateKey(
      {
        name: "HMAC",
        hash: { name: "SHA-256" },
      },
      false,
      ["sign", "verify"],
    );
    assertRejects(async () => {
      await exportSymmetricKey(
        key,
        ENCODER.encode("test@example.com"),
      );
    });
  });

  it("Refuses a dynamically generated AES-CBC key", async () => {
    // Unsupported
    const key = await crypto.subtle.generateKey(
      {
        name: "AES-CBC",
        length: 256,
      },
      true,
      ["encrypt", "decrypt"],
    );

    // These aren't even private or public keys
    assertRejects(async () => {
      await exportPrivateKey(key, ENCODER.encode("test@example.com"));
    });
    assertRejects(async () => {
      await exportPublicKey(key, ENCODER.encode("test@example.com"));
    });
    assertRejects(async () => {
      await exportSymmetricKey(
        key,
        ENCODER.encode("test@example.com"),
      );
    });
  });

  it("Export a dynamically Ed25519 generated key", async () => {
    const key = await crypto.subtle.generateKey(
      {
        name: "Ed25519",
      },
      true,
      ["sign", "verify"],
    ) as CryptoKeyPair;
    const exportedPrivate = await exportPrivateKey(
      key.privateKey,
      ENCODER.encode("test@example.com"),
    );
    assertEquals(exportedPrivate.kty, KTY_OKP);
    assertEquals(exportedPrivate.key_ops, [KEY_OP_SIGN]);
    assertEquals(exportedPrivate.alg, EDDSA);
    if (exportedPrivate.alg == EDDSA) {
      assertEquals(exportedPrivate.crv, OKP_CRV_ED25519);
    }

    const exportedPublic = await exportPublicKey(
      key.publicKey,
      ENCODER.encode("test@example.com"),
    );
    assertEquals(exportedPublic.kty, KTY_OKP);
    assertEquals(exportedPublic.key_ops, [KEY_OP_VERIFY]);
    assertEquals(exportedPublic.alg, EDDSA);
    if (exportedPublic.alg == EDDSA) {
      assertEquals(exportedPublic.crv, OKP_CRV_ED25519);
    }
  });
});

// Keys come from https://github.com/LeviSchuck/cose-examples/tree/main

function decode(b64url: string): CBORType {
  const bytes = decodeBase64Url(b64url);
  const cbor = decodeCBOR(bytes);
  return cbor;
}

describe("Importing keys", () => {
  // it("Imports a RS256 Public Key", async () => {
  //   const cbor = decode('pgEDAlFoZWxsb0BleGFtcGxlLmNvbQSBAgM5AQAhQwEAASBZAQC39rfzb7mCsntRDoHf687SeuTxrQxO7A-sPfbmwS_zwLAAW3OGfhZuya8qDxoUF5ybosh74yEWOPKXZmE-ac-N8UQazh1OItA5aJILDI_gWYtkqi4-B08v-IgF_s1Au-fLll6gsQtvTOSBs6-ZYSkdVKNsLDUrp_D98nrLzgV4vydSEvwqlbt_Ykxgw6x_5ZhJIzuCvf0nMBYDr7dxQcEvxYJSARZIFNuMqJnc5iDEzCnT4C8sJOGxJqTV62nOnnvZMVEIF_zzXVWZgTPqi7D3RmCpsmD0C2lee1dV1lNf8v7dRRExESk4Wrfpm_Bdp8vFrzevWmTJyW8ezGWlbGCF');
  //   const key =
  //   const imported = await importPublicKey()
  // })
  it("Imports an HS256 key", async () => {
    const cbor = decode(
      "pQEEIFgg58-Wmw5lAYoVsBWNZ-Od1UsodZ-PDMPr27l95UzW1OYCUWhlbGxvQGV4YW1wbGUuY29tBIIJCgMF",
    );
    const coseKey = parseCBORToCOSEKey(cbor);
    const { key } = await importSymmetricKey(coseKey, true);
    const signature = await crypto.subtle.sign(
      { name: "HMAC" },
      key,
      ENCODER.encode("Hello world"),
    );
    assertEquals(
      new Uint8Array(signature),
      decodeBase64("Jl7zJByUUrh1y5b94fES52I2SwgjCmSywcvuvjywS4Y="),
    );
    (cbor as Map<number, CBORType>).delete(4);
    const coseKey2 = parseCBORToCOSEKey(cbor);
    const skey2 = await importSymmetricKey(coseKey2, false);
    const signature2 = await crypto.subtle.sign(
      { name: "HMAC" },
      skey2.key,
      ENCODER.encode("Hello world"),
    );
    assertEquals(
      new Uint8Array(signature2),
      decodeBase64("Jl7zJByUUrh1y5b94fES52I2SwgjCmSywcvuvjywS4Y="),
    );
  });
  it("Unsupported Symmetric algorithm", () => {
    assertRejects(async () => {
      const cbor = decode(
        "pQEEIFgg58-Wmw5lAYoVsBWNZ-Od1UsodZ-PDMPr27l95UzW1OYCUWhlbGxvQGV4YW1wbGUuY29tBIIJCgMF",
      );
      (cbor as Map<number, CBORType>).set(3, RSASSA_PKCS1_v1_5_SHA_256);
      const coseKey = parseCBORToCOSEKey(cbor);
      await importSymmetricKey(coseKey, true);
    });
    assertRejects(async () => {
      const cbor = decode(
        "pQEBIAYhWCBMBNC6kELz0E-_DMukE1opN0PlMpI0BHryQ-Q-TuvG8CNYIAe8jNQE0LJjAwBNCF1rBPRWOH6bPvS6jgOgI76ZJyl6BIEB",
      );
      (cbor as Map<number, CBORType>).set(3, RSASSA_PKCS1_v1_5_SHA_256);
      const coseKey = parseCBORToCOSEKey(cbor);
      await importSymmetricKey(coseKey, true);
    });
  });
  it("Imports an HS384 key", async () => {
    const cbor = decode(
      "pQEEIFgwkmqjI1J0ZqSTLs27o7gkTDM4jp7z2abse2C3nXm1C0OzPrr9beK4H5tt5mvZFhkbAlFoZWxsb0BleGFtcGxlLmNvbQSCCQoDBg==",
    );
    const coseKey = parseCBORToCOSEKey(cbor);
    const { key } = await importSymmetricKey(coseKey, true);
    const signature = await crypto.subtle.sign(
      { name: "HMAC" },
      key,
      ENCODER.encode("Hello world"),
    );
    assertEquals(
      new Uint8Array(signature),
      decodeBase64(
        "QYQHWmLwz8tZaadmRuitBUmUjbX+TM+rvfAvlVutvDIoXyejSIylCm3Bwpzcftst",
      ),
    );
  });
  it("Imports an HS512 key", async () => {
    const cbor = decode(
      "pQEEIFhAIZEMIfF4qzuGFf_vWAXIq9VUUG7Gtva8ry3Ymci4U0yYVEMokdsp86eNUC5LjOgyiL-70t0OlohycL1YmC1qCAJRaGVsbG9AZXhhbXBsZS5jb20EggkKAwc=",
    );
    const coseKey = parseCBORToCOSEKey(cbor);
    const { key } = await importSymmetricKey(coseKey, true);
    const signature = await crypto.subtle.sign(
      { name: "HMAC" },
      key,
      ENCODER.encode("Hello world"),
    );
    assertEquals(
      new Uint8Array(signature),
      decodeBase64(
        "aqNllE9QEqrc5+rMPyWGsR+cRbC+A57DAKNw5phJS2RWYdfdWFAknHfNejTixoBgSs/gHlsfkioKjvrI8B67BQ==",
      ),
    );
  });
  it("Imports a RS256 private key", async () => {
    const cbor = decode(
      "rAEDIUMBAAEgWQEAt_a382-5grJ7UQ6B3-vO0nrk8a0MTuwPrD325sEv88CwAFtzhn4WbsmvKg8aFBecm6LIe-MhFjjyl2ZhPmnPjfFEGs4dTiLQOWiSCwyP4FmLZKouPgdPL_iIBf7NQLvny5ZeoLELb0zkgbOvmWEpHVSjbCw1K6fw_fJ6y84FeL8nUhL8KpW7f2JMYMOsf-WYSSM7gr39JzAWA6-3cUHBL8WCUgEWSBTbjKiZ3OYgxMwp0-AvLCThsSak1etpzp572TFRCBf8811VmYEz6ouw90ZgqbJg9AtpXntXVdZTX_L-3UURMREpOFq36ZvwXafLxa83r1pkyclvHsxlpWxghSJZAQAnk1ND8tFXGVP3nlYYyLcr5yXJCxgGg3ikrojm4AEToGyMix_5ezcSut8svmZ3E5RMlBKqujREPliL8wmw_lzZFaH33UcHJ-yhKQqgB2INWt4muAiuLe7ebEpA9e2Mg1AMp2rwiV3jIgjXkUMRzUnlxi9JBmKi42RwEUHTBd19-c3TRysGLaORsPcqpEJlFKvTNe8aeCne5uECQpvxgdDiMKU-nn3xVOEkoF6z62Lt9xbsoop8BNXtm2a9YIv-auUkOdcycOyfGhoQgZgXUF6gTUxtE6OwJwTrjXmXe1PWglstTIEKurhQcDm2AWW4oTddFtCjej_UsSie62kJnN5ZI1iA6lNZIHurpQa4KB1gAJg-G7PPAFChQjFSWSj2z374hEKDaUf5LLySHU3scaTUpXESOV6dma_8F_Z1-gQzS7jkDaWtLmEzzAhaAHcU1dvEBkSCOm3vZtP_9gH9-LNCfpfW8cImhWpe4N3XgMAhej9cY43443mu3gOAwixXjCAOUQ0kWIDI-tckE3WY9bKORlBmqw50rq50k10-Je3vmjqPvlwPdJYnvfgDn16L3dh49fWRLrYtmY2lOyrWE9aPfKZnDU9FqFaTH9Gsd3Z8Ov4EY03xkH_kAXcgtsR8FtpAoDWYp9cFhIxhQXy6_Sr_mHAOuBvqeZgOV8NVqMFWI3fHRIA_WSVYgGEJyysMi_R3Z-QU5iDY6z-Fov-6ZE2JJ1UNBcjACCKdeNYsnB_Op6PDFVuqqvUocieX6yQuIPO7ePfkrWl6U9bi-WjvkAe6nar7pYE61V7TGCsiQ7YNrT4vbQGFGtBaCQVtJY6ykkAFHq2O405A1v3TWXK6fZQrVzMSMd8xlzwxJliALN2CRXVqnRjMIWKk9CZfdcDBBRkYiZUiBojhZdFS78hQ9NI9mWFsU8DUYDxX828AEDHlIuuQZnXLQgDLjNm1xpELspA52Exa0OTCa-xXLAPb6ORC2bSzLBhV5HNfQ5LEN2EdjWB3Ha8CeEhpS3_iC3fVb-47ltWzQy1rwboS_xEnWICj2FlgdqVMYSFqP2qpQajQ7ifFwmmsVAFPrmLacFIM-UIk6XVV7Ku9MMMskhfq5e3S1qPBzm7CAhDEw1hgHFGn2AZ45AUSxYcC-AAM-st7mLZHXD39EH1r1YzDLSA9eGKxtW8PCngIEVVUeRIHb1qKhEeARn2e5x6Wn6GV52AZxAJRaGVsbG9AZXhhbXBsZS5jb20EgQEDOQEA",
    );
    const coseKey = parseCBORToCOSEKey(cbor);
    const { key } = await importPrivateKey(coseKey, true);
    const signature = await crypto.subtle.sign(
      { name: "RSASSA-PKCS1-v1_5" },
      key,
      ENCODER.encode("Hello world"),
    );
    assert(signature != null && signature.byteLength > 0);
  });
  it("Imports a RS256 public key", async () => {
    const cbor = decode(
      "pgEDAlFoZWxsb0BleGFtcGxlLmNvbQSBAgM5AQAhQwEAASBZAQC39rfzb7mCsntRDoHf687SeuTxrQxO7A-sPfbmwS_zwLAAW3OGfhZuya8qDxoUF5ybosh74yEWOPKXZmE-ac-N8UQazh1OItA5aJILDI_gWYtkqi4-B08v-IgF_s1Au-fLll6gsQtvTOSBs6-ZYSkdVKNsLDUrp_D98nrLzgV4vydSEvwqlbt_Ykxgw6x_5ZhJIzuCvf0nMBYDr7dxQcEvxYJSARZIFNuMqJnc5iDEzCnT4C8sJOGxJqTV62nOnnvZMVEIF_zzXVWZgTPqi7D3RmCpsmD0C2lee1dV1lNf8v7dRRExESk4Wrfpm_Bdp8vFrzevWmTJyW8ezGWlbGCF",
    );
    const coseKey = parseCBORToCOSEKey(cbor);
    const { key } = await importPublicKey(coseKey);
    const verified = await crypto.subtle.verify(
      { name: "RSASSA-PKCS1-v1_5" },
      key,
      decodeBase64Url(
        "F88zCMVUxVCQVBpT_HVEcceQ-g9q2RDm3u1olumXg-n5lFaM2S1lap8Vmb2z5wkmpf8pVryvaTJuJWiQ34A9bDLw3OvppvrBTMZxk3GocLCqRfjCNicL3AR70Vl-lHkaSNnH5iW8OT-yShAmB9OYNfqzcL3loeDNBgGV3LMqKrDu4JsDYL5v7-n4C0jwaWLeQdXQFUmtDy_-oKneOczksPDitoL9hi-T7KNGQzgAOqdBZXksdiYfouTxjqSMh38-2DCNpSHkdF-RKpeuGajXp1MDMkh9ZtCSvjJ1Lg975yxDX5txzEZZuTUznIRO31wdYhlYPQ05VshOnP5uHlm4iA",
      ),
      ENCODER.encode("Hello world"),
    );
    assert(verified);
  });
  it("Imports a ES256 private key", async () => {
    const cbor = decode(
      "pwECIAEhWCD2dKUDaWhLWJ9mzZ-gcJeFgTzXmvVwGsh_-z-MnRMUHyJYINwlpbVywj_6LAUv8yACBRmEWcLeTmMsQQX4vTh083hNI1ggnuG5ksf4_br2nNDQC0cwfx2STOLiL57U04pAfYaUhNgCUWhlbGxvQGV4YW1wbGUuY29tBIEB",
    );
    const coseKey = parseCBORToCOSEKey(cbor);
    const { key } = await importPrivateKey(coseKey, true);
    const signature = await crypto.subtle.sign(
      { name: "ECDSA", hash: { name: "SHA-256" } },
      key,
      ENCODER.encode("Hello world"),
    );
    assert(signature != null && signature.byteLength > 0);
  });
  it("Imports a ES256 public key", async () => {
    const cbor = decode(
      "pgECAlFoZWxsb0BleGFtcGxlLmNvbQSBAiABIVgg9nSlA2loS1ifZs2foHCXhYE815r1cBrIf_s_jJ0TFB8iWCDcJaW1csI_-iwFL_MgAgUZhFnC3k5jLEEF-L04dPN4TQ",
    );
    const coseKey = parseCBORToCOSEKey(cbor);
    const { key } = await importPublicKey(coseKey);
    const verified = await crypto.subtle.verify(
      { name: "ECDSA", hash: { name: "SHA-256" } },
      key,
      decodeBase64Url(
        "ds2xLiNSQoqv3OAy-Q8l0QuZ7hLsshtNayxf9seId4Yx39xCzfzipQBuqYx0gQa6o1Ketq49Ph092qRtbwjRiQ",
      ),
      ENCODER.encode("Hello world"),
    );
    assert(verified);
  });
  it("Imports a Ed25519 private key", async () => {
    const cbor = decode(
      "pQEBIAYhWCBMBNC6kELz0E-_DMukE1opN0PlMpI0BHryQ-Q-TuvG8CNYIAe8jNQE0LJjAwBNCF1rBPRWOH6bPvS6jgOgI76ZJyl6BIEB",
    );
    const coseKey = parseCBORToCOSEKey(cbor);
    const { key } = await importPrivateKey(coseKey, true);
    const signature = await crypto.subtle.sign(
      { name: "Ed25519" },
      key,
      ENCODER.encode("Hello world"),
    );
    assert(signature != null && signature.byteLength > 0);
  });
  it("Imports an Ed25519 public key", async () => {
    const cbor = decode(
      "pAEBBIECIAYhWCBMBNC6kELz0E-_DMukE1opN0PlMpI0BHryQ-Q-TuvG8A",
    );
    const coseKey = parseCBORToCOSEKey(cbor);
    const { key } = await importPublicKey(coseKey);
    const verified = await crypto.subtle.verify(
      { name: "Ed25519" },
      key,
      decodeBase64Url(
        "NXTlvCErNKKo2hBxJlniLh7NlBXsTiKXAQROfULE3JPmwYjLSTneTU-pvCTHKtC-zAXrltoOgQ7GuT3-jYT-Aw",
      ),
      ENCODER.encode("Hello world"),
    );
    assert(verified);
  });
});
