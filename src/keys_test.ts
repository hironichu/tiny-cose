import {
  assertEquals,
  assertNotEquals,
  assertRejects,
} from "https://deno.land/std@0.195.0/assert/mod.ts";
import { describe, it } from "https://deno.land/std@0.195.0/testing/bdd.ts";
import {
  exportPrivateKey,
  exportPublicKey,
  exportSymmetricKey,
} from "./keys.ts";
import {
  EC2_CRV_P256,
  EC2_CRV_P384,
  ECDSA_SHA_256,
  ECDSA_SHA_384,
  HMAC_SHA_256,
  HMAC_SHA_384,
  HMAC_SHA_512,
  KEY_OP_MAC_CREATE,
  KEY_OP_MAC_VERIFY,
  KEY_OP_SIGN,
  KEY_OP_VERIFY,
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
});
