// ex. scripts/build_npm.ts
import { build, emptyDir } from "https://deno.land/x/dnt@0.37.0/mod.ts";

await emptyDir("./npm");

await build({
  entryPoints: ["./index.ts"],
  outDir: "./npm",
  shims: {
    deno: true,
  },
  test: false,
  mappings: {
    "https://deno.land/x/tiny_cbor@0.2.2/index.ts": {
      name: "@levischuck/tiny-cbor",
      version: "0.2.2",
    },
  },
  package: {
    // package.json properties
    name: "@levischuck/tiny-cose",
    version: Deno.args[0],
    description: "Tiny COSE library for cryptographic operations in CBOR",
    license: "MIT",
    repository: {
      type: "git",
      url: "git+https://github.com/levischuck/tiny-cose.git",
    },
    bugs: {
      url: "https://github.com/levischuck/tiny-cose/issues",
    },
  },
  compilerOptions: {
    lib: ["ES2021", "DOM"],
  },
  postBuild() {
    // steps to run after building and before running the tests
    Deno.copyFileSync("LICENSE.txt", "npm/LICENSE");
    Deno.copyFileSync("README.md", "npm/README.md");
  },
});
