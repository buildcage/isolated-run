import { globSync } from "node:fs";
import { defineConfig } from "rolldown";

// Small standalone scripts baked into the built Docker image, as opposed
// to rolldown.config.js's action entrypoints.
const productionInputs = globSync(["**/scripts/*.ts"], {
  exclude: ["node_modules/**", "dist/**", "**/*.test.ts"],
});

// src/core/lib/acl/*.test.ts is dual-consumed (also runs under vitest);
// *.property.test.ts siblings are vitest/fast-check only, not qjs-compatible.
const qjsTestInputs = [
  "src/core/scripts/test/run-tests.qjs.ts",
  ...globSync(["src/core/lib/acl/*.test.ts"], { exclude: ["**/*.property.test.ts"] }),
];

function settingsFor(input) {
  return input.endsWith(".qjs.ts")
    ? {
        outDir: "dist/qjs",
        stripSuffix: /\.qjs\.ts$/,
        external: ["qjs:std", "qjs:os"],
        platform: "neutral",
      }
    : {
        outDir: "dist/node-scripts",
        stripSuffix: /\.node\.ts$/,
        external: [/^node:/],
        platform: "node",
      };
}

const baseOutput = {
  format: "esm",
  codeSplitting: false,
  minify: {
    compress: true,
    mangle: false,
    codegen: { removeWhitespace: false, legalComments: "none" },
  },
};

const target = process.env.BUILD_TARGET;
const scriptInputs =
  target === "qjs"
    ? productionInputs.filter((input) => input.endsWith(".qjs.ts"))
    : productionInputs;

export default defineConfig(
  target === "qjs-test"
    ? qjsTestInputs.map((input) => ({
        input,
        // "vitest" is only ever reached by test-shim.ts's Node branch (dead at
        // qjs runtime), but its dynamic import()'s specifier is a compile-time
        // constant, so rolldown resolves and inlines it unless excluded here —
        // dragging in vitest's own devDependencies (e.g. expect-type), which
        // aren't installed for/resolvable under qjs's "neutral" platform.
        external: ["qjs:std", "qjs:os", "vitest"],
        platform: "neutral",
        output: { file: `dist/qjs-test/${input.replace(/\.ts$/, ".js")}`, ...baseOutput },
      }))
    : scriptInputs.map((input) => {
        const { outDir, stripSuffix, external, platform } = settingsFor(input);
        return {
          input,
          external,
          platform,
          output: { file: `${outDir}/${input.replace(stripSuffix, ".js")}`, ...baseOutput },
        };
      }),
);
