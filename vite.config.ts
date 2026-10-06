import { defineConfig } from "vite-plus";

const generatedOutputs = ["dist/**"];
const fixtures = ["**/__fixtures__/**"];

// Allowed to name the always-on `annotate`; everything else takes the sink as an argument
// (see src/core/lib/actions/annotation.ts).
const annotateCallers = [
  "src/lib/sandbox-step.ts",
  "src/post.ts",
  "src/core/lib/actions/fatal.ts",
  "src/core/lib/actions/annotation.test.ts",
];

export default defineConfig({
  lint: {
    ignorePatterns: generatedOutputs,
    rules: {
      // A regex, not a group glob: a glob matches the specifier as written, so it would
      // miss the relative "./annotation.ts" that fatal.ts imports through.
      "no-restricted-imports": [
        "error",
        {
          patterns: [
            {
              regex: "annotation\\.ts$",
              importNames: ["annotate"],
              message: "Take an Annotation, or the annotate method, as an argument instead.",
            },
          ],
        },
      ],
    },
    overrides: [{ files: annotateCallers, rules: { "no-restricted-imports": "off" } }],
    options: { typeAware: true },
  },
  fmt: {
    sortImports: true,
    ignorePatterns: [...generatedOutputs, ...fixtures, "MAINTAINERS.md"],
  },
  staged: {
    "*.{ts,tsx,js,jsx,json,jsonc,yaml,yml,md}": "vp check --fix",
    "dist/**/*.cjs": "sh .github/actions/verify-dist/check-test-hooks.sh",
    "docker/gen-seccomp-profile/**/*.go": "gofmt -w",
  },
  test: {
    include: ["src/**/*.test.ts"],
    restoreMocks: true,
    // @vitest/coverage-v8 is pinned to the exact vitest version vite-plus
    // bundles, which vite-plus asserts at startup; bump both together.
    coverage: {
      provider: "v8",
      // Without an explicit include, v8 reports only files some test imported,
      // which hides the files that have no test at all.
      include: ["src/**/*.ts"],
      exclude: [
        "**/*.test.ts",
        ...fixtures,
        "**/*.d.ts",
        // Test scaffolding: the QuickJS shims and the QuickJS test runner.
        "src/core/lib/test/**",
        "src/core/scripts/test/**",
        // QuickJS entry points, which vitest cannot run. What they call is
        // measured where it lives.
        "**/*.qjs.ts",
      ],
      // text goes to the CI log; the file copy is what the workflow pastes
      // into the job summary.
      reporter: [
        ["text", {}],
        ["text-summary", { file: "summary.txt" }],
      ],
      // 100% is not the goal in itself: it is what makes new untested code
      // fail the run instead of sinking into a number nobody reads. What is
      // deliberately untested carries a v8 ignore comment naming the reason.
      thresholds: { 100: true },
    },
  },
});
