import { defineConfig } from "vite-plus";

const generatedOutputs = ["dist/**"];
const fixtures = ["**/__fixtures__/**"];

export default defineConfig({
  lint: {
    ignorePatterns: generatedOutputs,
    options: { typeAware: true },
  },
  fmt: {
    ignorePatterns: [...generatedOutputs, ...fixtures, "MAINTAINERS.md"],
  },
  staged: {
    "*.{ts,tsx,js,jsx,json,jsonc,yaml,yml,md}": "vp check --fix",
    "docker/gen-seccomp-profile/**/*.go": "gofmt -w",
  },
  test: {
    include: ["src/**/*.test.ts"],
    restoreMocks: true,
  },
});
