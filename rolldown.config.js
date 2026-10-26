import { defineConfig } from "rolldown";
import { replacePlugin } from "rolldown/plugins";

// replacePlugin() substitutes BUILDCAGE_BUILD_TEST_HOOKS with the value from
// this build's own env, not the resulting action's runtime env; see
// readLocalImageOverride in src/lib/compose-file.ts.
const mainPlugins = [
  replacePlugin({
    "process.env.BUILDCAGE_BUILD_TEST_HOOKS": JSON.stringify(
      process.env.BUILDCAGE_BUILD_TEST_HOOKS ?? "",
    ),
  }),
];

const configs = [
  {
    input: "src/main.ts",
    file: "dist/main.cjs",
    plugins: mainPlugins,
    // src/core/lib/provenance's sigstore usage relies on dynamic imports;
    // inline them so dist is a single file.
    codeSplitting: false,
  },
  // Also gated: post.ts's own crash-fallback cleanup reads the same
  // BUILDCAGE_TEST_COMPOSE_OVERLAY override as main.ts, through that same
  // function, so it needs the same build-time substitution to keep that
  // reachable only in a test build.
  // In a BUILDCAGE_BUILD_TEST_HOOKS=1 build, that gate is reachable, so its
  // dynamic import needs the same codeSplitting: false as main.ts; without
  // it, rolldown wants a second chunk for the dynamic import, which
  // conflicts with output.file (single-file mode).
  { input: "src/post.ts", file: "dist/post.cjs", plugins: mainPlugins, codeSplitting: false },
];

export default defineConfig(
  configs.map(({ input, file, plugins, codeSplitting }) => ({
    input,
    external: [/^node:/],
    platform: "node",
    treeshake: {
      moduleSideEffects: [{ test: /\/(@actions\/http-client|undici)\//, sideEffects: false }],
    },
    plugins,
    output: {
      file,
      format: "cjs",
      codeSplitting,
      comments: false,
      minify: {
        compress: true,
        mangle: false,
        codegen: { removeWhitespace: false },
      },
    },
  })),
);
