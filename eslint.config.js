import { createHash } from "node:crypto";
import { builtinRules } from "eslint/use-at-your-own-risk";
import tseslint from "typescript-eslint";
import noNamespace from "./scripts/lint/no-namespace.mjs";
import preferNamespaceKeyword from "./scripts/lint/prefer-namespace-keyword.mjs";

// ESLint exposes its built-in rule registry without a stability guarantee.
const recommendedNames = [...builtinRules]
  .filter(([, rule]) => rule.meta.docs.recommended === true)
  .map(([name]) => name)
  .sort();
const ruleSetDigest = createHash("sha256").update(JSON.stringify(recommendedNames)).digest("hex");
if (ruleSetDigest !== "26d2e4c3de39d0c32819430300649c594c42c7fdbf3ca0f7ab8723e7b73abb4d") {
  throw new Error(
    "ESLint's recommended core rules changed. Review the rule changes before updating the digest.",
  );
}

// Keep the existing rule IDs so inline suppressions and CLI overrides still apply.
const strictConfig = tseslint.configs.strictTypeChecked.map((config) => {
  const plugin = config.plugins?.["@typescript-eslint"];
  if (!plugin) return config;
  return {
    ...config,
    plugins: {
      ...config.plugins,
      "@typescript-eslint": {
        ...plugin,
        rules: {
          ...plugin.rules,
          "no-namespace": noNamespace,
          "prefer-namespace-keyword": preferNamespaceKeyword,
        },
      },
    },
  };
});

export default tseslint.config(
  { ignores: ["dist", "coverage", "node_modules"] },
  { rules: Object.fromEntries(recommendedNames.map((name) => [name, "error"])) },
  ...strictConfig,
  {
    languageOptions: { parserOptions: { projectService: true, tsconfigRootDir: import.meta.dirname } },
    rules: {
      "@typescript-eslint/consistent-type-imports": "error",
      "@typescript-eslint/restrict-template-expressions": ["error", { allowNumber: true }],
    },
  },
  // node:test registers top-level tests via un-awaited calls by design.
  { files: ["test/**"], rules: { "@typescript-eslint/no-floating-promises": "off" } },
  { files: ["eslint.config.js"], ...tseslint.configs.disableTypeChecked },
  {
    files: [
      "examples/**/*.mjs",
      "scripts/test.mjs",
      "scripts/lint/no-namespace.mjs",
      "scripts/lint/no-namespace.test.mjs",
      "scripts/lint/prefer-namespace-keyword.mjs",
      "scripts/lint/prefer-namespace-keyword.test.mjs",
    ],
    ...tseslint.configs.disableTypeChecked,
  },
);
