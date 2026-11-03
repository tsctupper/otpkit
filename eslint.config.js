import js from "@eslint/js";
import tseslint from "typescript-eslint";

export default tseslint.config(
  { ignores: ["dist", "coverage", "node_modules"] },
  js.configs.recommended,
  ...tseslint.configs.strictTypeChecked,
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
);
