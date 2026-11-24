import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readdirSync, rmSync } from "node:fs";
import { createRequire } from "node:module";
import { join } from "node:path";
import process from "node:process";

const coverage = process.argv.includes("--coverage");
const require = createRequire(import.meta.url);

// Isolate each compilation, including concurrent test and coverage runs.
// Under the package root, the emitted files inherit its ESM configuration.
mkdirSync("coverage", { recursive: true });
const outDir = mkdtempSync(join("coverage", "test-"));
try {
  execFileSync(
    process.execPath,
    [
      require.resolve("typescript/bin/tsc"),
      "--project",
      "tsconfig.json",
      "--noEmit",
      "false",
      "--rootDir",
      ".",
      "--outDir",
      outDir,
      "--sourceMap",
      "--inlineSources",
    ],
    { stdio: "inherit" },
  );

  const files = readdirSync(join(outDir, "test"))
    .filter((name) => name.endsWith(".test.js"))
    .map((name) => join(outDir, "test", name));
  if (files.length === 0) throw new Error("The compiler emitted no test files");

  const flags = coverage ? ["--experimental-test-coverage", "--test-coverage-include=**/src/**"] : [];
  execFileSync(process.execPath, ["--enable-source-maps", "--test", ...flags, ...files], {
    stdio: "inherit",
  });
} finally {
  rmSync(outDir, { recursive: true, force: true });
}
