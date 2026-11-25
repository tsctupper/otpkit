import assert from "node:assert/strict";
import { test } from "node:test";
import { ESLint } from "eslint";
import rule from "./prefer-namespace-keyword.mjs";

const id = "@typescript-eslint/prefer-namespace-keyword";
const eslint = new ESLint();
const filePath = "types/node-runtime.d.ts";

test("the project enables its own namespace keyword fixer", async () => {
  const { plugins, rules } = await eslint.calculateConfigForFile(filePath);
  assert.equal(plugins["@typescript-eslint"].rules["prefer-namespace-keyword"], rule);
  assert.equal(rules[id][0], 2);
});

test("fixes only the introducer, preserving trivia, dotted names and line endings", async () => {
  const prefix = "/* 🧭 */ export declare /* module */ ";
  const tail = " /* module */ module.Inner {\r\n  export type Label = 'module';\r\n}";
  const source = prefix + "module" + tail;
  const [report] = await eslint.lintText(source, { filePath });
  assert.equal(report.fatalErrorCount, 0);
  const changes = report.messages.filter((message) => message.ruleId === id);
  assert.deepEqual(
    changes.map(({ fix }) => fix),
    [{ range: [prefix.length, prefix.length + 6], text: "namespace" }],
  );
  const [fixed] = await new ESLint({ fix: true }).lintText(source, { filePath });
  assert.equal(fixed.output, prefix + "namespace" + tail);
});

test("checks named declarations inside augmentations and honors local suppressions", async () => {
  const source = [
    'declare module "module" {',
    "  export module Nested {}",
    "}",
    "declare global { namespace module {} }",
    "// eslint-disable-next-line @typescript-eslint/prefer-namespace-keyword",
    "declare module Allowed {}",
  ].join("\n");
  const [result] = await eslint.lintText(source, { filePath });
  assert.equal(result.fatalErrorCount, 0);
  assert.deepEqual(
    result.messages.filter((m) => m.ruleId === id).map((m) => m.line),
    [2],
  );
  assert.deepEqual(
    result.suppressedMessages.filter((m) => m.ruleId === id).map((m) => m.line),
    [6],
  );
});
