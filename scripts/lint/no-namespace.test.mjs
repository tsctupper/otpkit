import assert from "node:assert/strict";
import { test } from "node:test";
import { ESLint } from "eslint";
import noNamespace from "./no-namespace.mjs";

const id = "@typescript-eslint/no-namespace";
const eslint = new ESLint();
const filename = "src/index.ts";

async function lint(text, filePath = filename, engine = eslint) {
  const [result] = await engine.lintText(text, { filePath });
  assert.equal(result.fatalErrorCount, 0, JSON.stringify(result.messages));
  return result.messages.filter((message) => message.ruleId === id);
}

test("the project uses its local rule under the existing directive name", async () => {
  const { plugins, rules } = await eslint.calculateConfigForFile(filename);
  assert.equal(plugins["@typescript-eslint"].rules["no-namespace"], noNamespace);
  assert.equal(rules[id][0], 2);
});

test("reports the full declaration for both outer and nested namespaces", async () => {
  const messages = await lint("export namespace Outer {\n  export namespace Inner.Deep {}\n}");
  assert.deepEqual(
    messages.map(({ messageId, line, column, endLine, endColumn }) => [
      messageId,
      line,
      column,
      endLine,
      endColumn,
    ]),
    [
      ["moduleSyntaxIsPreferred", 1, 8, 3, 2],
      ["moduleSyntaxIsPreferred", 2, 10, 2, 33],
    ],
  );
});

test("permits augmentations, reports namespaces inside them and honors suppressions", async () => {
  const messages = await lint(
    [
      'declare module "external" { namespace Nested {} }',
      "export {}; declare global { namespace Inside {} }",
      "// eslint-disable-next-line @typescript-eslint/no-namespace",
      "namespace AllowedHere {}",
      "namespace global {}",
    ].join("\n"),
  );
  assert.deepEqual(
    messages.map(({ line, column }) => [line, column]),
    [
      [1, 29],
      [2, 29],
      [5, 1],
    ],
  );
});

test("respects declaration files and the two rule options", async () => {
  const text = "declare namespace Outer { namespace Inner {} }";
  const file = "types/node-runtime.d.ts";
  assert.equal((await lint(text, file)).length, 0);
  const configured = (options) => new ESLint({ overrideConfig: { rules: { [id]: ["error", options] } } });
  assert.equal((await lint(text, file, configured({ allowDefinitionFiles: false }))).length, 2);
  const allowDeclared = configured({ allowDeclarations: true });
  assert.equal((await lint(text, filename, allowDeclared)).length, 0);
  assert.equal((await lint("namespace Plain {}", filename, allowDeclared)).length, 1);
  assert.equal(
    (await lint("declare class X { static { namespace Nested {} } }", filename, allowDeclared)).length,
    1,
  );
});
