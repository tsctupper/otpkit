// Match the declaration paths accepted by the existing lint policy, including
// TypeScript's .d.<extension>.ts convention and case-insensitive suffixes.
function isDeclarationPath(filename) {
  return /\.d\.(?:[cm]?ts|.*\.ts)$/i.test(filename);
}

function isDeclaredNamespace(node) {
  for (let current = node; current; current = current.parent) {
    if (current.type === "TSModuleDeclaration" && current.declare) return true;
  }
  return false;
}

export default {
  meta: {
    type: "suggestion",
    schema: [
      {
        type: "object",
        properties: {
          allowDeclarations: { type: "boolean" },
          allowDefinitionFiles: { type: "boolean" },
        },
        additionalProperties: false,
      },
    ],
    messages: { moduleSyntaxIsPreferred: "ES2015 module syntax is preferred over namespaces." },
  },
  create(context) {
    const { allowDeclarations = false, allowDefinitionFiles = true } = context.options[0] ?? {};
    if (allowDefinitionFiles && isDeclarationPath(context.filename)) return {};
    return {
      'TSModuleDeclaration[kind!="global"][id.type!="Literal"]'(node) {
        if (allowDeclarations && isDeclaredNamespace(node)) return;
        context.report({ node, messageId: "moduleSyntaxIsPreferred" });
      },
    };
  },
};
