export default {
  meta: {
    type: "suggestion",
    fixable: "code",
    schema: [],
    messages: { useNamespace: "Use 'namespace' instead of 'module' to declare custom TypeScript modules." },
  },
  create(context) {
    return {
      TSModuleDeclaration(node) {
        if (node.kind !== "module" || node.id.type === "Literal") return;
        // The name can be qualified. Its preceding token is the introducer,
        // even with comments between the keyword and the first identifier.
        const keyword = context.sourceCode.getTokenBefore(node.id);
        context.report({
          node,
          messageId: "useNamespace",
          fix: (fixer) => fixer.replaceText(keyword, "namespace"),
        });
      },
    };
  },
};
