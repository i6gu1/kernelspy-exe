// KernelSpy Scanner - minimal ESLint flat config focused on security rules.
export default [
  {
    files: ["**/*.js", "**/*.mjs", "**/*.cjs", "**/*.jsx", "**/*.ts", "**/*.tsx"],
    rules: {
      "no-eval": "error",
      "no-implied-eval": "error",
      "no-new-func": "error",
      "no-script-url": "error",
      "no-prototype-builtins": "warn",
      "no-restricted-syntax": [
        "error",
        {
          "selector": "AssignmentExpression[left.property.name='innerHTML']",
          "message": "Potential XSS: avoid assigning to innerHTML."
        },
        {
          "selector": "CallExpression[callee.property.name='write'][callee.object.name='document']",
          "message": "Potential XSS: document.write is unsafe."
        }
      ]
    }
  }
];
