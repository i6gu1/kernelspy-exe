// KernelSpy Scanner - security-focused ESLint flat config.
// Loaded explicitly by EslintRunner with --no-config-lookup so the scanned
// project's own configuration cannot weaken these checks.
export default [
  {
    files: ["**/*.js", "**/*.mjs", "**/*.cjs", "**/*.jsx", "**/*.ts", "**/*.tsx"],
    rules: {
      "no-eval": "error",
      "no-implied-eval": "error",
      "no-new-func": "error",
      "no-script-url": "error",
      "no-restricted-syntax": [
        "error",
        {
          "selector": "AssignmentExpression[left.property.name='innerHTML']",
          "message": "Potential XSS: avoid assigning to innerHTML."
        },
        {
          "selector": "AssignmentExpression[left.property.name='outerHTML']",
          "message": "Potential XSS: avoid assigning to outerHTML."
        },
        {
          "selector": "CallExpression[callee.property.name='write'][callee.object.name='document']",
          "message": "Potential XSS: document.write is unsafe."
        },
        {
          "selector": "CallExpression[callee.name='insertAdjacentHTML']",
          "message": "Potential XSS: insertAdjacentHTML can inject markup."
        },
        {
          "selector": "CallExpression[callee.property.name='insertAdjacentHTML']",
          "message": "Potential XSS: insertAdjacentHTML can inject markup."
        }
      ]
    }
  }
];
