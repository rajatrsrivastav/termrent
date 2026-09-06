import js from '@eslint/js';
import globals from 'globals';
export default [
  { ignores: ['node_modules/**', 'test-results/**'] },
  js.configs.recommended,
  { files: ['**/*.js'], languageOptions: { globals: globals.node } },
  { files: ['public/*.js', 'test/e2e/*.js'], languageOptions: { globals: globals.browser } },
  { rules: { 'no-unused-vars': ['error', { caughtErrors: 'none' }] } },
];
