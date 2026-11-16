// Shared ESLint flat config for every TypeScript package (each runs `eslint .` from its own folder).
import js from '@eslint/js';
import globals from 'globals';
import tseslint from 'typescript-eslint';

export default tseslint.config(
  { ignores: ['**/dist/**', '**/node_modules/**', '**/coverage/**'] },
  js.configs.recommended,
  ...tseslint.configs.recommendedTypeChecked,
  {
    languageOptions: {
      globals: globals.node,
      parserOptions: { projectService: true, tsconfigRootDir: import.meta.dirname },
    },
    rules: {
      // Never let a promise (an approval, a pipe call) fail silently.
      '@typescript-eslint/no-floating-promises': 'error',
      // stdout carries MCP protocol messages; log to stderr with console.error only.
      'no-console': ['error', { allow: ['error'] }],
    },
  },
  {
    files: ['**/*.js'],
    ...tseslint.configs.disableTypeChecked,
  },
  // TEMPORARY (DECISIONS.md D-008). Hand-off code whose pipe/device responses are still untyped `any`.
  // Phase 3 (mcp-server) and Phase 7 (relay) replace these with Zod-validated responses and delete this block.
  // Do not add files to this list; new code gets the full rule set.
  {
    files: [
      'apps/mcp-server/src/core-client.ts',
      'apps/mcp-server/src/tools/fill-login.ts',
      'apps/mcp-server/src/tools/search-items.ts',
      'services/relay/src/server.ts',
      'services/relay/src/device-link.stub.ts',
    ],
    rules: {
      '@typescript-eslint/no-explicit-any': 'off',
      '@typescript-eslint/no-unsafe-argument': 'off',
      '@typescript-eslint/no-unsafe-assignment': 'off',
      '@typescript-eslint/no-unsafe-member-access': 'off',
      '@typescript-eslint/require-await': 'off',
      '@typescript-eslint/unbound-method': 'off',
      '@typescript-eslint/no-misused-promises': 'off',
      // Flags `RELAY_STATE_KEY!`, which is a real bug (an unset key means an empty HMAC key). Fixed in Phase 7.
      '@typescript-eslint/no-unnecessary-type-assertion': 'off',
    },
  },
);
