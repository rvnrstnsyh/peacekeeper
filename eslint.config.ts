import js from '@eslint/js'
import globals from 'globals'
import tseslint from 'typescript-eslint'

export default [
  {
    ignores: ['sys/**', 'node_modules/**', '_dist/**', '_drizzle/**', '**/*.js', '**/*.mjs', '**/*.cjs']
  },
  js.configs.recommended,
  ...tseslint.configs.recommended,
  {
    files: ['**/*.ts', '**/*.tsx'],
    languageOptions: {
      ecmaVersion: 2024,
      sourceType: 'module',
      parser: tseslint.parser,
      parserOptions: {
        projectService: true,
        tsconfigRootDir: __dirname
      },
      globals: {
        ...globals.node,
        ...globals.es2024
      }
    },
    rules: {
      // TypeScript specific rules
      '@typescript-eslint/no-explicit-any': 1,
      '@typescript-eslint/no-inferrable-types': 0,
      '@typescript-eslint/no-unused-vars': [
        1,
        {
          vars: 'all',
          args: 'none',
          argsIgnorePattern: '^_',
          varsIgnorePattern: '^_',
          caughtErrorsIgnorePattern: '^_'
        }
      ],
      '@typescript-eslint/no-non-null-assertion': 1,
      '@typescript-eslint/no-var-requires': 1,
      '@typescript-eslint/consistent-type-imports': [
        'error',
        {
          prefer: 'type-imports'
        }
      ],

      // General rules
      'handle-callback-err': 2,
      'no-debugger': 2,
      'no-fallthrough': 2,
      'eol-last': 1,
      'no-irregular-whitespace': 1,
      'no-mixed-spaces-and-tabs': [1, 'smart-tabs'],
      'no-trailing-spaces': 1,
      'no-new-require': 2,
      'no-unreachable': 2,
      'no-console': 1,
      'new-cap': 0,
      'max-len': [2, 300, 4],
      'space-before-function-paren': [
        'error',
        {
          anonymous: 'ignore',
          named: 'never',
          asyncArrow: 'ignore'
        }
      ],

      // Disable conflicting ESLint rules (handled by TypeScript)
      'no-undef': 0,
      'no-unused-vars': 0
    }
  },
  {
    files: ['**/*.d.ts'],
    rules: {
      '@typescript-eslint/no-explicit-any': 0,
      '@typescript-eslint/no-unused-vars': 0,
      '@typescript-eslint/triple-slash-reference': 0,
      '@typescript-eslint/ban-types': 0,
      '@typescript-eslint/no-empty-interface': 0
    }
  }
]
