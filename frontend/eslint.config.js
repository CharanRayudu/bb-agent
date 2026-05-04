import js from "@eslint/js";
import reactPlugin from "eslint-plugin-react";
import reactHooks from "eslint-plugin-react-hooks";

export default [
  js.configs.recommended,
  {
    files: ["src/**/*.{js,jsx}"],
    plugins: {
      react: reactPlugin,
      "react-hooks": reactHooks,
    },
    languageOptions: {
      ecmaVersion: 2022,
      sourceType: "module",
      parserOptions: {
        ecmaFeatures: { jsx: true },
      },
      globals: {
        // Browser globals
        window: "readonly",
        document: "readonly",
        console: "readonly",
        fetch: "readonly",
        setTimeout: "readonly",
        clearTimeout: "readonly",
        setInterval: "readonly",
        clearInterval: "readonly",
        URL: "readonly",
        URLSearchParams: "readonly",
        navigator: "readonly",
        localStorage: "readonly",
        sessionStorage: "readonly",
        EventSource: "readonly",
        AbortController: "readonly",
        AbortSignal: "readonly",
        WebSocket: "readonly",
        FormData: "readonly",
        FileReader: "readonly",
        Blob: "readonly",
        crypto: "readonly",
        performance: "readonly",
        requestAnimationFrame: "readonly",
        cancelAnimationFrame: "readonly",
        ResizeObserver: "readonly",
        MutationObserver: "readonly",
        IntersectionObserver: "readonly",
        CustomEvent: "readonly",
        Event: "readonly",
        KeyboardEvent: "readonly",
        MouseEvent: "readonly",
        HTMLElement: "readonly",
        Node: "readonly",
        TextDecoder: "readonly",
        TextEncoder: "readonly",
        confirm: "readonly",
        alert: "readonly",
        location: "readonly",
        history: "readonly",
        process: "readonly",
      },
    },
    settings: {
      react: { version: "18" },
    },
    rules: {
      ...reactPlugin.configs.recommended.rules,
      // Keep core hooks rules; disable the strict new v7 rules
      // that require large refactors of valid existing patterns.
      "react-hooks/rules-of-hooks": "error",
      "react-hooks/exhaustive-deps": "warn",
      "react-hooks/set-state-in-effect": "off",
      "react-hooks/immutability": "off",

      // React
      "react/react-in-jsx-scope": "off",
      "react/prop-types": "off",

      // Variables
      "no-unused-vars": ["warn", { argsIgnorePattern: "^_", varsIgnorePattern: "^_" }],
      "no-console": "off",

      // Allow empty catch blocks with a comment
      "no-empty": ["error", { allowEmptyCatch: true }],
    },
  },
];
