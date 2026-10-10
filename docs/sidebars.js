/*
 * Copyright (c) 2025-2026 Datalayer, Inc.
 * Distributed under the terms of the Modified BSD License.
 */

/**
 * Creating a sidebar enables you to:
 - create an ordered group of docs
 - render a sidebar for each doc of that group
 - provide next/previous navigation

 The sidebars can be generated from the filesystem, or explicitly defined here.

 Create as many sidebars as you want.
 */

// @ts-check

/** @type {import('@docusaurus/plugin-content-docs').SidebarsConfig} */
const sidebars = {
  docsSidebar: [
    "index",
    "getting-started/index",
    {
      type: "category",
      label: "Understand PAP",
      collapsed: false,
      items: [
        "concepts/protocol-tour",
        "concepts/architecture",
        "concepts/glossary",
        "protocol/coverage",
      ],
    },
    {
      type: "category",
      label: "SDKs",
      collapsed: false,
      items: [
        "sdk/python",
        "sdk/python-api",
        "sdk/typescript",
        "sdk/typescript-api",
      ],
    },
    {
      type: "category",
      label: "Implementation guides",
      collapsed: false,
      items: [
        "guides/personal-agent",
        "guides/sessions",
        "guides/cryptography",
        "guides/direct-sign-in",
        "guides/company",
        "guides/agent-runtimes",
        "guides/extensions",
        "guides/cli",
        "guides/conformance",
      ],
    },
    {
      type: "category",
      label: "Example flows",
      collapsed: false,
      items: [
        "examples/index",
        "examples/company-discovery",
        "examples/agent-identity",
        "examples/session-assertion",
        "examples/direct-sign-in-boundary",
        "examples/dpop-proof",
        "examples/dpop-transport",
        "examples/conversation-messages",
        "examples/session-lifecycle",
        "examples/direct-sign-in-lifecycle",
        "examples/browser-session",
      ],
    },
    {
      type: "category",
      label: "Contributing",
      items: ["contributing/sdk-design"],
    },
    "studio/integration",
    "security/index",
    "protocol/status",
  ],
};

module.exports = sidebars;
