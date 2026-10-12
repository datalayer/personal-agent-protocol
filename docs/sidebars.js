/*
 * Copyright (c) 2025-2026 Datalayer, Inc.
 *
 * BSD 3-Clause License
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
        "concepts/contribution-points",
        "concepts/glossary",
        "protocol/coverage",
        {
          type: "category",
          label: "Coverage by area",
          items: [
            "protocol/coverage/discovery",
            "protocol/coverage/identity-sessions",
            "protocol/coverage/sign-in",
            "protocol/coverage/browser",
            "protocol/coverage/apis",
            "protocol/coverage/conversations",
            "protocol/coverage/operations",
            "protocol/coverage/operational-guidance",
          ],
        },
        "protocol/load-tests",
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
        "guides/device-sign-in",
        "guides/mediated-sign-in",
        "guides/account-tokens",
        "guides/conversations",
        "guides/operations",
        "guides/company",
        "guides/agent-runtimes",
        "guides/extensions",
        "guides/operational-limits",
        "guides/cli",
        "guides/telemetry",
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
        "examples/conversation-events",
        "examples/session-lifecycle",
        "examples/direct-sign-in-lifecycle",
        "examples/device-sign-in",
        "examples/browser-session",
        "examples/mediated-sign-in",
        "examples/account-tokens",
        "examples/conversation-streaming",
        "examples/conversation-control",
        "examples/operations",
        "examples/user-with-a-company",
        "examples/two-companies",
      ],
    },
    {
      type: "category",
      label: "Contributing",
      items: ["contributing/sdk-design"],
    },
    {
      type: "category",
      label: "Releases",
      items: [
        "releases/compatibility",
        "releases/migration",
        "protocol/conformance-report",
        "releases/support",
      ],
    },
    "studio/integration",
    "security/index",
    "security/demonstrations",
    "security/review",
    "protocol/status",
  ],
};

module.exports = sidebars;
