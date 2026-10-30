/*
 * Copyright (c) 2025-2026 Datalayer, Inc.
 *
 * BSD 3-Clause License
 */

const path = require('path');

/**
 * The package's `./decks` entry, from its source: the site shows the decks the
 * package ships without a build of the package first.
 */
function papDecks() {
  return {
    name: 'pap-decks',
    configureWebpack() {
      return {
        resolve: {
          alias: {
            '@datalayer/personal-agent-protocol/decks$': path.resolve(__dirname, '../src/decks/index.ts'),
          },
          // The source's `./x.js` imports name `./x.ts`.
          extensionAlias: { '.js': ['.ts', '.js'] },
          // `yaml`, for that source: it sits outside the site's node_modules.
          modules: [path.resolve(__dirname, 'node_modules'), 'node_modules'],
        },
      };
    },
  };
}

/** @type {import('@docusaurus/types').DocusaurusConfig} */
module.exports = {
  title: '🤖 🌸 Personal Agent Protocol',
  tagline: 'Build personal agents and company integrations on one open protocol',
  url: 'https://personal-agent-protocol.datalayer.tech',
  baseUrl: '/',
  onBrokenLinks: 'throw',
  favicon: 'img/favicon.ico',
  organizationName: 'datalayer',
  projectName: 'personal-agent-protocol',
  future: {
    v4: {
      removeLegacyPostBuildHeadAttribute: true,
    },
    faster: true,
  },
  markdown: {
    format: 'detect',
    mermaid: true,
    hooks: {
      onBrokenMarkdownLinks: 'throw',
    },
  },
  plugins: [
    'docusaurus-lunr-search',
    papDecks,
    // Each example explained as a short deck (docs/decks), at most ten slides.
    ['@datalayer/decks-docusaurus', { decksDir: 'decks', maxSlides: 10 }],
  ],
  themes: [
    '@docusaurus/theme-mermaid',
  ],
  themeConfig: {
    colorMode: {
      defaultMode: 'light',
      disableSwitch: true,
    },
    navbar: {
      title: 'Personal Agent Protocol',
      logo: {
        alt: 'Datalayer Logo',
        src: 'img/datalayer/logo.svg',
      },
      items: [
        {
          type: 'doc',
          docId: 'getting-started/index',
          position: 'left',
          label: 'Getting Started',
        },
        {
          type: 'docSidebar',
          sidebarId: 'docsSidebar',
          position: 'left',
          label: 'Documentation',
        },
        {
          type: 'dropdown',
          position: 'left',
          label: 'SDKs',
          items: [
            {type: 'doc', docId: 'sdk/python', label: 'Python SDK'},
            {type: 'doc', docId: 'sdk/typescript', label: 'TypeScript SDK'},
          ],
        },
        {to: '/blog', label: 'Blog', position: 'left'},
        {
          type: 'dropdown',
          position: 'left',
          label: 'Specification',
          items: [
            {label: 'personalagentprotocol.org', href: 'https://personalagentprotocol.org'},
            {label: 'Draft 0.2', href: 'https://personalagentprotocol.org/docs/0.2/spec'},
            {label: 'Changelog', href: 'https://personalagentprotocol.org/docs/changelog'},
            {
              label: 'GitHub: personal-agent-protocol',
              href: 'https://github.com/personal-agent-protocol/personal-agent-protocol',
            },
          ],
        },
        {
          href: 'https://discord.gg/YQFwvmSSuR',
          position: 'right',
          className: 'header-discord-link',
          'aria-label': 'Discord',
        },
        {
          href: 'https://github.com/datalayer',
          position: 'right',
          className: 'header-github-link',
          'aria-label': 'GitHub',
        },
        {
          href: 'https://bsky.app/profile/datalayer.ai',
          position: 'right',
          className: 'header-bluesky-link',
          'aria-label': 'Bluesky',
        },
        {
          href: 'https://x.com/DatalayerIO',
          position: 'right',
          className: 'header-x-link',
          'aria-label': 'X',
        },
        {
          href: 'https://www.linkedin.com/company/datalayer',
          position: 'right',
          className: 'header-linkedin-link',
          'aria-label': 'LinkedIn',
        },
        {
          href: 'https://tiktok.com/@datalayerio',
          position: 'right',
          className: 'header-tiktok-link',
          'aria-label': 'TikTok',
        },
        {
          href: 'https://www.youtube.com/@datalayer',
          position: 'right',
          className: 'header-youtube-link',
          'aria-label': 'YouTube',
        },
        {
          href: 'https://datalayer.ai',
          position: 'right',
          className: 'header-datalayer-io-link',
          'aria-label': 'Datalayer',
        },
      ],
    },
    footer: {
      style: 'dark',
      links: [
        {
          title: 'Docs',
          items: [
            {
              label: 'Personal Agent Protocol',
              to: '/',
            },
            {
              label: 'Implementation status',
              to: '/protocol/status/',
            },
            {
              label: 'Security',
              to: '/security/',
            },
            {
              label: 'Blog',
              to: '/blog',
            },
          ],
        },
        {
          title: 'Specification',
          items: [
            {
              label: 'personalagentprotocol.org',
              href: 'https://personalagentprotocol.org',
            },
            {
              label: 'Specification on GitHub',
              href: 'https://github.com/personal-agent-protocol/personal-agent-protocol',
            },
            {
              label: 'Protocol feedback',
              href: 'https://github.com/personal-agent-protocol/personal-agent-protocol/issues',
            },
          ],
        },
        {
          title: 'Community',
          items: [
            {
              label: 'GitHub',
              href: 'https://github.com/datalayer',
            },
            {
              label: 'Bluesky',
              href: 'https://bsky.app/profile/datalayer.ai',
            },
            {
              label: 'LinkedIn',
              href: 'https://www.linkedin.com/company/datalayer',
            },
          ],
        },
        {
          title: 'More',
          items: [
            {
              label: 'Datalayer AI',
              href: 'https://datalayer.ai',
            },
            {
              label: 'Datalayer Blog',
              href: 'https://datalayer.blog',
            },
          ],
        },
      ],
      copyright: `Copyright © ${new Date().getFullYear()} Datalayer, Inc.`,
    },
  },
  presets: [
    [
      '@docusaurus/preset-classic',
      {
        docs: {
          routeBasePath: '/',
          sidebarPath: require.resolve('./sidebars.js'),
          editUrl: 'https://github.com/datalayer/personal-agent-protocol/edit/main/docs/',
        },
        blog: {
          blogTitle: 'Personal Agent Protocol blog',
          blogDescription: 'Releases and news of the Personal Agent Protocol SDKs',
          showReadingTime: true,
          editUrl: 'https://github.com/datalayer/personal-agent-protocol/edit/main/docs/',
        },
        theme: {
          customCss: require.resolve('./src/css/custom.css'),
        },
      },
    ],
  ],
};
