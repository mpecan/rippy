// @ts-check
import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';

export default defineConfig({
  site: 'https://rippy.pecan.si',
  integrations: [
    starlight({
      title: 'rippy',
      description:
        'A fast shell command safety hook for AI coding tools — written in Rust.',
      social: [
        {
          icon: 'github',
          label: 'GitHub',
          href: 'https://github.com/mpecan/rippy',
        },
      ],
      editLink: {
        baseUrl: 'https://github.com/mpecan/rippy/edit/main/site/',
      },
      customCss: ['./src/styles/custom.css'],
      sidebar: [
        {
          label: 'Getting started',
          items: [
            { label: 'Installation', slug: 'getting-started/installation' },
            { label: 'Claude Code', slug: 'getting-started/claude-code' },
            { label: 'Cursor', slug: 'getting-started/cursor' },
            { label: 'Gemini CLI', slug: 'getting-started/gemini-cli' },
            { label: 'Codex CLI', slug: 'getting-started/codex' },
          ],
        },
        {
          label: 'Configuration',
          items: [
            { label: 'Overview', slug: 'configuration/overview' },
            { label: 'Rules', slug: 'configuration/rules' },
            { label: 'Patterns', slug: 'configuration/patterns' },
            { label: 'Examples', slug: 'configuration/examples' },
          ],
        },
        {
          label: 'Reference',
          items: [
            { label: 'Safety model', slug: 'reference/safety-model' },
            { label: 'Handlers', slug: 'reference/handlers' },
            { label: 'File analysis', slug: 'reference/file-analysis' },
          ],
        },
        {
          label: 'About',
          items: [
            { label: 'Comparison with Dippy', slug: 'about/comparison' },
            { label: 'FAQ', slug: 'about/faq' },
          ],
        },
      ],
    }),
  ],
});
