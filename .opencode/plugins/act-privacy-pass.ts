/**
 * ACT (Anonymous Credit Tokens) Privacy Pass Plugin for OpenCode
 *
 * Provides an `act_fetch` tool that automatically handles ACT authentication.
 * Use this instead of webfetch for ACT-protected endpoints.
 *
 * Requirements:
 * - act-cli installed and in PATH
 * - Credential enrolled via: act login <issuer-url>
 *
 * @see https://datatracker.ietf.org/doc/draft-schlesinger-privacypass-act/
 */

import { type Plugin, tool } from '@opencode-ai/plugin';

export const ACTPrivacyPassPlugin: Plugin = async ({ $, client }) => {
  const log = async (level: 'debug' | 'info' | 'warn' | 'error', message: string) => {
    await client.app.log({
      body: { service: 'act-privacy-pass', level, message },
    });
  };

  // Check act-cli availability at startup
  const actCheck = await $`which act`.quiet().nothrow();
  if (actCheck.exitCode !== 0) {
    await log('warn', 'act-cli not found in PATH, ACT tools disabled');
    await log('info', 'Install: cargo install --git https://github.com/thibmeu/act-rs act-cli');
    return {};
  }

  await log('info', 'ACT Privacy Pass plugin loaded');

  return {
    tool: {
      act_fetch: tool({
        description: `Fetch a URL with ACT (Anonymous Credit Tokens) authentication.
Use this for ACT-protected endpoints that return 401 with WWW-Authenticate: PrivateToken.
Automatically handles credential lookup, token generation, and refund processing.
Requires act-cli with an enrolled credential for the issuer.`,
        args: {
          url: tool.schema.string().describe('The URL to fetch'),
          credential: tool.schema
            .string()
            .optional()
            .describe('Credential name (defaults to issuer hostname)'),
        },
        async execute(args, context) {
          const { url, credential } = args;

          // Validate URL
          let parsedUrl: URL;
          try {
            parsedUrl = new URL(url);
          } catch {
            return { error: `Invalid URL: ${url}` };
          }

          await log('info', `ACT fetch: ${url}`);

          // Use act redeem which handles the full flow
          const credFlag = credential ? `-u ${credential}` : '';
          const result = await $`act redeem ${url} ${credFlag}`.quiet().nothrow();

          if (result.exitCode !== 0) {
            const stderr = result.stderr;

            if (stderr.includes('no credential') || stderr.includes('not found')) {
              return {
                error: `No ACT credential found for this issuer.\nEnroll first: act login <issuer-url>`,
                stderr,
              };
            }
            if (stderr.includes('insufficient') || stderr.includes('balance')) {
              return {
                error: `ACT credential has insufficient balance.\nRe-enroll: act login <issuer-url>`,
                stderr,
              };
            }

            return { error: `ACT request failed: ${stderr}` };
          }

          await log('debug', 'ACT request successful');

          return {
            success: true,
            output: result.stdout,
            url,
          };
        },
      }),

      act_balance: tool({
        description: 'Check ACT credential balance and details',
        args: {
          credential: tool.schema.string().optional().describe('Credential name to inspect'),
        },
        async execute(args) {
          const credFlag = args.credential ? `-u ${args.credential}` : '';
          const result = await $`act inspect ${credFlag} --json`.quiet().nothrow();

          if (result.exitCode !== 0) {
            return { error: result.stderr || 'No credential found' };
          }

          try {
            return JSON.parse(result.stdout);
          } catch {
            return { output: result.stdout };
          }
        },
      }),

      act_enroll: tool({
        description: 'Enroll a new ACT credential from an issuer',
        args: {
          issuer_url: tool.schema
            .string()
            .describe('Issuer URL (e.g., https://act-issuer.research.cloudflare.com)'),
          credits: tool.schema
            .number()
            .optional()
            .describe('Number of credits to request (default: 100)'),
          name: tool.schema.string().optional().describe('Name for the credential'),
        },
        async execute(args) {
          const { issuer_url, credits, name } = args;

          const creditFlag = credits ? `--credits ${credits}` : '';
          const nameFlag = name ? `--as ${name}` : '';

          const result = await $`act login ${issuer_url} ${creditFlag} ${nameFlag}`
            .quiet()
            .nothrow();

          if (result.exitCode !== 0) {
            return { error: `Enrollment failed: ${result.stderr}` };
          }

          return {
            success: true,
            message: 'Credential enrolled successfully',
            output: result.stdout,
          };
        },
      }),
    },
  };
};

export default ACTPrivacyPassPlugin;
