/**
 * ACT (Anonymous Credit Tokens) Privacy Pass Plugin for OpenCode
 *
 * Automatically intercepts 401 responses and retries with ACT authentication.
 * Also provides explicit tools for credential management.
 *
 * Requirements:
 * - act CLI installed and in PATH
 * - Credential enrolled via: act login <issuer-url>
 *
 * @see https://datatracker.ietf.org/doc/draft-schlesinger-privacypass-act/
 */

import { type Plugin, tool } from '@opencode-ai/plugin';

// ACT token type identifier
const ACT_TOKEN_TYPE = 0xe5ad;

// Cache for ACT challenge detection (avoids double-probing)
const actChallengeCache = new Map<string, boolean>();

export const ACTPrivacyPassPlugin: Plugin = async ({ $, client }) => {
  const log = async (level: 'debug' | 'info' | 'warn' | 'error', message: string) => {
    await client.app.log({
      body: { service: 'act-privacy-pass', level, message },
    });
  };

  // Check act CLI availability at startup
  const actCheck = await $`which act`.quiet().nothrow();
  if (actCheck.exitCode !== 0) {
    await log('warn', 'act CLI not found in PATH, ACT auto-retry disabled');
    await log('info', 'Install: cargo install --git https://github.com/thibmeu/act-rs act');
    return {};
  }

  await log('info', 'ACT Privacy Pass plugin loaded');

  /**
   * Check if a URL has an ACT challenge by probing with curl (cached)
   */
  const hasACTChallenge = async (url: string): Promise<boolean> => {
    // Check cache first
    const cached = actChallengeCache.get(url);
    if (cached !== undefined) {
      await log('debug', `ACT challenge cache hit for ${url}: ${cached}`);
      return cached;
    }

    const probe = await $`curl -sI ${url}`.quiet().nothrow();
    if (probe.exitCode !== 0) {
      actChallengeCache.set(url, false);
      return false;
    }

    const headers = probe.stdout.toString();
    const wwwAuth = headers.match(/WWW-Authenticate:\s*PrivateToken[^\r\n]+challenge="([^"]+)"/i);
    if (!wwwAuth) {
      actChallengeCache.set(url, false);
      return false;
    }

    // Decode challenge and check token type
    try {
      const challenge = wwwAuth[1];
      const bytes = Buffer.from(challenge.replace(/-/g, '+').replace(/_/g, '/'), 'base64');
      if (bytes.length < 2) {
        actChallengeCache.set(url, false);
        return false;
      }
      const tokenType = (bytes[0] << 8) | bytes[1];
      const isACT = tokenType === ACT_TOKEN_TYPE;
      actChallengeCache.set(url, isACT);
      return isACT;
    } catch {
      actChallengeCache.set(url, false);
      return false;
    }
  };

  /**
   * Attempt ACT redemption for a URL with optional headers/method/body
   */
  const tryACTRedeem = async (
    url: string,
    options?: {
      headers?: Record<string, string>;
      method?: string;
      body?: string;
    }
  ): Promise<{ success: boolean; output?: string; error?: string }> => {
    // Default to Accept: text/markdown for agent-friendly responses
    const headers = { Accept: 'text/markdown', ...options?.headers };

    // Build command args
    const args: string[] = ['redeem', url];
    for (const [key, value] of Object.entries(headers)) {
      args.push('-H', `${key}: ${value}`);
    }
    if (options?.method) {
      args.push('-X', options.method);
    }
    if (options?.body) {
      args.push('-d', options.body);
    }

    const result = await $`act ${args}`.quiet().nothrow();
    if (result.exitCode !== 0) {
      return { success: false, error: result.stderr.toString() };
    }
    return { success: true, output: result.stdout.toString() };
  };

  return {
    // Intercept webfetch 401s and retry with ACT
    'tool.execute.after': async (
      input: { tool: string; sessionID: string; callID: string; args: Record<string, unknown> },
      output: { title: string; output: string; metadata: unknown }
    ) => {
      // Only handle webfetch failures
      if (input.tool !== 'webfetch') return;
      if (!output.output?.includes('401')) return;

      const url = input.args.url as string | undefined;
      if (!url) return;

      await log('debug', `Checking if ${url} has ACT challenge`);

      // Check if this is an ACT-protected endpoint
      if (!(await hasACTChallenge(url))) {
        await log('debug', 'Not an ACT challenge, skipping');
        return;
      }

      await log('info', `ACT challenge detected, authenticating to ${url}`);

      // Forward original request params
      const method = input.args.method as string | undefined;
      const body = input.args.body as string | undefined;
      const originalHeaders = input.args.headers as Record<string, string> | undefined;

      // Try ACT redemption with original params
      const result = await tryACTRedeem(url, {
        headers: originalHeaders,
        method,
        body,
      });
      if (!result.success) {
        await log('error', `ACT auth failed: ${result.error}`);
        // Provide helpful error message
        output.output = `ACT authentication failed. ${result.error}\n\nTo fix:\n1. Install: cargo install --git https://github.com/thibmeu/act-rs act\n2. Enroll: act login https://act-issuer.research.cloudflare.com`;
        return;
      }

      await log('info', 'ACT authentication successful');
      output.output = result.output ?? 'ACT authentication successful';
      output.title = 'ACT Authenticated Response';
    },

    tool: {
      act_fetch: tool({
        description: `Fetch a URL with ACT (Anonymous Credit Tokens) authentication.
Use this for ACT-protected endpoints that return 401 with WWW-Authenticate: PrivateToken.
Automatically handles credential lookup, token generation, and refund processing.
Requires act CLI with an enrolled credential for the issuer.`,
        args: {
          url: tool.schema.string().describe('The URL to fetch'),
          headers: tool.schema
            .record(tool.schema.string(), tool.schema.string())
            .optional()
            .describe('HTTP headers to send (defaults to Accept: text/markdown)'),
          method: tool.schema
            .enum(['GET', 'POST', 'PUT', 'DELETE', 'PATCH'])
            .optional()
            .describe('HTTP method (defaults to GET)'),
          body: tool.schema.string().optional().describe('Request body'),
          credential: tool.schema
            .string()
            .optional()
            .describe('Credential name (defaults to issuer hostname)'),
        },
        async execute(args) {
          const { url, headers, method, body, credential } = args;

          // Validate URL
          try {
            new URL(url);
          } catch {
            return `Error: Invalid URL: ${url}`;
          }

          await log('info', `ACT fetch: ${url}`);

          // Build command args with headers/method/body support
          const requestHeaders = { Accept: 'text/markdown', ...headers };
          const cmdArgs: string[] = ['redeem', url];

          if (credential) {
            cmdArgs.push('-u', credential);
          }
          for (const [key, value] of Object.entries(requestHeaders)) {
            cmdArgs.push('-H', `${key}: ${value}`);
          }
          if (method) {
            cmdArgs.push('-X', method);
          }
          if (body) {
            cmdArgs.push('-d', body);
          }

          const result = await $`act ${cmdArgs}`.quiet().nothrow();

          if (result.exitCode !== 0) {
            const stderr = result.stderr.toString();

            if (stderr.includes('no credential') || stderr.includes('not found')) {
              return `Error: No ACT credential found for this issuer.\nEnroll first: act login <issuer-url>\n\n${stderr}`;
            }
            if (stderr.includes('insufficient') || stderr.includes('balance')) {
              return `Error: ACT credential has insufficient balance.\nRe-enroll: act login <issuer-url>\n\n${stderr}`;
            }

            return `Error: ACT request failed: ${stderr}`;
          }

          await log('debug', 'ACT request successful');
          return result.stdout.toString();
        },
      }),

      act_balance: tool({
        description: 'Check ACT credential balance and details',
        args: {
          credential: tool.schema.string().optional().describe('Credential name to inspect'),
        },
        async execute(args) {
          const credFlag = args.credential ? `-u ${args.credential}` : '';
          const result = await $`act inspect ${credFlag}`.quiet().nothrow();

          if (result.exitCode !== 0) {
            return `Error: ${result.stderr.toString() || 'No credential found'}`;
          }

          return result.stdout.toString();
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
            return `Error: Enrollment failed: ${result.stderr.toString()}`;
          }

          return `Credential enrolled successfully.\n${result.stdout.toString()}`;
        },
      }),
    },
  };
};

export default ACTPrivacyPassPlugin;
