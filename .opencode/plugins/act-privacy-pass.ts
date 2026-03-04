/**
 * ACT (Anonymous Credit Tokens) Privacy Pass Plugin for OpenCode
 *
 * Automatically intercepts 401 responses with ACT challenges and retries
 * with valid tokens from act-cli credential store.
 *
 * Requirements:
 * - act-cli installed and in PATH (cargo install --path act-cli from act-rs)
 * - Credential pre-enrolled via: act request <issuer-url>
 *
 * Credential naming: Uses issuer hostname from challenge (e.g., "act-issuer.research.cloudflare.com")
 *
 * @see https://datatracker.ietf.org/doc/draft-schlesinger-privacypass-act/
 */

import type { Plugin } from '@opencode-ai/plugin';

// ACT token type per draft-schlesinger-privacypass-act
const ACT_TOKEN_TYPE = 0xe5ad;

interface Challenge {
  origin: string;
  issuerHostname: string;
  header: string;
}

interface WebFetchArgs {
  url: string;
  format?: string;
  timeout?: number;
}

interface BashArgs {
  command: string;
  workdir?: string;
  timeout?: number;
}

interface ToolExecuteInput {
  tool: string;
  args: WebFetchArgs | BashArgs | Record<string, unknown>;
}

interface ToolExecuteOutput {
  result?: string;
  error?: string;
  // Plugin API may expose headers differently - this is our best guess
  metadata?: {
    status?: number;
    headers?: Record<string, string>;
  };
}

export const ACTPrivacyPassPlugin: Plugin = async ({ $, client }) => {
  const log = async (level: 'debug' | 'info' | 'warn' | 'error', message: string) => {
    await client.app.log({
      body: { service: 'act-privacy-pass', level, message },
    });
  };

  // Check act-cli availability at startup
  const actCheck = await $`which act`.quiet().nothrow();
  if (actCheck.exitCode !== 0) {
    await log('warn', 'act-cli not found in PATH, ACT challenge interception disabled');
    await log('info', 'Install: cargo install --path act-cli (from act-rs repo)');
    return {};
  }

  await log('info', 'ACT Privacy Pass plugin loaded');

  return {
    'tool.execute.after': async (input: ToolExecuteInput, output: ToolExecuteOutput) => {
      // Only intercept webfetch - bash command reconstruction is too fragile
      if (input.tool !== 'webfetch') {
        // For bash with curl/wget, log helpful message but don't attempt retry
        if (input.tool === 'bash' && isCurlOrWget(input.args as BashArgs)) {
          const challenge = extractChallengeFromText(output.result ?? output.error ?? '');
          if (challenge) {
            await log(
              'warn',
              `ACT challenge detected in bash output but cannot auto-retry.\n` +
                `Run manually: act token "${challenge.origin}" | xargs -I{} curl -H "Authorization: {}" ...`
            );
          }
        }
        return;
      }

      // Check for 401 with ACT challenge
      const challenge = extractACTChallenge(input.args as WebFetchArgs, output);
      if (!challenge) return;

      await log('info', `ACT challenge detected for ${challenge.issuerHostname}`);

      // Cost defaults to 1.
      // Future enhancement: parse cost from challenge attributes or add to plugin config
      const cost = 1;

      // Generate token via act-cli
      // Credential is selected by issuer hostname (set via `act request <issuer> --as <name>`)
      // Using -u to explicitly select credential by issuer hostname
      const tokenResult =
        await $`act token ${sanitizeUrl(challenge.origin)} -a ${cost} -u ${sanitizeHostname(challenge.issuerHostname)}`
          .quiet()
          .nothrow();

      if (tokenResult.exitCode !== 0) {
        const stderr = tokenResult.stderr;
        if (stderr.includes('no credential') || stderr.includes('not found')) {
          await log(
            'error',
            `No ACT credential for ${challenge.issuerHostname}.\n` +
              `Enroll first: act request https://${challenge.issuerHostname}/.well-known/private-token-issuer-directory`
          );
        } else if (stderr.includes('insufficient balance')) {
          await log(
            'error',
            `ACT credential exhausted for ${challenge.issuerHostname}.\n` +
              `Re-enroll: act request <issuer-url> --force`
          );
        } else if (stderr.includes('pending')) {
          await log(
            'error',
            `ACT credential has pending spend.\n` +
              `Complete: act refund -u ${challenge.issuerHostname}\n` +
              `Or abort: act refund -u ${challenge.issuerHostname} --abort`
          );
        } else {
          await log('error', `act token failed: ${stderr}`);
        }
        return; // Let original 401 propagate
      }

      const authHeader = tokenResult.stdout.trim();
      if (!authHeader.startsWith('PrivateToken token=')) {
        await log('error', `Unexpected act token output: ${authHeader}`);
        return;
      }

      await log('debug', 'Token generated, retrying request');

      // Retry webfetch with Authorization header
      const args = input.args as WebFetchArgs;
      const retryResult =
        await $`curl -s -D - -H "Authorization: ${authHeader}" "${sanitizeUrl(args.url)}"`
          .quiet()
          .nothrow();

      if (retryResult.exitCode !== 0) {
        await log('error', `Retry request failed: ${retryResult.stderr}`);
        return;
      }

      // Parse response to extract headers and body
      const { headers, body } = parseHttpResponse(retryResult.stdout);

      // Process refund if present
      const refundHeader = headers['privacypass-reverse'] ?? headers['PrivacyPass-Reverse'];
      if (refundHeader) {
        const sanitizedRefund = sanitizeBase64(refundHeader);
        if (sanitizedRefund) {
          const refundResult = await $`act refund --header ${sanitizedRefund}`.quiet().nothrow();
          if (refundResult.exitCode !== 0) {
            await log('warn', `Refund processing failed: ${refundResult.stderr}`);
            await log('warn', 'Credential balance may be incorrect. Check: act inspect');
          } else {
            await log('debug', 'Refund processed successfully');
          }
        } else {
          await log('warn', 'Invalid refund header format, skipping');
        }
      } else {
        await log('debug', 'No refund header in response');
      }

      // Update output with successful response
      output.result = body;
      output.error = undefined;
    },
  };
};

/**
 * Check if bash command appears to be curl/wget
 */
function isCurlOrWget(args: BashArgs): boolean {
  return /\b(curl|wget|httpie?|http)\b/.test(args.command);
}

/**
 * Extract ACT challenge from webfetch output
 */
function extractACTChallenge(args: WebFetchArgs, output: ToolExecuteOutput): Challenge | null {
  // Check for 401 status or challenge in error/result
  const text = output.error ?? output.result ?? '';

  // Look for WWW-Authenticate header in output
  // Format: WWW-Authenticate: PrivateToken challenge="base64", token-key="base64"
  const wwwAuthMatch = text.match(/WWW-Authenticate:\s*([^\r\n]+)/i);
  if (!wwwAuthMatch) return null;

  const wwwAuth = wwwAuthMatch[1];
  if (!wwwAuth.includes('PrivateToken')) return null;

  // Parse challenge to verify it's ACT (token_type = 0xe5ad)
  const challengeMatch = wwwAuth.match(/challenge="([^"]+)"/);
  if (!challengeMatch) return null;

  // Decode base64 challenge and check token type
  try {
    const challengeBytes = base64Decode(challengeMatch[1]);
    if (challengeBytes.length < 2) return null;

    // Token type is first 2 bytes, big-endian
    const tokenType = (challengeBytes[0] << 8) | challengeBytes[1];
    if (tokenType !== ACT_TOKEN_TYPE) return null;
  } catch {
    return null;
  }

  // Extract issuer hostname from challenge (issuer_name field)
  // For now, use the origin hostname as fallback
  const originUrl = new URL(args.url);

  return {
    origin: args.url,
    issuerHostname: originUrl.hostname,
    header: wwwAuth,
  };
}

/**
 * Extract challenge from arbitrary text (for bash output)
 */
function extractChallengeFromText(text: string): Challenge | null {
  const wwwAuthMatch = text.match(/WWW-Authenticate:\s*([^\r\n]+)/i);
  if (!wwwAuthMatch) return null;

  const urlMatch = text.match(/https?:\/\/[^\s"'<>]+/);
  const origin = urlMatch?.[0] ?? 'unknown';

  try {
    const hostname = new URL(origin).hostname;
    return { origin, issuerHostname: hostname, header: wwwAuthMatch[1] };
  } catch {
    return null;
  }
}

/**
 * Parse HTTP response with headers and body
 */
function parseHttpResponse(response: string): { headers: Record<string, string>; body: string } {
  const headers: Record<string, string> = {};

  // Split on double newline (CRLF or LF)
  const parts = response.split(/\r?\n\r?\n/);
  const headerSection = parts[0] ?? '';
  const body = parts.slice(1).join('\n\n');

  // Parse headers
  for (const line of headerSection.split(/\r?\n/)) {
    const colonIndex = line.indexOf(':');
    if (colonIndex > 0) {
      const name = line.substring(0, colonIndex).trim();
      const value = line.substring(colonIndex + 1).trim();
      headers[name] = value;
      // Also store lowercase for case-insensitive lookup
      headers[name.toLowerCase()] = value;
    }
  }

  return { headers, body };
}

// --- Input Sanitization (Critical for shell injection prevention) ---

/**
 * Sanitize URL for shell use - only allow valid URL characters
 */
function sanitizeUrl(url: string): string {
  try {
    const parsed = new URL(url);
    // Reconstruct URL to ensure it's valid
    return parsed.toString();
  } catch {
    throw new Error(`Invalid URL: ${url}`);
  }
}

/**
 * Sanitize hostname - only alphanumeric, dots, hyphens
 */
function sanitizeHostname(hostname: string): string {
  if (!/^[a-zA-Z0-9][a-zA-Z0-9.-]*[a-zA-Z0-9]$/.test(hostname)) {
    throw new Error(`Invalid hostname: ${hostname}`);
  }
  return hostname;
}

/**
 * Sanitize base64 string - only base64 characters
 */
function sanitizeBase64(value: string): string | null {
  // Allow standard and URL-safe base64
  if (!/^[A-Za-z0-9+/=_-]+$/.test(value)) {
    return null;
  }
  return value;
}

/**
 * Decode base64 (standard or URL-safe)
 */
function base64Decode(input: string): Uint8Array {
  // Convert URL-safe to standard
  const standard = input.replace(/-/g, '+').replace(/_/g, '/');
  const binary = atob(standard);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}
