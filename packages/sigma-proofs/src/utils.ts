/**
 * Internal utilities.
 */

/**
 * Convert ASCII string to Uint8Array.
 *
 * Only supports ASCII characters (0-127). This avoids TextEncoder
 * dependency for better cross-runtime compatibility.
 *
 * @param s - ASCII string
 * @returns Byte array
 * @throws If string contains non-ASCII characters
 */
export function asciiToBytes(s: string): Uint8Array {
  const bytes = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) {
    const code = s.charCodeAt(i);
    if (code > 127) {
      throw new Error(`Non-ASCII character at position ${i}: ${s[i]}`);
    }
    bytes[i] = code;
  }
  return bytes;
}
