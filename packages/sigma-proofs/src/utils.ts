/**
 * Internal utilities.
 */

/**
 * Concatenate multiple Uint8Arrays.
 */
export function concat(...arrays: Uint8Array[]): Uint8Array {
  const totalLength = arrays.reduce((sum, arr) => sum + arr.length, 0);
  const result = new Uint8Array(totalLength);
  let offset = 0;
  for (const arr of arrays) {
    result.set(arr, offset);
    offset += arr.length;
  }
  return result;
}

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
