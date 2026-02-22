import { createHmac } from 'crypto';

/**
 * Generates a TOTP (Time-based One-Time Password).
 *
 * @param secret - The secret key used to generate the TOTP.
 * @param time - The current time in seconds (default is the current time).
 * @param digitLength - The number of digits in the TOTP (default is 6).
 * @returns The generated TOTP.
 */
export function generateTOTP(secret: string, time: number = Math.floor(Date.now() / 1000 / 30), digitLength: number = 6): string {
    const timeBuffer = Buffer.alloc(8);
    timeBuffer.writeUInt32BE(time, 4);

    const hmac = createHmac('sha1', Buffer.from(secret, 'base64'));
    hmac.update(timeBuffer);
    const hmacResult = hmac.digest();

    const offset = hmacResult[hmacResult.length - 1] & 0xf;
    const code = (hmacResult.readUInt32BE(offset) & 0x7fffffff) % (10 ** digitLength);

    return code.toString().padStart(digitLength, '0');
}