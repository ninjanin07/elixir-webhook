
import crypto from 'crypto';
import getRawBody from 'raw-body';

const elixirPubKey = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAozKuWrMROnLq65EDSz8G
O8EV7fUC959KUSlMKtLEkgNNLpU1lZ1DT2I3XJSiHQdJ74X+3MGNdyJhPCRuD0BV
RN+sagaTJpAC0yU8vk8Z6K0Pu+M/b2ExGmsXB59hBqhruz1UzIXEOa7FNY67usSZ
UOQVM1QeTjvv7Traj1UCPCaHmZU30aN+i3HE+FC399vKXpFXlRLYNWUIY336tmMf
XWfB8EJSVtJv027IOwJCFIWdZkLMXG+8S21Wn42yfYGNyPCxG/nJhlJc5i3XUxp1
XwcPFc3ZMfSteWRIBAj33SHIWTYx6cnzNaIq67Xb77M3yk8Dxqt2SpqkPFzxXdvy
swIDAQAB
-----END PUBLIC KEY-----`;

function decryptPayload(base64Payload) {
  try {
    console.log(`🛬 Incoming at ${new Date().toISOString()}`);

    base64Payload = base64Payload.trim().replace(/[^A-Za-z0-9+/=]/g, '');
    if (base64Payload.length % 4 !== 0) throw new Error('Malformed Base64');

    const privateKeyObject = crypto.createPrivateKey({
      key: process.env.ELIXIR_PRIVATE_KEY,
      format: 'pem',
      type: 'pkcs8',
      passphrase: process.env.ELIXIR_PASSPHRASE,
    });

    const DECRYPT_CHUNK = 256;
    const encryptedBuf = Buffer.from(base64Payload, 'base64');
    const decryptedParts = [];
    for (let i = 0; i < encryptedBuf.length; i += DECRYPT_CHUNK) {
      decryptedParts.push(
        crypto.privateDecrypt({
          key: privateKeyObject,
          padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
          oaepHash: 'sha1',
        }, encryptedBuf.slice(i, i + DECRYPT_CHUNK))
      );
    }

    const plaintext = Buffer.concat(decryptedParts).toString('utf8');
    return JSON.parse(plaintext);
  } catch (err) {
    console.error('Webhook Error:', err);
    return null;
  }
}

function encryptReturnThis(returnThisObj) {
  try {
    const plainBuf = Buffer.from(JSON.stringify(returnThisObj), 'utf8');
    const ENCRYPT_CHUNK = 210;
    const encryptedSlices = [];
    for (let i = 0; i < plainBuf.length; i += ENCRYPT_CHUNK) {
      encryptedSlices.push(
        crypto.publicEncrypt({
          key: elixirPubKey,
          padding: crypto.constants.RSA_PKCS1_PADDING,
        }, plainBuf.slice(i, i + ENCRYPT_CHUNK))
      );
    }
    return Buffer.concat(encryptedSlices).toString('base64');
  } catch (err) {
    console.error('Encryption Error:', err);
    return null;
  }
}

export default async function handler(req, res) {
  if (req.method !== 'POST') return res.status(405).send('Only POST allowed');
  try {
    const rawBody = await getRawBody(req);
    const base64 = rawBody.toString('utf8');
    const parsed = decryptPayload(base64);
    if (parsed?.eventType === "ACTIVATION" && parsed?.data?.returnThis) {
      console.log("✅ VALID RETURNTHIS:", parsed.data.returnThis);
      const encrypted = encryptReturnThis(parsed.data.returnThis);
      if (encrypted) {
        res.setHeader('Content-Type', 'text/plain');
        return res.status(200).send(encrypted);
      }
    }
    return res.status(400).send('Invalid payload or missing returnThis');
  } catch (err) {
    console.error('Handler Error:', err);
    return res.status(500).send('Internal Server Error');
  }
}
