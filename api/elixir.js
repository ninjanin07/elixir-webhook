import crypto from 'crypto';
import getRawBody from 'raw-body';

const elixirPubKey = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAozKuWrMROnLq65EDSz8G
O8EV7fUC959KUSlMKtLEkgNNLpU1lZ1DT2I3XSjHQdJ74X+3MGNdyJhPCRuD0BVR
N+sagaTJpAC0yU8v8ZK60Pu+M/b2ExGmsXB59BhqruzlUzIXE0a7FNY67usSZUOQ
VM1QeJvT7rajJUCPCAhmZ3U0Ah+I3HE+FC399vKXpFXLYRNMVU1Y336tmtMfXwFB
8EJSvtJvO27IOwJCFfWdZkLMXG+8S2IWn42yfYNGyPCxG/nJhUc5i3XUxp1XwcPF
c3ZMFsteWRlBAj33SHWTYx6cnzNaIq67Xb7M73yk8D2xqt2SpqkPFzxXdvyswIDA
QAB
-----END PUBLIC KEY-----`;

function processWebhook(base64Payload) {
  try {
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
          padding: crypto.constants.RSA_PKCS1_PADDING
        }, encryptedBuf.slice(i, i + DECRYPT_CHUNK))
      );
    }

    const decryptedBuffer = Buffer.concat(decryptedParts);
    console.log('🔍 Raw decrypted buffer (hex):', decryptedBuffer.toString('hex'));
    console.log('📦 Decrypted buffer (base64):', decryptedBuffer.toString('base64'));

    // Instead of trying to parse it, just return the base64 string for now
    return decryptedBuffer.toString('base64');
  } catch (err) {
    console.error('Webhook Error:', err);
    return `ERROR: ${err.message}`;
  }
}

export default async function handler(req, res) {
  if (req.method !== 'POST') return res.status(405).send('Only POST allowed');

  try {
    const rawBody = await getRawBody(req);
    const base64 = rawBody.toString('utf8');
    const reply = processWebhook(base64);

    if (reply.startsWith('ERROR:')) {
      return res.status(400).send(reply);
    }

    res.setHeader('Content-Type', 'text/plain');
    return res.status(200).send(reply);
  } catch (err) {
    console.error('Handler Error:', err);
    return res.status(500).send('Internal Server Error');
  }
}
