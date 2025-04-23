
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

function decryptPayload(base64Payload) {
  const privateKeyObject = crypto.createPrivateKey({
    key: process.env.ELIXIR_PRIVATE_KEY,
    format: 'pem',
    type: 'pkcs8',
    passphrase: process.env.ELIXIR_PASSPHRASE,
  });

  try {
    const DECRYPT_CHUNK = 256;
    const encryptedBuf = Buffer.from(base64Payload.trim(), 'base64');
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
    return Buffer.concat(decryptedParts).toString('utf8');
  } catch (err) {
    console.error('❌ RSA Decrypt Error:', err.message);
    throw err;
  }
}

function encryptReturnThis(returnThis) {
  try {
    const data = JSON.stringify(returnThis);
    const plainBuf = Buffer.from(data, 'utf8');
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
    console.error('❌ RSA Encrypt Error:', err.message);
    throw err;
  }
}

export default async function handler(req, res) {
  console.log('🛬 Incoming request at', new Date().toISOString());

  if (req.method !== 'POST') return res.status(405).send('Only POST allowed');
  if (req.headers['content-type'] !== 'text/plain') return res.status(400).send('Invalid Content-Type');

  try {
    const rawBody = await getRawBody(req);
    const base64 = rawBody.toString('utf8');

    let decrypted, payload;
    try {
      decrypted = decryptPayload(base64);
      payload = JSON.parse(decrypted);
    } catch (err) {
      return res.status(400).send('Webhook Error');
    }

    if (payload.eventType !== 'ACTIVATION' || !payload.data?.returnThis) {
      console.log('❌ Invalid activation payload structure');
      return res.status(400).send('Invalid activation payload');
    }

    console.log('✅ VALID RETURNTHIS:', payload.data.returnThis);
    try {
      const encrypted = encryptReturnThis(payload.data.returnThis);
      res.setHeader('Content-Type', 'text/plain');
      return res.status(200).send(encrypted);
    } catch (err) {
      return res.status(400).send('Encryption failed');
    }
  } catch (err) {
    console.error('❌ Webhook Error:', err.message);
    return res.status(400).send('Webhook Error');
  }
}
