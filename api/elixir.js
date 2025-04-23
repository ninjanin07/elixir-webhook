import crypto from 'crypto';
import getRawBody from 'raw-body';
import zlib from 'zlib';

const elixirPubKey = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAozKuWrMROnLq65EDSz8G
O8EV7fUC959KUSlMKtLEkgNNLpU1lZ1DT2I3XSjHQdJ74X+3MGNdyJhPCRuD0BVR
N+sagaTJpAC0yU8v8ZK60Pu+M/b2ExGmsXB59BhqruzlUzIXE0a7FNY67usSZUOQ
VM1QeJvT7rajJUCPCAhmZ3U0Ah+I3HE+FC399vKXpFXLYRNMVU1Y336tmtMfXwFB
8EJSvtJvO27IOwJCFfWdZkLMXG+8S2IWn42yfYNGyPCxG/nJhUc5i3XUxp1XwcPF
c3ZMFsteWRlBAj33SHWTYx6cnzNaIq67Xb7M73yk8D2xqt2SpqkPFzxXdvyswIDA
QAB
-----END PUBLIC KEY-----`;

function decodeAESCTR(buffer) {
  const key = buffer.slice(0, 32);
  const iv = buffer.slice(32, 48);
  const ciphertext = buffer.slice(48);

  try {
    const decipher = crypto.createDecipheriv('aes-256-ctr', key, iv);
    const decrypted = Buffer.concat([decipher.update(ciphertext), decipher.final()]);

    console.log('✅ AES-256-CTR decrypted buffer (hex):', decrypted.toString('hex'));
    console.log('🔎 First 100 bytes (utf8):', decrypted.toString('utf8').slice(0, 100));

    // Try base64 decode then JSON
    try {
      const b64Decoded = Buffer.from(decrypted.toString('utf8'), 'base64');
      console.log('📥 Base64 decoded buffer (hex):', b64Decoded.toString('hex'));
      const parsed = JSON.parse(b64Decoded.toString('utf8'));
      console.log('✅ Base64 → JSON parsed result:', parsed);
    } catch (err) {
      console.log('❌ Base64+JSON decode failed:', err.message);
    }

    // Try gunzip then JSON
    try {
      const gunzipped = zlib.gunzipSync(decrypted);
      console.log('📦 Gzipped → Buffer (hex):', gunzipped.toString('hex'));
      const parsed = JSON.parse(gunzipped.toString('utf8'));
      console.log('✅ Gunzipped → JSON parsed result:', parsed);
    } catch (err) {
      console.log('❌ Gunzip+JSON decode failed:', err.message);
    }

  } catch (err) {
    console.log('❌ AES-256-CTR decryption failed:', err.message);
  }
}

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

    const encryptedBuf = Buffer.from(base64Payload, 'base64');
    const decryptedParts = [];
    for (let i = 0; i < encryptedBuf.length; i += 256) {
      decryptedParts.push(
        crypto.privateDecrypt({
          key: privateKeyObject,
          padding: crypto.constants.RSA_PKCS1_PADDING
        }, encryptedBuf.slice(i, i + 256))
      );
    }

    const decryptedBuffer = Buffer.concat(decryptedParts);
    console.log('🔓 RSA decrypted buffer (hex):', decryptedBuffer.toString('hex'));
    console.log('📏 Length:', decryptedBuffer.length);

    decodeAESCTR(decryptedBuffer);

    return 'Decoding attempts complete. Check logs.';
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
    res.setHeader('Content-Type', 'text/plain');
    return res.status(200).send(reply);
  } catch (err) {
    console.error('Handler Error:', err);
    return res.status(500).send('Internal Server Error');
  }
}
