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

function tryAES(mode, key, iv, ciphertext, options = {}) {
  try {
    const decipher = crypto.createDecipheriv(mode, key, iv, options);
    let decrypted = decipher.update(ciphertext);
    decrypted = Buffer.concat([decrypted, decipher.final()]);

    console.log(`✅ [${mode}] decrypted (hex):`, decrypted.toString('hex'));
    console.log(`🧾 [${mode}] decrypted (utf8):`, decrypted.toString('utf8'));
    try {
      const parsed = JSON.parse(decrypted.toString('utf8'));
      console.log(`📦 [${mode}] parsed JSON:`, parsed);
    } catch {
      console.log(`ℹ️ [${mode}] not valid JSON.`);
    }
  } catch (err) {
    console.log(`❌ [${mode}] error:`, err.message);
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

    const key = decryptedBuffer.slice(0, 32);
    const iv = decryptedBuffer.slice(32, 48);
    const ciphertext = decryptedBuffer.slice(48);

    tryAES('aes-256-cbc', key, iv, ciphertext);
    tryAES('aes-256-cbc', key, iv, ciphertext, { autoPadding: false });
    tryAES('aes-256-ctr', key, iv, ciphertext);
    tryAES('aes-256-gcm', key, iv, ciphertext);

    return 'Decryption attempts completed (check logs).';
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
