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

function attemptAESDecryption(buffer) {
  try {
    const key = buffer.slice(0, 32);
    const iv = buffer.slice(32, 48);
    const encrypted = buffer.slice(48);

    const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
    const decrypted = Buffer.concat([decipher.update(encrypted), decipher.final()]);

    console.log('🧪 AES decrypted (hex):', decrypted.toString('hex'));
    console.log('🧾 AES decrypted (utf8):', decrypted.toString('utf8'));

    try {
      const json = JSON.parse(decrypted.toString('utf8'));
      console.log('✅ Parsed JSON:', json);
    } catch (e) {
      console.log('❌ Failed to parse JSON from AES decrypted output.');
    }
  } catch (err) {
    console.log('❌ AES decryption error:', err.message);
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

    console.log('🔍 Decrypted buffer (hex):', decryptedBuffer.toString('hex'));
    console.log('📦 Decrypted buffer (base64):', decryptedBuffer.toString('base64'));
    console.log('📏 Length:', decryptedBuffer.length);

    console.log('🔑 AES key (32b):', decryptedBuffer.slice(0, 32).toString('hex'));
    console.log('🧊 AES IV (16b):', decryptedBuffer.slice(32, 48).toString('hex'));
    console.log('🔐 Ciphertext:', decryptedBuffer.slice(48).toString('hex'));

    attemptAESDecryption(decryptedBuffer);

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
