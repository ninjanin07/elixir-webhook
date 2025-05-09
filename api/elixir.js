
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
  const privateKeyObject = crypto.createPrivateKey({
    key: process.env.ELIXIR_PRIVATE_KEY,
    format: 'pem',
    type: 'pkcs8',
    passphrase: process.env.ELIXIR_PASSPHRASE,
  });

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
}

function encryptReturnThis(returnThis) {
  const buffer = Buffer.from(JSON.stringify(returnThis), 'utf8');
  return crypto.publicEncrypt({
    key: elixirPubKey,
    padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
    oaepHash: 'sha1'
  }, buffer).toString('base64');
}

export default async function handler(req, res) {
  console.log('🛬 Incoming request at', new Date().toISOString());
  if (req.method !== 'POST') return res.status(405).send('Only POST allowed');
  if (req.headers['content-type'] !== 'text/plain') return res.status(400).send('Invalid Content-Type');

  try {
    const rawBody = await getRawBody(req);
    const base64 = rawBody.toString('utf8');
    const decrypted = decryptPayload(base64);
    const payload = JSON.parse(decrypted);

    console.log(`📨 Received event: ${payload.eventType}`);

    if (payload.eventType === 'ACTIVATION') {
      if (!payload.data?.returnThis) {
        console.log('❌ Missing returnThis');
        return res.status(400).send('Missing returnThis');
      }

      const returnThis = payload.data.returnThis;
      console.log('✅ VALID RETURNTHIS:', returnThis);

      // Forward returnThis to n8n
      await fetch('https://nzskinhealth.app.n8n.cloud/webhook/elixir-activation', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(returnThis)
      });

      const encrypted = encryptReturnThis(returnThis);
      res.setHeader('Content-Type', 'text/plain');
      return res.status(200).send(encrypted);
    }

    // For other events (e.g., appointments), forward entire payload
    console.log('🔁 Forwarding event to n8n webhook');
    await fetch('https://nzskinhealth.app.n8n.cloud/webhook/elixir-activation', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });

    return res.status(200).send('OK');
  } catch (err) {
    console.error('❌ Webhook Error:', err);
    return res.status(400).send('Webhook Error');
  }
}
