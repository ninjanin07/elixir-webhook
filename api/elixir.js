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

function respondWithEncrypted(returnThisObj) {
  const json = JSON.stringify(returnThisObj);
  const buf = Buffer.from(json, 'utf8');
  const chunks = [];
  for (let i = 0; i < buf.length; i += 210) {
    chunks.push(
      crypto.publicEncrypt({
        key: elixirPubKey,
        padding: crypto.constants.RSA_PKCS1_PADDING
      }, buf.slice(i, i + 210))
    );
  }
  return Buffer.concat(chunks).toString('base64');
}

function decryptPayload(buffer, privateKeyObject) {
  const decryptedParts = [];
  for (let i = 0; i < buffer.length; i += 256) {
    decryptedParts.push(
      crypto.privateDecrypt({
        key: privateKeyObject,
        padding: crypto.constants.RSA_PKCS1_PADDING
      }, buffer.slice(i, i + 256))
    );
  }

  const decrypted = Buffer.concat(decryptedParts);
  const key = decrypted.slice(0, 32);
  const iv = decrypted.slice(32, 48);
  const ciphertext = decrypted.slice(48);

  const decipher = crypto.createDecipheriv('aes-256-ctr', key, iv);
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
}

export default async function handler(req, res) {
  if (req.method !== 'POST') return res.status(405).send('Only POST allowed');

  try {
    const rawBody = await getRawBody(req);
    const base64Payload = rawBody.toString('utf8').trim();

    const privateKeyObject = crypto.createPrivateKey({
      key: process.env.ELIXIR_PRIVATE_KEY,
      format: 'pem',
      type: 'pkcs8',
      passphrase: process.env.ELIXIR_PASSPHRASE,
    });

    const encryptedBuffer = Buffer.from(base64Payload, 'base64');
    const decrypted = decryptPayload(encryptedBuffer, privateKeyObject);

    const parsed = JSON.parse(decrypted.toString('utf8'));
    if (!parsed?.data?.returnThis) {
      return res.status(400).send('Invalid payload: no returnThis');
    }

    const encryptedReturn = respondWithEncrypted(parsed.data.returnThis);
    res.setHeader('Content-Type', 'text/plain');
    return res.status(200).send(encryptedReturn);
  } catch (err) {
    console.error('Webhook Error:', err);
    return res.status(500).send('Internal Server Error');
  }
}
