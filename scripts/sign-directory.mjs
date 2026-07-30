import { readFile } from 'node:fs/promises'

const authority = process.env.WBA_DIRECTORY_AUTHORITY ?? 'agents.tempo.xyz'
const created = toTimestamp('WBA_DIRECTORY_CREATED')
const expires = toTimestamp('WBA_DIRECTORY_EXPIRES')
const privateKeyPath = process.env.WBA_PRIVATE_JWK_PATH

if (!privateKeyPath) throw new Error('WBA_PRIVATE_JWK_PATH is required.')
if (expires <= created) throw new Error('WBA_DIRECTORY_EXPIRES must be after creation.')

const directoryUrl = new URL(
  '../public/.well-known/http-message-signatures-directory',
  import.meta.url,
)
const body = await readFile(directoryUrl)
const directory = JSON.parse(body)
if (!Array.isArray(directory.keys) || directory.keys.length !== 1)
  throw new Error('This signer expects exactly one directory key.')
const [publicKey] = directory.keys

const keyDocument = JSON.parse(await readFile(privateKeyPath, 'utf8'))
const privateKey = keyDocument.privateKeyJwk ?? keyDocument
const keyId = keyDocument.keyId ?? privateKey.kid
if (keyId !== publicKey.kid || privateKey.x !== publicKey.x)
  throw new Error('The private JWK does not match the published directory key.')

const key = await crypto.subtle.importKey(
  'jwk',
  privateKey,
  { name: 'Ed25519' },
  false,
  ['sign'],
)
const digest = Buffer.from(await crypto.subtle.digest('SHA-256', body)).toString('base64')
const contentDigest = `sha-256=:${digest}:`
const parameters =
  `("@authority";req "content-digest");created=${created};expires=${expires}` +
  `;keyid="${publicKey.kid}";alg="ed25519";tag="http-message-signatures-directory"`
const signatureBase = [
  `"@authority";req: ${authority}`,
  `"content-digest": ${contentDigest}`,
  `"@signature-params": ${parameters}`,
].join('\n')
const signature = Buffer.from(
  await crypto.subtle.sign('Ed25519', key, new TextEncoder().encode(signatureBase)),
).toString('base64')

console.log(
  JSON.stringify(
    {
      'Content-Digest': contentDigest,
      'Signature-Input': `directory=${parameters}`,
      Signature: `directory=:${signature}:`,
    },
    null,
    2,
  ),
)

function toTimestamp(name) {
  const value = Number(process.env[name])
  if (!Number.isSafeInteger(value) || value <= 0)
    throw new Error(`${name} must be a positive integer Unix timestamp.`)
  return value
}
