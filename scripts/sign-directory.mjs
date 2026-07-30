import { readFile } from 'node:fs/promises'
import { delimiter } from 'node:path'

const authority = process.env.WBA_DIRECTORY_AUTHORITY ?? 'agents.tempo.xyz'
const created = toTimestamp('WBA_DIRECTORY_CREATED')
const expires = toTimestamp('WBA_DIRECTORY_EXPIRES')
const privateKeyPaths = (
  process.env.WBA_PRIVATE_JWK_PATHS ?? process.env.WBA_PRIVATE_JWK_PATH ?? ''
)
  .split(delimiter)
  .filter(Boolean)

if (!privateKeyPaths.length)
  throw new Error('WBA_PRIVATE_JWK_PATH or WBA_PRIVATE_JWK_PATHS is required.')
if (expires <= created) throw new Error('WBA_DIRECTORY_EXPIRES must be after creation.')

const directoryUrl = new URL(
  '../public/.well-known/http-message-signatures-directory',
  import.meta.url,
)
const body = await readFile(directoryUrl)
const directory = JSON.parse(body)
if (!Array.isArray(directory.keys) || !directory.keys.length)
  throw new Error('The directory must contain at least one public key.')

const privateKeys = new Map()
for (const path of privateKeyPaths) {
  const keyDocument = JSON.parse(await readFile(path, 'utf8'))
  const privateKey = keyDocument.privateKeyJwk ?? keyDocument
  const keyId = keyDocument.keyId ?? privateKey.kid ?? (await jwkThumbprint(privateKey))
  if (privateKeys.has(keyId)) throw new Error(`Duplicate private key ID "${keyId}".`)
  privateKeys.set(keyId, privateKey)
}

const digest = Buffer.from(await crypto.subtle.digest('SHA-256', body)).toString('base64')
const contentDigest = `sha-256=:${digest}:`
const inputs = []
const signatures = []
for (const [index, publicKey] of directory.keys.entries()) {
  const privateKey = privateKeys.get(publicKey.kid)
  if (!privateKey || privateKey.x !== publicKey.x)
    throw new Error(`No matching private JWK was provided for "${publicKey.kid}".`)
  const key = await crypto.subtle.importKey(
    'jwk',
    privateKey,
    { name: 'Ed25519' },
    false,
    ['sign'],
  )
  const label = directory.keys.length === 1 ? 'directory' : `directory${index}`
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
  inputs.push(`${label}=${parameters}`)
  signatures.push(`${label}=:${signature}:`)
}

console.log(
  JSON.stringify(
    {
      'Content-Digest': contentDigest,
      'Signature-Input': inputs.join(', '),
      Signature: signatures.join(', '),
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

async function jwkThumbprint(key) {
  if (key.kty !== 'OKP' || key.crv !== 'Ed25519' || !key.x)
    throw new Error('Private keys must be Ed25519 JWKs.')
  const canonical = JSON.stringify({ crv: key.crv, kty: key.kty, x: key.x })
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(canonical))
  return Buffer.from(digest).toString('base64url')
}
