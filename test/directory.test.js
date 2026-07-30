import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import { test } from 'node:test'

const directoryPath = new URL(
  '../public/.well-known/http-message-signatures-directory',
  import.meta.url,
)

async function readJson(url) {
  return JSON.parse(await readFile(url, 'utf8'))
}

async function readResponseHeaders() {
  const config = await readJson(new URL('../vercel.json', import.meta.url))
  assert.equal(config.rewrites, undefined)
  assert.equal(config.headers.length, 1)
  assert.equal(config.headers[0].source, '/.well-known/http-message-signatures-directory')
  return new Map(config.headers[0].headers.map(({ key, value }) => [key.toLowerCase(), value]))
}

test('publishes only a public Ed25519 verification key', async () => {
  const directory = await readJson(directoryPath)

  assert.equal(directory.keys.length, 1)
  const [key] = directory.keys
  assert.deepEqual(Object.keys(key).sort(), ['crv', 'kid', 'kty', 'use', 'x'])
  assert.equal(key.crv, 'Ed25519')
  assert.equal(key.kty, 'OKP')
  assert.equal(key.use, 'sig')
  assert.equal(Buffer.from(key.x, 'base64url').byteLength, 32)
  assert.equal(key.d, undefined)
})

test('uses the RFC 7638 JWK thumbprint as the key identifier', async () => {
  const directory = await readJson(directoryPath)
  const [key] = directory.keys
  const canonical = JSON.stringify({ crv: key.crv, kty: key.kty, x: key.x })
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(canonical))

  assert.equal(Buffer.from(digest).toString('base64url'), key.kid)
})

test('serves the well-known file directly with bounded caching and CORS', async () => {
  const headers = await readResponseHeaders()

  assert.equal(
    headers.get('content-type'),
    'application/http-message-signatures-directory+json',
  )
  assert.equal(headers.get('cache-control'), 'public, max-age=300, must-revalidate')
  assert.equal(headers.get('cdn-cache-control'), 'public, max-age=300, must-revalidate')
  assert.equal(headers.get('vercel-cdn-cache-control'), 'public, max-age=300, must-revalidate')
  assert.equal(headers.get('access-control-allow-origin'), '*')
  assert.equal(headers.get('x-content-type-options'), 'nosniff')
})

test('authenticates the static response with the advertised key', async () => {
  const body = await readFile(directoryPath)
  const directory = JSON.parse(body)
  const [publicKey] = directory.keys
  const headers = await readResponseHeaders()
  const contentDigest = headers.get('content-digest')
  const signatureInput = headers.get('signature-input')
  const signatureHeader = headers.get('signature')

  const digest = Buffer.from(await crypto.subtle.digest('SHA-256', body)).toString('base64')
  assert.equal(contentDigest, `sha-256=:${digest}:`)
  assert.ok(signatureInput?.startsWith('directory='))
  assert.ok(signatureHeader?.startsWith('directory=:') && signatureHeader.endsWith(':'))

  const parameters = signatureInput.slice('directory='.length)
  assert.match(parameters, /"@authority";req/)
  assert.match(parameters, /"content-digest"/)
  assert.match(parameters, new RegExp(`;keyid="${publicKey.kid}"`))
  assert.match(parameters, /;alg="ed25519"/)
  assert.match(parameters, /;tag="http-message-signatures-directory"/)

  const signatureBase = [
    '"@authority";req: agents.tempo.xyz',
    `"content-digest": ${contentDigest}`,
    `"@signature-params": ${parameters}`,
  ].join('\n')
  const signature = Buffer.from(signatureHeader.slice('directory=:'.length, -1), 'base64')
  const key = await crypto.subtle.importKey(
    'jwk',
    publicKey,
    { name: 'Ed25519' },
    false,
    ['verify'],
  )

  assert.equal(
    await crypto.subtle.verify(
      'Ed25519',
      key,
      signature,
      new TextEncoder().encode(signatureBase),
    ),
    true,
  )
})
