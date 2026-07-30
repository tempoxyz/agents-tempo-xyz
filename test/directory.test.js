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
  const config = await readJson(new URL('../vercel.json', import.meta.url))

  assert.equal(config.rewrites, undefined)
  assert.deepEqual(config.headers, [
    {
      source: '/.well-known/http-message-signatures-directory',
      headers: [
        {
          key: 'Content-Type',
          value: 'application/http-message-signatures-directory+json',
        },
        {
          key: 'Cache-Control',
          value: 'public, max-age=300, must-revalidate',
        },
        {
          key: 'CDN-Cache-Control',
          value: 'public, max-age=300, must-revalidate',
        },
        {
          key: 'Vercel-CDN-Cache-Control',
          value: 'public, max-age=300, must-revalidate',
        },
        { key: 'Access-Control-Allow-Origin', value: '*' },
        { key: 'X-Content-Type-Options', value: 'nosniff' },
      ],
    },
  ])
})
