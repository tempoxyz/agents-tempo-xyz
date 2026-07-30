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

test('publishes only public Ed25519 verification keys', async () => {
  const directory = await readJson(directoryPath)

  assert.ok(directory.keys.length > 0)
  assert.equal(new Set(directory.keys.map((key) => key.kid)).size, directory.keys.length)
  for (const key of directory.keys) {
    assert.deepEqual(Object.keys(key).sort(), ['crv', 'kid', 'kty', 'use', 'x'])
    assert.equal(key.crv, 'Ed25519')
    assert.equal(key.kty, 'OKP')
    assert.equal(key.use, 'sig')
    assert.equal(Buffer.from(key.x, 'base64url').byteLength, 32)
    assert.equal(key.d, undefined)
  }
})

test('uses RFC 7638 JWK thumbprints as key identifiers', async () => {
  const directory = await readJson(directoryPath)

  for (const key of directory.keys) {
    const canonical = JSON.stringify({ crv: key.crv, kty: key.kty, x: key.x })
    const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(canonical))
    assert.equal(Buffer.from(digest).toString('base64url'), key.kid)
  }
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
  const headers = await readResponseHeaders()
  const contentDigest = headers.get('content-digest')
  const signatureInput = headers.get('signature-input')
  const signatureHeader = headers.get('signature')

  const digest = Buffer.from(await crypto.subtle.digest('SHA-256', body)).toString('base64')
  assert.equal(contentDigest, `sha-256=:${digest}:`)
  assert.ok(signatureInput)
  assert.ok(signatureHeader)
  const inputs = parseDictionary(signatureInput)
  const signatures = parseDictionary(signatureHeader)
  assert.equal(inputs.size, directory.keys.length)
  assert.deepEqual([...signatures.keys()], [...inputs.keys()])

  for (const publicKey of directory.keys) {
    const input = [...inputs.entries()].find(([, value]) =>
      value.includes(`;keyid="${publicKey.kid}"`),
    )
    assert.ok(input)
    const [label, parameters] = input
    assert.match(parameters, /"@authority";req/)
    assert.match(parameters, /"content-digest"/)
    assert.match(parameters, /;alg="ed25519"/)
    assert.match(parameters, /;tag="http-message-signatures-directory"/)

    const created = Number(parameters.match(/;created=(\d+)/)?.[1])
    const expires = Number(parameters.match(/;expires=(\d+)/)?.[1])
    assert.ok(Number.isSafeInteger(created))
    assert.ok(expires > created)

    const signatureBase = [
      '"@authority";req: agents.tempo.xyz',
      `"content-digest": ${contentDigest}`,
      `"@signature-params": ${parameters}`,
    ].join('\n')
    const signatureValue = signatures.get(label)
    assert.match(signatureValue ?? '', /^:[A-Za-z0-9+/]+=*:$/)
    const signature = Buffer.from(signatureValue.slice(1, -1), 'base64')
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
  }
})

function parseDictionary(value) {
  return new Map(
    value.split(/,\s*/).map((entry) => {
      const separator = entry.indexOf('=')
      assert.ok(separator > 0)
      return [entry.slice(0, separator), entry.slice(separator + 1)]
    }),
  )
}
