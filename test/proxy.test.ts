import { describe, expect, it, vi } from 'vitest'

import { handleProxyRequest, type ProxyEnv } from '../src/proxy'

function createRequest(input: string, init?: RequestInit): Request {
  return new Request(`https://worker.example.com${input}`, init)
}

function createEnv(overrides: Partial<ProxyEnv> = {}): ProxyEnv {
  return {
    ROUTE_BASE_PATH: '',
    SELF_HOSTNAMES: '',
    DISPATCH_SECRET: 'relay-secret',
    ...overrides,
  }
}

function readSetCookies(headers: Headers): string[] {
  const getSetCookie = (
    headers as Headers & { getSetCookie?: () => string[] }
  ).getSetCookie

  if (typeof getSetCookie === 'function') {
    return getSetCookie.call(headers)
  }

  const singleValue = headers.get('set-cookie')

  return singleValue ? [singleValue] : []
}

describe('handleProxyRequest', () => {
  it.each([
    '/proxy/www.google.com',
    '/proxyssl/api.openai.com/v1/responses',
  ])('returns 404 for former public proxy routes: %s', async (path) => {
    const fetchSpy = vi.fn()

    const response = await handleProxyRequest(createRequest(path), createEnv(), fetchSpy)

    expect(response.status).toBe(404)
    expect(fetchSpy).not.toHaveBeenCalled()
  })

  it('rejects an invalid relay secret as not found', async () => {
    const fetchSpy = vi.fn()

    const response = await handleProxyRequest(
      createRequest('/relay/bad-token/h/example.com/v1/chat'),
      createEnv(),
      fetchSpy,
    )

    expect(response.status).toBe(404)
    expect(fetchSpy).not.toHaveBeenCalled()
  })

  it('maps the internal relay /h route to an HTTP upstream and preserves path and query', async () => {
    const fetchSpy = vi.fn(async (request: Request) => {
      expect(request.url).toBe('http://www.google.com/search/results?q=workers')

      return new Response('ok', { status: 200 })
    })

    const response = await handleProxyRequest(
      createRequest('/relay/relay-secret/h/www.google.com/search/results?q=workers'),
      createEnv(),
      fetchSpy,
    )

    expect(response.status).toBe(200)
    expect(await response.text()).toBe('ok')
    expect(fetchSpy).toHaveBeenCalledTimes(1)
  })

  it('maps the internal relay /s route to an HTTPS upstream and ignores legacy Bearer routing', async () => {
    const fetchSpy = vi.fn(async (request: Request) => {
      expect(request.url).toBe('https://api.openai.com/v1/responses?list=models')
      expect(request.headers.get('authorization')).toBe(
        'Bearer https://legacy.invalid:token',
      )

      return new Response(JSON.stringify({ ok: true }), {
        status: 200,
        headers: {
          'content-type': 'application/json',
        },
      })
    })

    const response = await handleProxyRequest(
      createRequest('/relay/relay-secret/s/api.openai.com/v1/responses?list=models', {
        headers: {
          Authorization: 'Bearer https://legacy.invalid:token',
        },
      }),
      createEnv(),
      fetchSpy,
    )

    expect(response.status).toBe(200)
    expect(await response.json()).toEqual({ ok: true })
  })

  it('supports an optional route base path', async () => {
    const fetchSpy = vi.fn(async (request: Request) => {
      expect(request.url).toBe('https://example.com/v1/chat?from=edge')

      return new Response('prefixed', { status: 200 })
    })

    const response = await handleProxyRequest(
      createRequest('/edge/relay/relay-secret/s/example.com/v1/chat?from=edge'),
      createEnv({ ROUTE_BASE_PATH: '/edge' }),
      fetchSpy,
    )

    expect(response.status).toBe(200)
    expect(await response.text()).toBe('prefixed')
  })

  it('restores encoded relay host segments and nested path segments into the upstream URL', async () => {
    const fetchSpy = vi.fn(async (request: Request) => {
      expect(request.url).toBe('https://example.com:8443/v1/chat/completions?trace=1')

      return new Response('restored', { status: 200 })
    })

    const response = await handleProxyRequest(
      createRequest('/relay/relay-secret/s/example.com%3A8443/v1/chat/completions?trace=1'),
      createEnv(),
      fetchSpy,
    )

    expect(response.status).toBe(200)
    expect(await response.text()).toBe('restored')
    expect(fetchSpy).toHaveBeenCalledTimes(1)
  })

  it('rejects missing authorities without reaching the upstream', async () => {
    const fetchSpy = vi.fn()

    const response = await handleProxyRequest(
      createRequest('/relay/relay-secret/s'),
      createEnv(),
      fetchSpy,
    )

    expect(response.status).toBe(400)
    expect(fetchSpy).not.toHaveBeenCalled()
    await expect(response.json()).resolves.toMatchObject({
      error: {
        code: 'MISSING_AUTHORITY',
      },
    })
  })

  it('rejects malformed authorities', async () => {
    const fetchSpy = vi.fn()

    const response = await handleProxyRequest(
      createRequest('/relay/relay-secret/s/https:%2F%2Fbad'),
      createEnv(),
      fetchSpy,
    )

    expect(response.status).toBe(400)
    expect(fetchSpy).not.toHaveBeenCalled()
    await expect(response.json()).resolves.toMatchObject({
      error: {
        code: 'INVALID_AUTHORITY',
      },
    })
  })

  it('blocks self-proxy loops against the current hostname and configured aliases', async () => {
    const fetchSpy = vi.fn()

    const sameHostResponse = await handleProxyRequest(
      createRequest('/relay/relay-secret/s/worker.example.com'),
      createEnv(),
      fetchSpy,
    )

    expect(sameHostResponse.status).toBe(403)

    const aliasResponse = await handleProxyRequest(
      createRequest('/relay/relay-secret/h/edge.example.com'),
      createEnv({ SELF_HOSTNAMES: 'edge.example.com,api.edge.example.com' }),
      fetchSpy,
    )

    expect(aliasResponse.status).toBe(403)
    expect(fetchSpy).not.toHaveBeenCalled()
  })

  it('forwards method, end-to-end headers and JSON bodies transparently', async () => {
    const fetchSpy = vi.fn(async (request: Request) => {
      expect(request.method).toBe('POST')
      expect(request.url).toBe('https://example.com/v1/chat/completions')
      expect(request.headers.get('user-agent')).toBe('Custom UA')
      expect(request.headers.get('cookie')).toBe('session=abc')
      expect(request.headers.get('content-type')).toBe('application/json')
      expect(request.headers.get('connection')).toBeNull()
      expect(await request.text()).toBe('{"hello":"world"}')

      return new Response('json-ok', { status: 201 })
    })

    const response = await handleProxyRequest(
      createRequest('/relay/relay-secret/s/example.com/v1/chat/completions', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'User-Agent': 'Custom UA',
          Cookie: 'session=abc',
          Connection: 'keep-alive',
        },
        body: '{"hello":"world"}',
      }),
      createEnv(),
      fetchSpy,
    )

    expect(response.status).toBe(201)
    expect(await response.text()).toBe('json-ok')
  })

  it('forwards binary request bodies unchanged', async () => {
    const binaryBody = new Uint8Array([0, 1, 2, 255])
    const fetchSpy = vi.fn(async (request: Request) => {
      expect(request.url).toBe('http://upload.example.com/files/blob')
      const forwarded = new Uint8Array(await request.arrayBuffer())

      expect(Array.from(forwarded)).toEqual(Array.from(binaryBody))

      return new Response('binary-ok', { status: 200 })
    })

    const response = await handleProxyRequest(
      createRequest('/relay/relay-secret/h/upload.example.com/files/blob', {
        method: 'PUT',
        headers: {
          'Content-Type': 'application/octet-stream',
        },
        body: binaryBody,
      }),
      createEnv(),
      fetchSpy,
    )

    expect(response.status).toBe(200)
    expect(await response.text()).toBe('binary-ok')
  })

  it('relays status, headers, multiple Set-Cookie values and streaming bodies', async () => {
    const encoder = new TextEncoder()
    const upstreamBody = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(encoder.encode('data: first\n\n'))
        controller.enqueue(encoder.encode('data: second\n\n'))
        controller.close()
      },
    })

    const fetchSpy = vi.fn(async () => {
      const headers = new Headers({
        'content-type': 'text/event-stream',
        'cache-control': 'no-cache',
      })

      headers.append('set-cookie', 'a=1; Path=/; HttpOnly')
      headers.append('set-cookie', 'b=2; Path=/; Secure')

      return new Response(upstreamBody, {
        status: 202,
        headers,
      })
    })

    const response = await handleProxyRequest(
      createRequest('/relay/relay-secret/s/stream.example.com/events'),
      createEnv(),
      fetchSpy,
    )

    expect(response.status).toBe(202)
    expect(response.headers.get('content-type')).toBe('text/event-stream')
    expect(readSetCookies(response.headers)).toEqual([
      'a=1; Path=/; HttpOnly',
      'b=2; Path=/; Secure',
    ])
    expect(await response.text()).toBe('data: first\n\ndata: second\n\n')
  })

  it.each([
    {
      status: 403,
      body: '<html>challenge</html>',
      contentType: 'text/html',
    },
    {
      status: 429,
      body: '{"error":"rate_limited"}',
      contentType: 'application/json',
    },
  ])(
    'passes upstream anti-bot responses through unchanged (status $status)',
    async ({ status, body, contentType }) => {
      const fetchSpy = vi.fn(
        async () =>
          new Response(body, {
            status,
            headers: {
              'content-type': contentType,
            },
          }),
      )

      const response = await handleProxyRequest(
        createRequest('/relay/relay-secret/s/protected.example.com'),
        createEnv(),
        fetchSpy,
      )

      expect(response.status).toBe(status)
      expect(response.headers.get('content-type')).toBe(contentType)
      expect(await response.text()).toBe(body)
    },
  )
})
