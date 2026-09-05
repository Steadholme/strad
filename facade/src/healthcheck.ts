const address = process.env.ANALYZE_FACADE_BIND_ADDR ?? '0.0.0.0:18120'
const port = address.slice(address.lastIndexOf(':') + 1)
const response = await fetch(`http://127.0.0.1:${port}/readyz`, {
  redirect: 'error',
  signal: AbortSignal.timeout(4000),
})
if (!response.ok) process.exit(1)
