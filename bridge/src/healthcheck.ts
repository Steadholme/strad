import http from 'node:http'

const rawPort = process.env.STRAD_BRIDGE_PORT ?? '18090'
if (!/^[0-9]{1,5}$/.test(rawPort)) process.exit(1)

const request = http.get(
  {
    hostname: '127.0.0.1',
    port: Number(rawPort),
    path: '/readyz',
    agent: false,
    timeout: 30_000,
  },
  (response) => {
    response.resume()
    response.once('end', () => process.exit(response.statusCode === 200 ? 0 : 1))
  }
)
request.once('timeout', () => request.destroy())
request.once('error', () => process.exit(1))
