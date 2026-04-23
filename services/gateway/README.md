# gateway

The gateway is the single externally-reachable entry point for the Deep Analysis stack. It terminates TLS, applies auth middleware (verifying short-lived JWTs issued by the `auth` service), enforces rate limits, and reverse-proxies requests to the appropriate internal service. Implementation is Caddy-primary with an optional thin FastAPI shim for request mutation. No other service is exposed to the public network.
