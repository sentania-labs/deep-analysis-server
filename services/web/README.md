# web

The web service is the user-facing dashboard UI. In production it reaches other services only through the gateway; in development it may talk directly to `auth` and `analytics`. Initial implementation is FastAPI + Jinja templating; an SPA frontend is an option for later phases. No domain data of its own — it is a presentation layer over the analytics API.
