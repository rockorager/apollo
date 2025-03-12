# apollo

An IRC server with some opinions

## Usage

Don't use it yet

## Development

Apollo can be run locally (or remotely) with the following command:

`apollo --hostname <hostname> --port <port> --auth <auth>`, where `auth` is one
of:

1. `none` - No authentication will happen. Whatever a user supplies as part of
their SASL plain auth will be used as their nick
2. `github` - The password portion of SASL plain is taken to be a Github access
token. apollo will request the profile of the authenticated user, and use their
github login as their nick

If you don't supply any options, it will default to "localhost", 6667, and
`none`. Apollo requires SASL plain authentication, and never runs it's own TLS.
When running remotely, always run it behind a proxy.
