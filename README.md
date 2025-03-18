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

## Design Principles

1. Low friction, modern chat experience
2. Self hostable on low-end hardware for most use cases
3. Identity provided by third parties (ATProto, Github, etc)
4. Comply with IRC specifications, but not necessarily IRC norms

## Clients

### comlink

```lua
comlink.connect({
	server = "irc.example.com",
	user = "anything",
	nick = "foo",
	password = "<github personal access token",
	real_name = "Can be anything",
	tls = true,
})
```

### senpai

```scfg
address irc.example.com
nickname foo
realname Can be anything
password <github personal access token>
```
```

### weechat

```
/server add <servername> <url>/6697 -ssl
/set irc.server.<servername>.sasl_mechanism "plain"
/set irc.server.<servername>.sasl_username "foo"
/set irc.server.<servername>.sasl_password "<github personal access token>"
```
