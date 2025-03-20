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
3. `atproto` - An ATProto handle + app password will be used to authenticate the
user. Works with did:web also.

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
	server = "chat.rockorager.dev", -- Chat server you want to connect to
	nick = "rockorager.dev", -- BlueSky / ATProto handle. Skip the '@'
	password = "xxxx-xxxx-xxxx-xxxx", -- app password
})
```

### senpai

```scfg
address chat.rockorager.dev
nickname rockorager.dev
password xxxx-xxxx-xxxx-xxxx
```

### weechat

```
/server add <servername> chat.rockorager.dev/6697 -ssl
/set irc.server.<servername>.sasl_mechanism "plain"
/set irc.server.<servername>.sasl_username "rockorager.dev"
/set irc.server.<servername>.sasl_password "xxxx-xxxx-xxxx-xxxx"
```

### halloy

```toml
[servers.apollo]
nickname = "rockorager.dev" #BlueSky handle
server = "chat.rockorager.dev" # Server url

[servers.apollo.sasl.plain]
username = "rockorager.dev" # BlueSky / ATProto handle
password = "xxxx-xxxx-xxxx-xxxx" # App password
```
