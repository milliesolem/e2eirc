# E2EIRC

E2EIRC lets you hold end-to-end encrypted conversations on regular, unmodified
IRC servers with your favourite IRC client.

It runs a small proxy on your machine (port 6666 by default). You point your
IRC client at the proxy, the proxy connects to the real IRC server, and it
encrypts the text of your messages on the way out and decrypts other
e2eirc users' messages on the way in. Everything else (nicks, channels,
joins, modes) passes through untouched.

## How it works

* **Identity.** On first run you get an Ed25519 identity key, stored in
  `~/.e2eirc/identity.key` encrypted with a password of your choice
  (Argon2id + XChaCha20-Poly1305). Its SHA-256 fingerprint is what other
  users verify.
* **Channel messages** are encrypted with a per-session *broadcast key*
  using ChaCha20-Poly1305. Every message carries a counter, and the
  channel name is bound into the authenticated data, so the server cannot
  replay a message, reorder it, or move it into another channel or
  conversation.
* **Private messages** use a separate pairwise key per peer derived from the
  key exchange, so trusting someone for channel traffic never gives them
  your private conversations with others.
* **Key exchange.** When your proxy sees a message it cannot read, it sends
  the sender a `HELLO`: an ephemeral X25519 key signed with your identity
  key, bound to both nicks. The sender answers with a `KEYEX` carrying its
  own signed ephemeral key and its broadcast key wrapped under the shared
  secret. Both sides also derive the private-message keys from the same
  exchange.
* **Trust.** Keys are only exchanged with identities you have approved.
  The first time a nick presents an identity, the proxy shows you its
  fingerprint through a pseudo-user called `$E2ECtrl` and asks you to
  confirm it. The approval is recorded as a *(nick, fingerprint)* pin in
  `~/.e2eirc/trusted_keys` (encrypted with a key derived from your
  identity). If a known nick later shows up with a different key, or a
  trusted key shows up under a different nick, you are warned loudly and
  asked again.
* Unencrypted messages from other users are delivered with a
  `[CLEARTEXT]` prefix so they can never be mistaken for authenticated
  text.

### Talking to the proxy

Send private messages to `$E2ECtrl` in your IRC client:

| Command | Effect |
|---|---|
| `TRUST <nick> <fingerprint prefix>` | approve the pending key request from `nick`; the prefix (at least 8 characters) must match the fingerprint shown, so an approval is always tied to the key you verified |
| `TRUST <nick>` | with nothing pending: start a key exchange with `nick`, forgetting an earlier refusal |
| `NO [nick]` | refuse the pending request; it is ignored for the rest of the session |
| `UNTRUST <nick>` | forget that nick's key, drop its session keys and rotate your broadcast key |
| `LISTTRUST` | show trusted keys and the state of this session's peers |
| `REGENKEY` | rotate your broadcast key; peers re-request it automatically |
| `HELP` | list the commands |

The proxy is the only thing that can speak as `$E2ECtrl`; lines the server
attributes to that name are dropped.

## Should I use this?

Maybe. It is a working proof of concept of end-to-end encryption for both
group chats and private chats on top of an untrusted server, and the code is
small enough to read in an afternoon. It has had a careful design and code
review, but it has not had an independent professional audit. Treat it as
beta software.

What it does **not** do: it does not make you anonymous. Your nick, IP
address, which channels you are in and when you talk are all visible to
the server. Anyone you trust for a channel can read everything you post to
channels they are in, and could repost it. The server can still drop or
delay messages.

## Install

You need Go 1.24 or newer.

```
$ git clone https://github.com/Novus0rdo/e2eirc
$ cd e2eirc
$ go build -o e2eirc .
```

Run it with the address of the IRC server you want to talk to:

```
$ ./e2eirc -host irc.libera.chat -port 6667
```

Flags:

| Flag | Default | Meaning |
|---|---|---|
| `-host` | `127.0.0.1` | IRC server to relay to |
| `-port` | `6667` | IRC server port |
| `-local_host` | `127.0.0.1` | address the proxy listens on |
| `-local_port` | `6666` | port the proxy listens on |
| `-dir` | `~/.e2eirc` | where the identity key and trusted keys live |
| `-key` | | identity password; leave unset to be prompted. Other local users can see command lines, so prefer the prompt |

On first start you choose a password for your identity key. If you lose it
you lose that identity and will need to be re-trusted by your contacts.

Then connect your IRC client to `127.0.0.1` port `6666`, join a channel
with other e2eirc users, and say hello. When someone's proxy asks for your
key you will get a message from `$E2ECtrl`; compare the fingerprint with
them over a channel you already trust and answer `TRUST`.

Note that the proxy itself talks to the IRC server in the clear. Use a
server that offers TLS, or an SSH tunnel, if you want transport encryption
as well.

### Upgrading from 0.0.x

Version 0.2 replaces the RSA/AES-CFB protocol with the design described
above; the two cannot talk to each other. Old `private_key.pem` and
`trusted_keys` files are moved aside (`.old`) and a new identity is
created on first start.
