[![Latest release](https://img.shields.io/github/release/jedisct1/piknik.svg)](https://github.com/jedisct1/piknik/releases/latest)
[![Build status](https://travis-ci.org/jedisct1/piknik.svg?branch=master)](https://travis-ci.org/jedisct1/piknik?branch=master)

# piknik
Copy/paste anything over the network ([watch a demo on Asciinema](https://asciinema.org/a/80708))

## Blurb
Ever needed a copy/paste clipboard that works over the network?

Piknik seamlessly and securely transfers URLs, code snippets, documents, virtually anything between arbitrary hosts.

No SSH needed, and hosts can sit behind NAT gateways, on different networks.

Fill in the clipboard ("copy") with whatever comes in to the standard input:

```bash
$ pkc
clipboard content
```

Magically retrieve that content from any other host having Piknik installed with the same configuration:

```bash
$ pkp
clipboard content
```

Boom.

Obviously, it can be used to transfer files as well:

```bash
$ pkc < kitten.gif
$ pkp > kittencopy.gif
```

```bash
$ tar cvf - *.txt | pkc
$ pkp | tar xvf -
```

In order to work around firewalls/NAT gatways, the clipboard content transits over TCP via a staging server.

Nothing transits without end-to-end encryption; the server cannot learn much about what the clipboard actually contains.

Data can be shared between different operating systems, including MacOS, Linux and Windows.

## Installation

### Option 1: use precompiled binaries

Precompiled binaries for MacOS, Linux (i386, x86_64, ARM), Win32, Win64, DragonflyBSD, NetBSD and FreeBSD can be downloaded here:
https://github.com/jedisct1/piknik/releases/latest

### Option 2 (on MacOS): use Homebrew

```bash
$ brew tap jedisct1/piknik
$ brew install piknik
```

### Option 3: compile the source code

This project is written in Go. So, a Go compiler is required, as well as the following incantation:

```bash
$ export GOPATH=${GOPATH:-~/go} ; mkdir -p $GOPATH
$ go get github.com/jedisct1/piknik
```

The `piknik` executable file should then be available in `$GOPATH/bin`.

## Setup

Piknik requires a bunch of keys. Generate them all with

```bash
$ piknik -genkeys
```

This generates random keys (highly recommended).

A temporary alternative is to derive the keys from a password. The same password will always generate the same set of keys, on all platforms. In order to do so, add the `-password` switch:

```bash
$ piknik -genkeys -password
```

The output of the `-genkeys` command is all you need to build a configuration file.

Only copy the section for servers on the staging server. Only copy the section for clients on the clients.

Is a host gonna act both as a staging server and as a client? Ponder on it before copying the "hybrid" section, but it's there, just in case.

The default location for the configuration file is `~/.piknik.toml`. With the exception of Windows, where dot-files are not so common. On that platform, the file is simply called `piknik.toml`.

Sample configuration file for a staging server:
```toml
Listen = "0.0.0.0:8075"         # Edit appropriately
Psk    = "bf82bab384697243fbf616d3428477a563e33268f0f2307dd14e7245dd8c995d"
SignPk = "0c41ca9b0a1b5fe4daae789534e72329a93a352a6ad73d6f1d368d8eff37271c"
```

Sample configuration file for clients:
```toml
Connect   = "127.0.0.1:8075"    # Edit appropriately
Psk       = "bf82bab384697243fbf616d3428477a563e33268f0f2307dd14e7245dd8c995d"
SignPk    = "0c41ca9b0a1b5fe4daae789534e72329a93a352a6ad73d6f1d368d8eff37271c"
SignSk    = "cecf1d92052f7ba87da36ac3e4a745b64ade8f9e908e52b4f7cd41235dfe7481"
EncryptSk = "2f530eb85e59c1977fce726df9f87345206f2a3d40bf91f9e0e9eeec2c59a3e4"
```

Do not use these, uh? Get your very own keys with the `piknik -genkeys` command.
Edit the `Connect` and `Listen` properties to reflect the staging server IP and port.
And `chmod 600 ~/.piknik.toml` might not be a bad idea.

Don't like the default config file location? Use the `-config` switch.

## Usage (staging server)

Run the following command on the staging server (or use `runit`, `openrc`, `systemd`, whatever to run it as a background service):

```bash
$ piknik -server
```

The staging server has to be publicly accessible. At the very least, it must be reachable by the clients over TCP with the port you specify in the configuration.

Commands without a valid API key (present in the client configuration file) will be rejected by the server.

## Usage (clients)

```bash
$ piknik -copy
```

Copy the standard input to the clipboard.

```bash
$ piknik -paste
```

Retrieve the content of the clipboard and spit it to the standard output.
`-paste` is actually a no-op. This is the default action if `-copy` was not specified.

```bash
$ piknik -move
```

Retrieve the content of the clipboard, spit it to the standard output
and clear the clipboard. Not necessarily in this order.
Only one lucky client will have the privilege to see the content.

That's it.

Feed it anything. Text, binary data, whatever. As long as it fits in memory.

## Suggested shell aliases

Wait. Where are the `pkc` and `pkp` commands mentioned earlier?

Sample shell aliases:

```bash
# pko <content> : copy <content> to the clipboard
pko() {
    echo "$*" | piknik -copy
}

# pkf <file> : copy the content of <file> to the clipboard
pkf() {
    piknik -copy < $1
}

# pkc : read the content to copy to the clipboard from STDIN
alias pkc='piknik -copy'

# pkp : paste the clipboard content
alias pkp='piknik -paste'

# pkm : move the clipboard content
alias pkm='piknik -move'

# pkz : delete the clipboard content
alias pkz='piknik -copy < /dev/null'
```

## Use cases

Use it to:

- Securely send passwords, API keys, URLs from one host to another
- Share a clipboard with your teammates (which can be a lot of fun)
- Copy data from/to isolated VMs, without the VMWare tools or shared volumes (great for unsupported operating systems and malware sandboxes)
- Copy files from/to a Windows machine, without Samba or SSH
- Transfer data between hosts sitting behind firewalls/NAT gateways
- Easily copy configuration files to multiple hosts
- Start a slow download at the office, retrieve it later at home
- Quickly backup a file to the cloud before messing with it
- ...and more!

## Protocol

Common definitions:
```
k: API key
ek: 256-bit symmetric encryption key
ekid: encryption key id encoded as a 64-bit little endian integer
m: plaintext
ct: XChaCha20 ek,n (m)
Hk,s: BLAKE2b(domain="SK", key=k, salt=s, size=32)
Len(x): x encoded as a 64-bit little endian unsigned integer
n: random 192-bit nonce
r: random 256-bit client nonce
r': random 256-bit server nonce
ts: Unix timestamp as a 64-bit little endian integer
Sig: Ed25519
v: 5
```

Copy:
```
-> v || r || h0
h0 := Hk,0(v || r)

<- v || r' || h1
Hh := Hk,1(v || r' || h0)

-> 'S' || h2 || Len(n || ct) || ekid || ts || s || n || ct
s := Sig(n || ct)
h2 := Hk,2(h1 || 'S' || ekid || s)

<- Hk,3(h2)
```

Move/Paste:
```
Move:  opcode := 'M'
Paste: opcode := 'G'

-> v || r || h0
h0 := Hk,0(v || r)

<- v || r' || h1
h1 := Hk,1(v || r' || H0)

-> opcode || h2
h2 := Hk,2(h1 || opcode)

<- Hk,3(h2 || ekid || s) || Len(n || ct) || ekid || ts || s || n || ct
s := Sig(n || ct)
```

## License

[ISC](https://en.wikipedia.org/wiki/ISC_license).
