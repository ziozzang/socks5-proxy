SOCKS 5 Proxy with Go Lang
=====

Original Library was imported from http://github.com/oov/socks5

I just modified and build for personal use.

this code support configuration loading.

* IP mask must be CIDR format like "1.2.3.0/24". If you want allow all client, use CIDR as "0.0.0.0/0"
* If ID/PW is supplied, use that. or IP restrictions

Installation
============
* if you want to use with windows, use released binary.
* if you want to use with linux(x86_64), just execute these command in console.
```
wget https://github.com/ziozzang/socks5-proxy/releases/download/1.0/socks5-proxy && chmod +x socks5-proxy
wget https://github.com/ziozzang/socks5-proxy/releases/download/1.0/socks5-proxy.config
```

* don't forget to edit configuration.

Original socks5
======

Package socks5 implements a "SOCKS Protocol Version 5" server.

This server supports a subset of RFC 1928:

* auth methods: "NO AUTHENTICATION REQUIRED", "USERNAME/PASSWORD"
* commands: "CONNECT"
* address types: "IP V4 address", "DOMAINNAME", "IP V6 address"
(but tested "DOMAINNAME" only)

INSTALL
-------

```sh
go get -u github.com/oov/socks5
```

USAGE
-----

```go
package main

import (
	"github.com/oov/socks5"
	"log"
)

func main() {
	srv := socks5.New()
	srv.AuthUsernamePasswordCallback = func(c *socks5.Conn, username, password []byte) error {
		user := string(username)
		if user != "guest" {
			return socks5.ErrAuthenticationFailed
		}

		log.Printf("Welcome %v!", user)
		c.Data = user
		return nil
	}
	srv.HandleConnectFunc(func(c *socks5.Conn, host string) (newHost string, err error) {
		if host == "example.com:80" {
			return host, socks5.ErrConnectionNotAllowedByRuleset
		}
		if user, ok := c.Data.(string); ok {
			log.Printf("%v connecting to %v", user, host)
		}
		return host, nil
	})
	srv.HandleCloseFunc(func(c *socks5.Conn) {
		if user, ok := c.Data.(string); ok {
			log.Printf("Goodbye %v!", user)
		}
	})

	srv.ListenAndServe(":12345")
}
```
