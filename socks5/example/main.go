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
