# Go **IRC** message parser package

[![GoDoc](https://godoc.org/github.com/ugjka/ircmsg?status.svg)](https://godoc.org/github.com/ugjka/ircmsg)

## Message

The [Message][] and [Prefix][] types provide translation to and from IRC message format.

```go
// Parse the IRC-encoded data and stores the result in a new struct.
message := ircmsg.ParseMessage(raw)

// Returns the IRC encoding of the message.
raw = message.String()
```

[message]: https://godoc.org/github.com/ugjka/ircmsg#Message "Message type documentation"
[prefix]: https://godoc.org/github.com/ugjka/ircmsg#Prefix "Prefix type documentation"

## Warning

We are at v0.0.X, the API is subject to change

## Original source

[https://github.com/sorcix/irc](https://github.com/sorcix/irc)
