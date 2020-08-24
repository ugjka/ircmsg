// Copyright 2014 Vic Demuzere
// Copyright 2020 Ugis Germanis
//
// Use of this source code is governed by the MIT license.

// Package ircmsg parses raw irc messages.
//
// The Message and Prefix structs provide translation to and from raw IRC messages:
//
//    // Parse the IRC-encoded data and store the result in a new struct:
//    message := ircmsg.ParseMessage(raw)
//
//    // Translate back to a raw IRC message string:
//    raw = message.String()
//
package ircmsg
