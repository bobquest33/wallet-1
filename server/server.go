/*
 * Copyright (c) 2016, Shinya Yagyu
 * All rights reserved.
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 * 3. Neither the name of the copyright holder nor the names of its
 *    contributors may be used to endorse or promote products derived from this
 *    software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

package server

import (
	"fmt"
	"log"
	"net"

	"github.com/monarj/wallet/msg"
	"github.com/monarj/wallet/node"
	"github.com/monarj/wallet/params"
)

func Start() (net.Listener, chan error, error) {
	port := fmt.Sprintf(":%d", params.Port)
	tcpAddr, err := net.ResolveTCPAddr("tcp", port)
	if err != nil {
		log.Println(err)
		return nil, nil, err
	}
	listener, err := net.ListenTCP("tcp", tcpAddr)
	if err != nil {
		log.Println(err)
		return nil, nil, err
	}
	ch := make(chan error)
	go func() {
		for {
			conn, err := listener.AcceptTCP()
			switch err {
			case nil:
				go handle(conn)
			default:
				ch <- err
				return
			}
		}
	}()
	return listener, ch, nil
}

func handle(conn *net.TCPConn) {
	log.Println("client is accepted from ", conn.RemoteAddr().String())
	n := node.New(conn)
	if err := n.Handshake(); err != nil {
		log.Println(err)
		n.Close()
		return
	}
	if err := n.Loop(); err != nil {
		log.Println(err)
		n.Close()
	}
}

func parse(conn net.Conn) error {
	cmd, payload, err := msg.ReadMessage(conn)
	if err != nil {
		return err
	}
	log.Println(cmd)
	switch cmd {
	case "version":
		ver, err := msg.NewVersion(payload)
		if err != nil {
			return err
		}
		log.Println(ver)
	}
	return nil
}
