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

package node

import (
	"errors"
	"log"
	"net"

	"io"
	"time"
)

const (
	timeout = 2
)

//Node represents one node.
type Node struct {
	conn      *net.TCPConn
	Closed    bool
	timeout   int
	LastBlock uint32
	lastPing  uint64
}

//Close closes conn.
func (n *Node) Close() {
	if err := n.conn.Close(); err != nil {
		log.Println(err)
	}
	n.Closed = true
}

//New returns Node struct.
func New(conn *net.TCPConn) *Node {
	return &Node{conn: conn}
}

//Connect connects to node ,send a version packet,
//and returns Node struct.
func Connect(addr *net.TCPAddr) error {
	conn, err := net.DialTCP("tcp", nil, addr)
	if err != nil {
		log.Println(err)
		return err
	}
	n := &Node{conn: conn}
	mutex.Lock()
	alive[n.String()] = n
	mutex.Unlock()
	log.Println("connecting ", n.String())
	go func(nn *Node) {
		defer func() {
			mutex.Lock()
			delete(alive, nn.String())
			mutex.Unlock()
		}()
		if err = n.Handshake(); err != nil {
			log.Println(err)
			return
		}
		if errr := nn.Loop(); errr != nil {
			log.Println(errr)
		}
	}(n)
	return err
}

//String returns TCPConn.String() of Node n.
func (n *Node) String() string {
	return n.conn.RemoteAddr().String()
}

func (n *Node) errClose(err error) error {
	if err != nil {
		log.Println(err)
		n.Close()
	}
	return err
}

func (n *Node) errHandle(err error) error {
	if err != nil {
		op, ok := err.(*net.OpError)
		if ok && op.Timeout() {
			if n.timeout++; n.timeout > timeout {
				return errors.New("timeout")
			}
			if err = n.writePing(); err != nil {
				return err
			}
			return nil
		}
	}
	return err
}

//Loop starts node lifecyle.
func (n *Node) Loop() error {
	funcs := map[string]func(io.Reader) error{
		"ping":        n.pongAfterReadPing,
		"pong":        n.readPong,
		"inv":         n.readInv,
		"headers":     n.readHeaders,
		"merkleblock": n.readMerkle,
	}
	for {
		cmd, payload, err := n.readMessage()
		if err = n.errHandle(err); err != nil {
			return n.errClose(err)
		}
		log.Println(cmd + " from " + n.conn.RemoteAddr().String())
		f, exist := funcs[cmd]
		if !exist {
			log.Printf("%s:unknown or unsupported command", cmd)
			n.mutex.Unlock()
			continue
		}
		err = f(payload)
		if err = n.errHandle(err); err != nil {
			return n.errClose(err)
		}
		if err := n.setDeadline(); err != nil {
			return n.errClose(err)
		}
		n.mutex.Unlock()
	}
}

func (n *Node) setDeadline() error {
	if err := n.conn.SetDeadline(time.Now().Add(3 * time.Minute)); err != nil {
		return err
	}
	if err := n.conn.SetReadDeadline(time.Now().Add(3 * time.Minute)); err != nil {
		return err
	}
	if err := n.conn.SetWriteDeadline(time.Now().Add(3 * time.Minute)); err != nil {
		return err
	}
	return nil
}

//Handshake set deadline, send versionn packet, and receives one.
func (n *Node) Handshake() error {
	if err := n.setDeadline(); err != nil {
		return err
	}
	if err := n.writeVersion(); err != nil {
		return err
	}
	log.Println("sended a Version packet to", n.String())
	cmd, payload, err := n.readMessage()
	if err != nil {
		log.Println(err)
		return err
	}
	if cmd != "version" {
		return errors.New("not version packcket from " + n.String())
	}
	_, err = n.parseVersion(payload)
	if err != nil {
		log.Println(err)
		return err
	}
	log.Println("recv version from ", n.String())

	cmd, _, err = n.readMessage()
	if err != nil {
		return n.errClose(err)
	}
	if cmd != "verack" {
		err = errors.New("no verack")
		return n.errClose(err)
	}
	log.Println("received verack")

	if err = n.writeMessage("verack", struct{}{}); err != nil {
		log.Println(err)
		return err
	}
	log.Println("sended verack")

	if err = n.writePing(); err != nil {
		return n.errClose(err)
	}

	if err = n.writeFilterload(); err != nil {
		log.Println(err)
		return err
	}

	if err = n.writeMessage("mempool", struct{}{}); err != nil {
		log.Println(err)
		return err
	}
	log.Println("sended mempool")

	if err = n.writeGetheaders(); err != nil {
		log.Println(err)
		return err
	}

	return nil
}
