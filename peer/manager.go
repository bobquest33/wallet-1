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

package peer

import (
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"github.com/boltdb/bolt"
	"github.com/monarj/wallet/block"
	"github.com/monarj/wallet/db"
	"github.com/monarj/wallet/msg"
	"github.com/monarj/wallet/params"
)

var (
	alive = make(map[string]*Peer)
	peers = make(map[string]*net.TCPAddr)
	mutex sync.RWMutex
)

const (
	maxNodes = 5
)

//Add adds tcpaddr as a candidate peer.
func Add(n *net.TCPAddr) {
	mutex.Lock()
	defer mutex.Unlock()
	if _, ok := peers[n.String()]; ok {
		return
	}
	peers[n.String()] = n
}

//Del deletes tcpaddr from peer list..
func Del(n net.Addr) {
	mutex.Lock()
	defer mutex.Unlock()
	delete(peers, n.String())
	delete(alive, n.String())
}

//Resolve resolvs node addresses from the dns seed.
func Resolve() {
	var wg sync.WaitGroup
	for _, dns := range params.DNSSeeds {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ns, err := net.LookupHost(dns)
			if err != nil {
				log.Println(err)
				return
			}
			for _, addr := range ns {
				n, err := net.ResolveTCPAddr("tcp", fmt.Sprintf("%s:%d", addr, params.Port))
				if err != nil {
					log.Println(err)
					continue
				}
				Add(n)
			}
		}()
		wg.Wait()
	}
}

//Connect connects to node ,send a version packet,
//and returns Node struct.
func Connect() error {
	for _, addr := range peers {
		if length() > maxNodes {
			return nil
		}
		conn, err := net.DialTCP("tcp", nil, addr)
		if err != nil {
			log.Println(err)
			return err
		}
		n := &Peer{conn: conn}
		mutex.Lock()
		alive[n.String()] = n
		mutex.Unlock()
		log.Println("connecting ", n.String())
		go func(nn *Peer) {
			defer func() {
				Del(nn.conn.RemoteAddr())
			}()
			if err = n.Handshake(); err != nil {
				log.Println(err)
				return
			}
			if errr := nn.Loop(); errr != nil {
				log.Println(errr)
			}
		}(n)
	}
	if length() < maxNodes {
		log.Println("shortage of nodes")
	}
	return nil
}

func length() int {
	mutex.RLock()
	defer mutex.RUnlock()
	return len(alive)
}

//Run starts to connect nodes.
func Run() {
	Resolve()
	Connect()
	time.Sleep(10 * time.Second)
	goGetHeader()
	go func() {
		for range time.Tick(5 * time.Minute) {
			Connect()
		}
	}()
}

func getheaders() (msg.Getheaders, error) {
	h, err := block.LocatorHash()
	return msg.Getheaders{
		Version:   params.ProtocolVersion,
		LocHashes: h,
		HashStop:  nil,
	}, err
}

//goGetHeader is goroutine which gets header continually.
func goGetHeader() {
	finished := 0
	go func() {
		for {
			data, err := getheaders()
			if err != nil {
				log.Println(err)
				return
			}
			wch <- &writeCmd{
				cmd:  "getheaders",
				data: data,
			}
			select {
			case result := <-blockAdded:
				if result.err == nil && len(result.hashes) == 0 {
					finished++
				} else {
					finished = 0
				}
			case <-time.After(time.Minute):
			}
			if finished > 10 {
				time.Sleep(15 * time.Minute)
			}
		}
	}()
}

var stop chan struct{}

const size uint64 = 1000

func done(height uint64) {
	err := db.DB.Update(func(tx *bolt.Tx) error {
		return db.Put(tx, "status", []byte("lastmerkle"), db.MustTob(height))
	})
	if err != nil {
		log.Print(err)
	}
}

func goGetMerkle() {
	if stop == nil {
		stop = make(chan struct{})
	}
	go func() {
		var lastheight uint64
		for lastheight = 0; ; lastheight += size {
			hash, err := block.GetHashes(lastheight, size)
			if err != nil {
				log.Print(err)
			}
			po := makeInv(msg.MsgFilterdBlock, hash)
			cmd := &writeCmd{
				cmd:  "getdata",
				data: po,
			}
			for failed := 0; failed < 5; failed++ {
				wch <- cmd
				select {
				case <-stop:
					return
				case <-time.After(time.Minute):
					continue
				case err := <-cmd.err:
					if err == nil {
						done(lastheight)
						break
					}
					log.Print(err)
				}
			}
		}
	}()
}

//GetMerkle (re)start to get merkle blocks from genesis.
func GetMerkle() {
	var lastheight uint64
	if stop != nil {
		stop <- struct{}{}
		done(0)
	} else {
		err := db.DB.View(func(tx *bolt.Tx) error {
			_, err := db.Get(tx, "status", []byte("lastmerkle"), &lastheight)
			return err
		})
		if err != nil {
			log.Print(err)
		}
	}
	goGetMerkle()
}
