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
	"log"
	"net"
	"sync"
	"time"

	"github.com/boltdb/bolt"
	"github.com/monarj/wallet/behex"
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
	maxNodes = 10
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
				ip := net.ParseIP(addr)
				if ip == nil {
					log.Println("invalid ip address")
					continue
				}
				n := &net.TCPAddr{
					IP:   ip,
					Port: params.Port,
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
		go func(addr *net.TCPAddr) {
			log.Printf("connecting %s", addr)
			conn, err := net.DialTCP("tcp", nil, addr)
			if err != nil {
				log.Println(err)
				return
			}
			n := &Peer{conn: conn}
			mutex.Lock()
			alive[n.String()] = n
			mutex.Unlock()
			defer func() {
				Del(n.conn.RemoteAddr())
			}()
			if err = n.Handshake(); err != nil {
				log.Println(err)
				return
			}
			if errr := n.Loop(); errr != nil {
				log.Println(errr)
			}
		}(addr)
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

func peersNum() int {
	mutex.RLock()
	defer mutex.RUnlock()
	return len(peers)
}

var (
	hashes = make(chan []byte, maxNodes*10)
)

//Run starts to connect nodes.
func Run() {
	log.Print("resolving dns")
	Resolve()
	log.Print("connecting")
	Connect()
	go func() {
		for range time.Tick(15 * time.Minute) {
			log.Print("reconnecting")
			Connect()
		}
	}()
	log.Print("start to get header")
	goGetHeader()
}

func isFinished(bs []*block.Block) bool {
	if len(bs) != 1 {
		return false
	}
	last := true
	for _, n := range alive {
		if uint64(n.LastBlock) != bs[0].Height {
			last = false
			break
		}
	}
	return last
}

//goGetHeader is goroutine which gets header continually.
func goGetHeader() {
	waittime := 10 * time.Second
	go func() {
		for {
			bs := block.Lastblocks()
			if isFinished(bs) {
				waittime = 5 * time.Minute
			}
			for _, b := range bs {
				hashes <- b.Hash
			}
			t := time.NewTimer(waittime)
		loop:
			for {
				select {
				case hash := <-hashes:
					log.Print("getting headers from ", behex.EncodeToString(hash))
					h, err := block.LocatorHash(hash)
					if err != nil {
						log.Println(err)
						return
					}
					data := msg.Getheaders{
						Version:   params.ProtocolVersion,
						LocHashes: h,
						HashStop:  nil,
					}
					cmd := &writeCmd{
						cmd:  "getheaders",
						data: data,
						err:  make(chan error),
					}
					go func() {
						wch <- cmd
						if err := <-cmd.err; err != nil {
							hashes <- hash
							log.Print(err)
							return
						}
					}()
				case <-t.C:
					break loop
				}
				if !t.Stop() {
					<-t.C
				}
				t.Reset(waittime)
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
				err:  make(chan error),
			}
			for failed := 0; failed < 5; failed++ {
				wch <- cmd
				if err := <-cmd.err; err != nil {
					log.Print(err)
					continue
				}
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
