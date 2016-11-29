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

	"sort"

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
	log.Print("start to get txs")
	gosaveMerkleInfo()
	getMerkle()
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
				log.Print("finished syncing header.")
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

var (
	txhashes = make(chan [][]byte)
)

const size uint64 = 500

func getMerkle() {
	goGetMerkle()
	go func() {
		for {
			var lastheight uint64
			err := db.DB.View(func(tx *bolt.Tx) error {
				_, err := db.Get(tx, "status", []byte("lastmerkle"), &lastheight)
				return err
			})
			if err != nil {
				log.Print(err)
			}
			for height := lastheight; ; height++ {
				hs, err := block.GetHashes(height, size)
				if err != nil || len(hs) == 0 {
					log.Print(err, len(hs))
					time.Sleep(15 * time.Minute)
					break
				}
				txhashes <- hs
			}
		}
	}()
}

func goGetMerkle() {
	go func() {
		for hashes := range txhashes {
			log.Print("getting txs from ", behex.EncodeToString(hashes[0]))
			po := makeInv(msg.MsgFilterdBlock, hashes)
			cmd := &writeCmd{
				cmd:  "getdata",
				data: po,
				err:  make(chan error),
			}
			go func(hashes [][]byte) {
				wch <- cmd
				if err := <-cmd.err; err != nil {
					txhashes <- hashes
					log.Print(err)
					return
				}
			}(hashes)
		}
	}()
}

func gosaveMerkleInfo() {
	go func() {
		for {
			t := time.NewTimer(time.Minute)
			var finished block.UInt64Slice
			select {
			case h := <-gotMerkle:
				b, err := block.LoadBlock(h)
				if err != nil {
					log.Print(err)
					break
				}
				finished = append(finished, b.Height)
			case <-t.C:
				if len(finished) == 0 {
					break
				}
				sort.Sort(finished)
				var i int
				for i = 0; i < len(finished)-1; i++ {
					if finished[i]+1 != finished[i+1] {
						break
					}
				}
				err := db.Batch("status", []byte("lastmerkle"), finished[i+1])
				if err != nil {
					log.Fatal(err)
				}
				finished = finished[i+1:]
				t.Stop()
				t.Reset(time.Minute)
			}
		}
	}()
}

//ResetTx resets synced height of tx to 0
func ResetTx() {
	err := db.Batch("status", []byte("lastmerkle"), uint64(0))
	if err != nil {
		log.Fatal(err)
	}
}
