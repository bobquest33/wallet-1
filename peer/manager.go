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
	log.Println("#peers", peersNum())
}

//Connect connects to node ,send a version packet,
//and returns Node struct.
func Connect() {
	go func() {
		for {
			peers2 := make(map[string]*net.TCPAddr)
			mutex.RLock()
			for k, v := range peers {
				peers2[k] = v
			}
			mutex.RUnlock()
			for s, addr := range peers2 {
				log.Printf("connecting %s", s)
				conn, err := net.DialTimeout("tcp", s, 5*time.Second)
				if err != nil {
					log.Println(err)
					continue
				}
				n := &Peer{conn: conn.(*net.TCPConn)}
				mutex.Lock()
				_, exist := alive[s]
				if exist {
					mutex.Unlock()
					continue
				}
				alive[s] = n
				mutex.Unlock()
				if err = n.Handshake(); err != nil {
					log.Println(err)
					continue
				}
				log.Printf("connected %s", addr)
				if err = n.Loop(); err != nil {
					log.Println(err)
					Del(addr)
				}
			}
			log.Fatal()
		}
	}()
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
	synced = false
)

//Run starts to connect nodes.
func Run() {
	log.Print("resolving dns")
	Resolve()
	log.Print("connecting")
	for i := 0; i < maxNodes; i++ {
		Connect()
	}
	for length() < maxNodes {
		log.Print("waiting for alive peers, now ", length())
		time.Sleep(5 * time.Second)
	}
	log.Print("start to get header")
	goGetHeader()
	log.Print("start to get txs")
	gosaveMerkleInfo()
	getMerkle()
}

func Alives() int {
	mutex.RLock()
	defer mutex.RUnlock()
	return len(alive)
}

func isFinished(bs []*block.Block) bool {
	if len(bs) != 1 {
		return false
	}
	mutex.RLock()
	defer mutex.RUnlock()
	for _, n := range alive {
		if uint64(n.LastBlock) > bs[0].Height+params.Nconfirmed {
			return false
		}
	}
	return true
}

//goGetHeader is goroutine which gets header continually.
func goGetHeader() {
	go func() {
		for {
			bs := block.Lastblocks()
			log.Println("last confirmed block ", bs[0].Height)
			if isFinished(bs) {
				synced = true
				log.Print("finished syncing header.")
				time.Sleep(5 * time.Minute)
			}
			for _, b := range bs {
				hashes <- b.Hash
			}
			t := time.NewTimer(10 * time.Second)
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
				t.Reset(10 * time.Second)
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
				time.Sleep(time.Minute)
				break
			}
			for height := lastheight; ; height += size {
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
			wch <- cmd
			if err := <-cmd.err; err != nil {
				txhashes <- hashes
				log.Print(err)
				return
			}
		}
	}()
}

func gosaveMerkleInfo() {
	go func() {
		t := time.NewTimer(30 * time.Second)
		var finished block.UInt64Slice
		for {
			select {
			case h := <-gotMerkle:
				b, err := block.LoadBlock(h)
				if err != nil {
					log.Print(err)
					continue
				}
				finished = append(finished, b.Height)
			case <-t.C:
				if len(finished) > 0 {
					sort.Sort(finished)
					var i int
					for i = 0; i < len(finished)-1; i++ {
						if finished[i]+1 < finished[i+1] {
							break
						}
					}
					err := db.Batch("status", []byte("lastmerkle"), finished[i])
					if err != nil {
						log.Fatal(err)
					}
					log.Println("saved ", finished[i])
					if len(finished) > i {
						copy(finished[0:], finished[i+1:])
						finished = finished[:len(finished)-i]
					}
				}
				t.Stop()
				t.Reset(30 * time.Second)
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
