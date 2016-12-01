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
		}
	}()
}

//AliveNum returns number of alive peers.
func AliveNum() int {
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
	for AliveNum() < maxNodes {
		log.Print("waiting for alive peers, now ", AliveNum())
		time.Sleep(5 * time.Second)
	}
	log.Print("start to get header")
	goGetHeader()
	log.Print("start to get txs")
	goGetMerkle()
}

//BlockSynced returns true is block is fully synced.
func BlockSynced() bool {
	bs := block.Lastblocks()
	return blockSynced(bs)
}

func blockSynced(bs []*block.Block) bool {
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

func addBlockHash() {
	bs := block.Lastblocks()
	log.Println("last confirmed block ", bs[0].Height)
	if blockSynced(bs) {
		synced = true
		log.Print("finished syncing header.")
		time.Sleep(5 * time.Minute)
	}
	for _, b := range bs {
		hashes <- b.Hash
	}
}

//goGetHeader is goroutine which gets header continually.
func goGetHeader() {
	go func() {
		t := time.NewTimer(10 * time.Second)
		for {
			addBlockHash()
		loop:
			for {
				t.Stop()
				t.Reset(10 * time.Second)
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

			}
		}
	}()
}

var (
	txhashes = make(chan [][]byte, maxNodes*10)
	gotTX    = make(chan uint64, maxNodes*10)
	finished block.UInt64Slice
)

const size uint64 = 500

func sendMerkles() {
	mutex.Lock()
	defer mutex.Unlock()
	sort.Sort(finished)
	var lastheight uint64
	err := db.DB.View(func(tx *bolt.Tx) error {
		_, err := db.Get(tx, "status", []byte("lastmerkle"), &lastheight)
		return err
	})
	if err != nil {
		log.Print("no lastmerkle")
		return
	}
	i := 0
	for i = 0; i < len(finished); i++ {
		if finished[i] <= lastheight {
			continue
		}
		if lastheight+1 < finished[i] {
			break
		}
		lastheight++
	}
	err = db.Batch("status", []byte("lastmerkle"), lastheight)
	if err != nil {
		log.Fatal(err)
	}
	copy(finished[0:], finished[i:])
	finished = finished[:len(finished)-i]
	log.Print("saved ", lastheight, len(finished))
	if len(finished) > 0 {
		log.Print("next", finished[0])
	}
	var n uint64
	for n = 0; n < maxNodes; n++ {
		hs, err := block.GetHashes(lastheight+1+n*size, size)
		if err != nil && len(hs) == 0 {
			log.Print(err, len(hs))
			log.Print("tx is synced")
			time.Sleep(5 * time.Minute)
			continue
		}
		txhashes <- hs
		if len(finished) > 1 && finished[0] < uint64(maxNodes)*size {
			return
		}
	}
	log.Print("sended txs requests")
}

func goGetMerkle() {
	t := time.NewTimer(10 * time.Second)
	go func() {
		for {
			t.Stop()
			t.Reset(10 * time.Second)
			select {
			case hashes := <-txhashes:
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
				}
			case h := <-gotTX:
				finished = append(finished, h)
			case <-t.C:
				sendMerkles()
			}
		}
	}()
}
