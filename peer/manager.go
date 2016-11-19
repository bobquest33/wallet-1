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
	"sync"
	"time"

	"net"

	"github.com/monarj/wallet/block"
	"github.com/monarj/wallet/msg"
	"github.com/monarj/wallet/params"
)

var (
	alive = make(map[string]*Peer)
	mutex sync.RWMutex
)

const (
	maxNodes = 5
)

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
				if _, ok := alive[n.String()]; ok {
					continue
				}
				log.Println("adding node", addr)
				if err := Connect(n); err != nil {
					log.Println(err)
				}
			}
		}()
		wg.Wait()
	}
}

func length() int {
	mutex.RLock()
	defer mutex.RUnlock()
	return len(alive)
}

//Run starts to connect nodes.
func Run() {
	Resolve()
	time.Sleep(30 * time.Second)
	goGetHeader()
	goGetMerkle()
	go func() {
		for range time.Tick(5 * time.Minute) {
			cnt := 0
			for ; cnt < 5 && length() < maxNodes; cnt++ {
				Resolve()
			}
			if cnt == 5 {
				log.Println("no nodes.")
			}
		}
	}()
}

func getheaders() msg.Getheaders {
	h := block.LocatorHash()
	return msg.Getheaders{
		Version:   params.ProtocolVersion,
		HashCount: msg.VarInt(len(h)),
		LocHashes: h,
		HashStop:  nil,
	}
}

var mhash = make(chan [][]byte, 5)

func goGetMerkle() {
	go func() {
		for hash := range mhash {
			po := makeInv(msg.MsgFilterdBlock, hash)
			wch <- &writeCmd{
				cmd:  "getdata",
				data: po,
			}
			log.Println("sended getdata")
			go func(hash [][]byte) {
				select {
				case result := <-txAdded:
					if result.err != nil {
						mhash <- hash
					}
				case <-time.After(time.Minute):
					mhash <- hash
				}
			}(hash)
		}
	}()
}

//goGetHeader is goroutine which gets header continually.
func goGetHeader() {
	finished := 0
	go func() {
		for {
			wch <- &writeCmd{
				cmd:  "getheaders",
				data: getheaders(),
			}
			select {
			case result := <-blockAdded:
				if result.err == nil && len(result.hashes) == 0 {
					finished++
				} else {
					finished = 0
					mhash <- result.hashes
				}
			case <-time.After(time.Minute):
			}
			if finished > 10 {
				time.Sleep(15 * time.Minute)
			}
		}
	}()
}

//Notify writes cmd to a node.
func Notify(cmd string, p interface{}) {
	wch <- &writeCmd{
		cmd:  cmd,
		data: getheaders(),
	}
}
