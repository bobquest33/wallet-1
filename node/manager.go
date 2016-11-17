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
	"fmt"
	"log"
	"sync"
	"time"

	"net"

	"github.com/monarj/wallet/params"
)

var (
	alive = make(map[string]*Node)
	mutex sync.RWMutex
)

const (
	maxNodes = 10
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

//WriteAll writes pkt to all alive nodes.
func WriteAll(cmd string, pkt interface{}) {
	mutex.RLock()
	defer mutex.RUnlock()
	for _, n := range alive {
		go func(n *Node) {
			n.mutex.Lock()
			if err := n.writeMessage(cmd, pkt); err != nil {
				log.Println(err)
			}
			n.mutex.Unlock()
		}(n)
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
