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

	"net"

	"github.com/monarj/wallet/params"
)

//Nodes represents nodes.
var Nodes []*net.TCPAddr

var alive []*Node

var mutex sync.RWMutex

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
				log.Println("adding node", addr)
				n, err := net.ResolveTCPAddr("tcp", fmt.Sprintf("%s:%d", addr, params.Port))
				if err != nil {
					log.Println(err)
					continue
				}
				mutex.Lock()
				Nodes = append(Nodes, n)
				mutex.Unlock()
			}
		}()
		wg.Wait()
	}
}

//ConnectAll connects to at most 10 nodes.
func ConnectAll() {
	for _, n := range Nodes {
		log.Println("connecting ", n.String())
		nn, err := Connect(n)
		if err != nil {
			log.Println(err)
			continue
		}
		alive = append(alive, nn)
		if len(alive) > maxNodes {
			return
		}
	}
}
