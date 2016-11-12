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

package myself

import (
	"fmt"
	"log"
	"net"
	"sync"

	"github.com/monarj/wallet/params"
)

var (
	//myself represents my ip and port.
	myself *net.TCPAddr
	mutex  sync.RWMutex
)

func init() {
	var err error
	myself, err = net.ResolveTCPAddr("tcp", fmt.Sprintf("127.0.0.1:%d", params.Port))
	if err != nil {
		log.Fatal(err)
	}
}

//SetIP sets my IP address.
func SetIP(ip []byte) {
	mutex.Lock()
	defer mutex.Unlock()
	myself.IP = net.IP(ip)
}

//SetPort sets my port number.
func SetPort(port int) {
	mutex.Lock()
	defer mutex.Unlock()
	myself.Port = port
}

//Get returns my TCPAddr.
func Get() *net.TCPAddr {
	mutex.RLock()
	defer mutex.RUnlock()
	m := net.TCPAddr{}
	m = *myself
	return &m
}
