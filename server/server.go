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

package server

import (
	"fmt"
	"log"
	"net"
	"net/http"
	"net/http/pprof"
	"time"
)

//registerPprof registers pprof relates funcs to s.
func registerPprof(s *http.ServeMux) {
	s.Handle("/debug/pprof/", http.HandlerFunc(pprof.Index))
	s.Handle("/debug/pprof/cmdline", http.HandlerFunc(pprof.Cmdline))
	s.Handle("/debug/pprof/profile", http.HandlerFunc(pprof.Profile))
	s.Handle("/debug/pprof/symbol", http.HandlerFunc(pprof.Symbol))
}

//StartDserver starts a http server in goroutine.
func StartDserver() (net.Listener, chan error) {
	h := fmt.Sprintf("0.0.0.0:%d", 8080)
	listener, err := net.Listen("tcp", h)
	if err != nil {
		log.Fatalln(err)
	}
	sm := http.NewServeMux()
	s := &http.Server{
		Addr:           h,
		Handler:        sm,
		ReadTimeout:    3 * time.Minute,
		WriteTimeout:   3 * time.Minute,
		MaxHeaderBytes: 1 << 20,
	}
	registerPprof(sm)
	ch := make(chan error)
	go func() {
		ch <- s.Serve(listener)
	}()
	return listener, ch
}
