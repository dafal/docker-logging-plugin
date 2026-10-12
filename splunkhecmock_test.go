/*
 * Copyright 2018 Splunk, Inc..
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package main

import (
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func (message *splunkMessage) EventAsString() (string, error) {
	if val, ok := message.Event.(string); ok {
		return val, nil
	}
	return "", fmt.Errorf("cannot cast Event %v to string", message.Event)
}

func (message *splunkMessage) EventAsMap() (map[string]interface{}, error) {
	if val, ok := message.Event.(map[string]interface{}); ok {
		return val, nil
	}
	return nil, fmt.Errorf("cannot cast Event %v to map", message.Event)
}

type HTTPEventCollectorMock struct {
	tcpAddr     *net.TCPAddr
	tcpListener *net.TCPListener

	token string

	// Toggled by tests while the server is running, so accessed atomically.
	serverError int32
	hang        int32
	delay       int64 // nanoseconds added to every request

	test *testing.T

	// Serializes request handling: a cancelled request can still be handled
	// while the driver already sends the next one on a new connection.
	mu sync.Mutex

	connectionVerified bool
	gzipEnabled        *bool
	messages           []*splunkMessage
	numOfRequests      int64
	acceptedPosts      int64
}

func NewHTTPEventCollectorMock(t *testing.T) *HTTPEventCollectorMock {
	tcpAddr := &net.TCPAddr{IP: []byte{127, 0, 0, 1}, Port: 0, Zone: ""}
	tcpListener, err := net.ListenTCP("tcp", tcpAddr)
	if err != nil {
		t.Fatal(err)
	}
	return &HTTPEventCollectorMock{
		tcpAddr:            tcpAddr,
		tcpListener:        tcpListener,
		token:              "4642492F-D8BD-47F1-A005-0C08AE4657DF",
		test:               t,
		connectionVerified: false}
}

func setFlag(flag *int32, value bool) {
	if value {
		atomic.StoreInt32(flag, 1)
	} else {
		atomic.StoreInt32(flag, 0)
	}
}

// setServerError makes every request fail with HTTP 500.
func (hec *HTTPEventCollectorMock) setServerError(value bool) {
	setFlag(&hec.serverError, value)
}

// setHang makes every request hang until the client gives up.
func (hec *HTTPEventCollectorMock) setHang(value bool) {
	setFlag(&hec.hang, value)
}

// setDelay makes every request take at least the given duration.
func (hec *HTTPEventCollectorMock) setDelay(delay time.Duration) {
	atomic.StoreInt64(&hec.delay, int64(delay))
}

func (hec *HTTPEventCollectorMock) requestCount() int64 {
	return atomic.LoadInt64(&hec.numOfRequests)
}

func (hec *HTTPEventCollectorMock) acceptedPostCount() int64 {
	return atomic.LoadInt64(&hec.acceptedPosts)
}

func (hec *HTTPEventCollectorMock) URL() string {
	return "http://" + hec.tcpListener.Addr().String()
}

func (hec *HTTPEventCollectorMock) Serve() error {
	return http.Serve(hec.tcpListener, hec)
}

func (hec *HTTPEventCollectorMock) Close() error {
	return hec.tcpListener.Close()
}

func (hec *HTTPEventCollectorMock) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	var err error

	atomic.AddInt64(&hec.numOfRequests, 1)

	if delay := atomic.LoadInt64(&hec.delay); delay > 0 {
		time.Sleep(time.Duration(delay))
	}

	if atomic.LoadInt32(&hec.hang) == 1 {
		if request.Body != nil {
			defer request.Body.Close()
		}
		// Accept the connection and never reply, until the client gives up.
		// The guard only stops a leaked handler; it is far longer than any
		// test deadline, so it cannot make a timeout test pass by itself.
		select {
		case <-request.Context().Done():
		case <-time.After(5 * time.Minute):
		}
		return
	}

	if atomic.LoadInt32(&hec.serverError) == 1 {
		if request.Body != nil {
			defer request.Body.Close()
		}
		writer.WriteHeader(http.StatusInternalServerError)
		return
	}

	hec.mu.Lock()
	defer hec.mu.Unlock()

	switch request.Method {
	case http.MethodGet:
		// Verify that options method is getting called only once
		if hec.connectionVerified {
			hec.test.Errorf("Connection should not be verified more than once. Got second request with %s method.", request.Method)
		}
		hec.connectionVerified = true
		writer.WriteHeader(http.StatusOK)
	case http.MethodPost:
		// Always verify that Driver is using correct path to HEC
		if request.URL.String() != "/services/collector/event/1.0" {
			hec.test.Errorf("Unexpected path %v", request.URL)
		}
		defer request.Body.Close()

		if authorization, ok := request.Header["Authorization"]; !ok || authorization[0] != ("Splunk "+hec.token) {
			hec.test.Error("Authorization header is invalid.")
		}

		gzipEnabled := false
		if contentEncoding, ok := request.Header["Content-Encoding"]; ok && contentEncoding[0] == "gzip" {
			gzipEnabled = true
		}

		if hec.gzipEnabled == nil {
			hec.gzipEnabled = &gzipEnabled
		} else if gzipEnabled != *hec.gzipEnabled {
			// Nothing wrong with that, but we just know that Splunk Logging Driver does not do that
			hec.test.Error("Driver should not change Content Encoding.")
		}

		var gzipReader *gzip.Reader
		var reader io.Reader
		if gzipEnabled {
			gzipReader, err = gzip.NewReader(request.Body)
			if err != nil {
				hec.test.Fatal(err)
			}
			reader = gzipReader
		} else {
			reader = request.Body
		}

		// Read body
		var body []byte
		body, err = ioutil.ReadAll(reader)
		if err != nil {
			hec.test.Fatal(err)
		}

		// Parse message
		messageStart := 0
		for i := 0; i < len(body); i++ {
			if i == len(body)-1 || (body[i] == '}' && body[i+1] == '{') {
				var message splunkMessage
				err = json.Unmarshal(body[messageStart:i+1], &message)
				if err != nil {
					hec.test.Log(string(body[messageStart : i+1]))
					hec.test.Fatal(err)
				}
				hec.messages = append(hec.messages, &message)
				messageStart = i + 1
			}
		}

		if gzipEnabled {
			gzipReader.Close()
		}

		atomic.AddInt64(&hec.acceptedPosts, 1)
		writer.WriteHeader(http.StatusOK)
	default:
		hec.test.Errorf("Unexpected HTTP method %s", http.MethodOptions)
		writer.WriteHeader(http.StatusBadRequest)
	}
}
