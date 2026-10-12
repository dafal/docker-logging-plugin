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
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/docker/docker/daemon/logger"
)

// Telemetry posts an extra event to the mock HEC 5s after a logger starts,
// which breaks message counts in tests that run longer than that (for example
// under the race detector). Tests that need it can enable it explicitly.
func TestMain(m *testing.M) {
	os.Setenv(envVarSplunkTelemetry, "false")
	os.Exit(m.Run())
}

// Validate options
func TestValidateLogOpt(t *testing.T) {
	err := ValidateLogOpt(map[string]string{
		splunkURLKey:                  "http://127.0.0.1",
		splunkTokenKey:                "2160C7EF-2CE9-4307-A180-F852B99CF417",
		splunkSourceKey:               "mysource",
		splunkSourceTypeKey:           "mysourcetype",
		splunkIndexKey:                "myindex",
		splunkCAPathKey:               "/usr/cert.pem",
		splunkCANameKey:               "ca_name",
		splunkInsecureSkipVerifyKey:   "true",
		splunkFormatKey:               "json",
		splunkVerifyConnectionKey:     "true",
		splunkGzipCompressionKey:      "true",
		splunkGzipCompressionLevelKey: "1",
		envKey:      "a",
		envRegexKey: "^foo",
		labelsKey:   "b",
		tagKey:      "c",
	})
	if err != nil {
		t.Fatal(err)
	}

	err = ValidateLogOpt(map[string]string{
		"not-supported-option": "a",
	})
	if err == nil {
		t.Fatal("Expecting error on unsupported options")
	}
}

// Driver require user to specify required options
func TestNewMissedConfig(t *testing.T) {
	info := logger.Info{
		Config: map[string]string{},
	}
	_, err := New(info)
	if err == nil {
		t.Fatal("Logger driver should fail when no required parameters specified")
	}
}

// Driver require user to specify splunk-url
func TestNewMissedUrl(t *testing.T) {
	info := logger.Info{
		Config: map[string]string{
			splunkTokenKey: "4642492F-D8BD-47F1-A005-0C08AE4657DF",
		},
	}
	_, err := New(info)
	if err.Error() != "splunk: splunk-url is expected" {
		t.Fatal("Logger driver should fail when no required parameters specified")
	}
}

//splunk-url needs to be in the format of scheme://dns_name_or_ip<:port>
func TestUrlFormat(t *testing.T) {
	info := logger.Info{
		Config: map[string]string{
			splunkURLKey: "127.0.0.1",
		},
	}
	_, err := parseURL(info)
	if err.Error() != "splunk: expected format scheme://dns_name_or_ip:port for splunk-url" {
		t.Fatal("Logger driver should fail when no schema is specified")
	}

	info = logger.Info{
		Config: map[string]string{
			splunkURLKey: "www.google.com",
		},
	}
	_, err = parseURL(info)
	if err.Error() != "splunk: expected format scheme://dns_name_or_ip:port for splunk-url" {
		t.Fatal("Logger driver should fail when schema is not specified")
	}

	info = logger.Info{
		Config: map[string]string{
			splunkURLKey: "ftp://127.0.0.1",
		},
	}
	_, err = parseURL(info)
	if err.Error() != "splunk: expected format scheme://dns_name_or_ip:port for splunk-url" {
		t.Fatal("Logger driver should fail when schema is not http or https")
	}

	info = logger.Info{
		Config: map[string]string{
			splunkURLKey: "http://127.0.0.1:8088/test",
		},
	}
	_, err = parseURL(info)
	if err.Error() != "splunk: expected format scheme://dns_name_or_ip:port for splunk-url" {
		t.Fatal("Logger driver should fail when path is specified")
	}

	info = logger.Info{
		Config: map[string]string{
			splunkURLKey: "testURL",
		},
	}
	_, err = parseURL(info)
	if err.Error() != "splunk: expected format scheme://dns_name_or_ip:port for splunk-url" {
		t.Fatal("Logger driver should fail when no schema is specified")
	}

	info = logger.Info{
		Config: map[string]string{
			splunkURLKey: "http://www.host.com/?q=hello",
		},
	}
	_, err = parseURL(info)
	if err.Error() != "splunk: expected format scheme://dns_name_or_ip:port for splunk-url" {
		t.Fatal("Logger driver should fail when query parameter is specified")
	}

	info = logger.Info{
		Config: map[string]string{
			splunkURLKey: "http://www.host.com#hello",
		},
	}
	_, err = parseURL(info)
	if err.Error() != "splunk: expected format scheme://dns_name_or_ip:port for splunk-url" {
		t.Fatal("Logger driver should fail when fragment is specified")
	}

	info = logger.Info{
		Config: map[string]string{
			splunkURLKey: "127.0.1:8000",
		},
	}
	_, err = parseURL(info)
	if !strings.HasPrefix(err.Error(), "splunk: failed to parse") {
		t.Fatal("Logger driver should fail when path is specified")
	}

	info = logger.Info{
		Config: map[string]string{
			splunkURLKey: "https://127.0.1:8000",
		},
	}

	url, err := parseURL(info)

	if url.String() != "https://127.0.1:8000/services/collector/event/1.0" {
		t.Fatalf("%s is not the right format of HEC endpoint.", url.String())
	}

	info = logger.Info{
		Config: map[string]string{
			splunkURLKey: "https://127.0.1:8000/",
		},
	}

	url, err = parseURL(info)

	if url.String() != "https://127.0.1:8000/services/collector/event/1.0" {
		t.Fatalf("%s is not the right format of HEC endpoint.", url.String())
	}
}

// Driver require user to specify splunk-token
func TestNewMissedToken(t *testing.T) {
	info := logger.Info{
		Config: map[string]string{
			splunkURLKey: "http://127.0.0.1:8088",
		},
	}
	_, err := New(info)
	if err.Error() != "splunk: splunk-token is expected" {
		t.Fatal("Logger driver should fail when no required parameters specified")
	}
}

// Test default settings
func TestDefault(t *testing.T) {
	hec := NewHTTPEventCollectorMock(t)

	go hec.Serve()

	info := logger.Info{
		Config: map[string]string{
			splunkURLKey:   hec.URL(),
			splunkTokenKey: hec.token,
		},
		ContainerID:        "containeriid",
		ContainerName:      "container_name",
		ContainerImageID:   "contaimageid",
		ContainerImageName: "container_image_name",
	}

	hostname, err := info.Hostname()
	if err != nil {
		t.Fatal(err)
	}

	loggerDriver, err := New(info)
	if err != nil {
		t.Fatal(err)
	}

	if loggerDriver.Name() != driverName {
		t.Fatal("Unexpected logger driver name")
	}

	if hec.connectionVerified {
		t.Fatal("By default connection should not be verified")
	}

	splunkLoggerDriver, ok := loggerDriver.(*splunkLoggerInline)
	if !ok {
		t.Fatal("Unexpected Splunk Logging Driver type")
	}

	if splunkLoggerDriver.hec.url != hec.URL()+"/services/collector/event/1.0" ||
		splunkLoggerDriver.hec.auth != "Splunk "+hec.token ||
		splunkLoggerDriver.nullMessage.Host != hostname ||
		splunkLoggerDriver.nullMessage.Source != "" ||
		splunkLoggerDriver.nullMessage.SourceType != "splunk_connect_docker" ||
		splunkLoggerDriver.nullMessage.Index != "" ||
		splunkLoggerDriver.hec.gzipCompression != false ||
		splunkLoggerDriver.hec.postMessagesFrequency != defaultPostMessagesFrequency ||
		splunkLoggerDriver.hec.postMessagesBatchSize != defaultPostMessagesBatchSize ||
		splunkLoggerDriver.hec.bufferMaximum != defaultBufferMaximum ||
		splunkLoggerDriver.hec.retryBackoffInitial != defaultPostMessagesFrequency ||
		splunkLoggerDriver.hec.retryBackoffMax != defaultRetryBackoffMax ||
		splunkLoggerDriver.hec.client.Timeout != defaultHTTPTimeout ||
		cap(splunkLoggerDriver.stream) != defaultStreamChannelSize {
		t.Fatal("Found not default values setup in Splunk Logging Driver.")
	}

	message1Time := time.Now()
	if err := loggerDriver.Log(&logger.Message{Line: []byte("{\"a\":\"b\"}"), Source: "stdout", Timestamp: message1Time}); err != nil {
		t.Fatal(err)
	}
	message2Time := time.Now()
	if err := loggerDriver.Log(&logger.Message{Line: []byte("notajson"), Source: "stdout", Timestamp: message2Time}); err != nil {
		t.Fatal(err)
	}

	err = loggerDriver.Close()
	if err != nil {
		t.Fatal(err)
	}

	if len(hec.messages) != 2 {
		t.Fatalf("Unexpected values of messages: %v", len(hec.messages))
		//t.Fatal("Expected two messages")
	}

	if *hec.gzipEnabled {
		t.Fatal("Gzip should not be used")
	}

	message1 := hec.messages[0]
	if message1.Time != fmt.Sprintf("%f", float64(message1Time.UnixNano())/float64(time.Second)) ||
		message1.Host != hostname ||
		message1.Source != "" ||
		message1.SourceType != "splunk_connect_docker" ||
		message1.Index != "" {
		t.Fatalf("Unexpected values of message 1 %v", message1)
	}

	if event, err := message1.EventAsMap(); err != nil {
		t.Fatal(err)
	} else {
		if event["line"] != "{\"a\":\"b\"}" ||
			event["source"] != "stdout" ||
			event["tag"] != "containeriid" ||
			len(event) != 3 {
			t.Fatalf("Unexpected event in message %v", event)
		}
	}

	message2 := hec.messages[1]
	if message2.Time != fmt.Sprintf("%f", float64(message2Time.UnixNano())/float64(time.Second)) ||
		message2.Host != hostname ||
		message2.Source != "" ||
		message2.SourceType != "splunk_connect_docker" ||
		message2.Index != "" {
		t.Fatalf("Unexpected values of message 1 %v", message2)
	}

	if event, err := message2.EventAsMap(); err != nil {
		t.Fatal(err)
	} else {
		if event["line"] != "notajson" ||
			event["source"] != "stdout" ||
			event["tag"] != "containeriid" ||
			len(event) != 3 {
			t.Fatalf("Unexpected event in message %v", event)
		}
	}

	err = hec.Close()
	if err != nil {
		t.Fatal(err)
	}
}

// Verify inline format with a not default settings for most of options
func TestInlineFormatWithNonDefaultOptions(t *testing.T) {
	hec := NewHTTPEventCollectorMock(t)

	go hec.Serve()

	info := logger.Info{
		Config: map[string]string{
			splunkURLKey:             hec.URL(),
			splunkTokenKey:           hec.token,
			splunkSourceKey:          "mysource",
			splunkSourceTypeKey:      "mysourcetype",
			splunkIndexKey:           "myindex",
			splunkFormatKey:          splunkFormatInline,
			splunkGzipCompressionKey: "true",
			tagKey:      "{{.ImageName}}/{{.Name}}",
			labelsKey:   "a",
			envRegexKey: "^foo",
		},
		ContainerID:        "containeriid",
		ContainerName:      "/container_name",
		ContainerImageID:   "contaimageid",
		ContainerImageName: "container_image_name",
		ContainerLabels: map[string]string{
			"a": "b",
		},
		ContainerEnv: []string{"foo_finder=bar"},
	}

	hostname, err := info.Hostname()
	if err != nil {
		t.Fatal(err)
	}

	loggerDriver, err := New(info)
	if err != nil {
		t.Fatal(err)
	}

	if hec.connectionVerified {
		t.Fatal("By default connection should not be verified")
	}

	splunkLoggerDriver, ok := loggerDriver.(*splunkLoggerInline)
	if !ok {
		t.Fatal("Unexpected Splunk Logging Driver type")
	}

	if splunkLoggerDriver.hec.url != hec.URL()+"/services/collector/event/1.0" ||
		splunkLoggerDriver.hec.auth != "Splunk "+hec.token ||
		splunkLoggerDriver.nullMessage.Host != hostname ||
		splunkLoggerDriver.nullMessage.Source != "mysource" ||
		splunkLoggerDriver.nullMessage.SourceType != "mysourcetype" ||
		splunkLoggerDriver.nullMessage.Index != "myindex" ||
		splunkLoggerDriver.hec.gzipCompression != true ||
		splunkLoggerDriver.hec.gzipCompressionLevel != gzip.DefaultCompression ||
		splunkLoggerDriver.hec.postMessagesFrequency != defaultPostMessagesFrequency ||
		splunkLoggerDriver.hec.postMessagesBatchSize != defaultPostMessagesBatchSize ||
		splunkLoggerDriver.hec.bufferMaximum != defaultBufferMaximum ||
		splunkLoggerDriver.hec.retryBackoffInitial != defaultPostMessagesFrequency ||
		splunkLoggerDriver.hec.retryBackoffMax != defaultRetryBackoffMax ||
		splunkLoggerDriver.hec.client.Timeout != defaultHTTPTimeout ||
		cap(splunkLoggerDriver.stream) != defaultStreamChannelSize {
		t.Fatal("Values do not match configuration.")
	}

	messageTime := time.Now()
	if err := loggerDriver.Log(&logger.Message{Line: []byte("1"), Source: "stdout", Timestamp: messageTime}); err != nil {
		t.Fatal(err)
	}

	err = loggerDriver.Close()
	if err != nil {
		t.Fatal(err)
	}

	if len(hec.messages) != 1 {
		t.Fatal("Expected one message")
	}

	if !*hec.gzipEnabled {
		t.Fatal("Gzip should be used")
	}

	message := hec.messages[0]
	if message.Time != fmt.Sprintf("%f", float64(messageTime.UnixNano())/float64(time.Second)) ||
		message.Host != hostname ||
		message.Source != "mysource" ||
		message.SourceType != "mysourcetype" ||
		message.Index != "myindex" {
		t.Fatalf("Unexpected values of message %v", message)
	}

	if event, err := message.EventAsMap(); err != nil {
		t.Fatal(err)
	} else {
		if event["line"] != "1" ||
			event["source"] != "stdout" ||
			event["tag"] != "container_image_name/container_name" ||
			event["attrs"].(map[string]interface{})["a"] != "b" ||
			event["attrs"].(map[string]interface{})["foo_finder"] != "bar" ||
			len(event) != 4 {
			t.Fatalf("Unexpected event in message %v", event)
		}
	}

	err = hec.Close()
	if err != nil {
		t.Fatal(err)
	}
}

// Verify JSON format
func TestJsonFormat(t *testing.T) {
	hec := NewHTTPEventCollectorMock(t)

	go hec.Serve()

	info := logger.Info{
		Config: map[string]string{
			splunkURLKey:                  hec.URL(),
			splunkTokenKey:                hec.token,
			splunkFormatKey:               splunkFormatJSON,
			splunkGzipCompressionKey:      "true",
			splunkGzipCompressionLevelKey: "1",
		},
		ContainerID:        "containeriid",
		ContainerName:      "/container_name",
		ContainerImageID:   "contaimageid",
		ContainerImageName: "container_image_name",
	}

	hostname, err := info.Hostname()
	if err != nil {
		t.Fatal(err)
	}

	loggerDriver, err := New(info)
	if err != nil {
		t.Fatal(err)
	}

	if hec.connectionVerified {
		t.Fatal("By default connection should not be verified")
	}

	splunkLoggerDriver, ok := loggerDriver.(*splunkLoggerJSON)
	if !ok {
		t.Fatal("Unexpected Splunk Logging Driver type")
	}

	if splunkLoggerDriver.hec.url != hec.URL()+"/services/collector/event/1.0" ||
		splunkLoggerDriver.hec.auth != "Splunk "+hec.token ||
		splunkLoggerDriver.nullMessage.Host != hostname ||
		splunkLoggerDriver.nullMessage.Source != "" ||
		splunkLoggerDriver.nullMessage.SourceType != "splunk_connect_docker" ||
		splunkLoggerDriver.nullMessage.Index != "" ||
		splunkLoggerDriver.hec.gzipCompression != true ||
		splunkLoggerDriver.hec.gzipCompressionLevel != gzip.BestSpeed ||
		splunkLoggerDriver.hec.postMessagesFrequency != defaultPostMessagesFrequency ||
		splunkLoggerDriver.hec.postMessagesBatchSize != defaultPostMessagesBatchSize ||
		splunkLoggerDriver.hec.bufferMaximum != defaultBufferMaximum ||
		splunkLoggerDriver.hec.retryBackoffInitial != defaultPostMessagesFrequency ||
		splunkLoggerDriver.hec.retryBackoffMax != defaultRetryBackoffMax ||
		splunkLoggerDriver.hec.client.Timeout != defaultHTTPTimeout ||
		cap(splunkLoggerDriver.stream) != defaultStreamChannelSize {
		t.Fatal("Values do not match configuration.")
	}

	message1Time := time.Now()
	if err := loggerDriver.Log(&logger.Message{Line: []byte("{\"a\":\"b\"}"), Source: "stdout", Timestamp: message1Time}); err != nil {
		t.Fatal(err)
	}
	message2Time := time.Now()
	if err := loggerDriver.Log(&logger.Message{Line: []byte("notjson"), Source: "stdout", Timestamp: message2Time}); err != nil {
		t.Fatal(err)
	}

	err = loggerDriver.Close()
	if err != nil {
		t.Fatal(err)
	}

	if len(hec.messages) != 2 {
		t.Fatal("Expected two messages")
	}

	message1 := hec.messages[0]
	if message1.Time != fmt.Sprintf("%f", float64(message1Time.UnixNano())/float64(time.Second)) ||
		message1.Host != hostname ||
		message1.Source != "" ||
		message1.SourceType != "splunk_connect_docker" ||
		message1.Index != "" {
		t.Fatalf("Unexpected values of message 1 %v", message1)
	}

	if event, err := message1.EventAsMap(); err != nil {
		t.Fatal(err)
	} else {
		if event["line"].(map[string]interface{})["a"] != "b" ||
			event["source"] != "stdout" ||
			event["tag"] != "containeriid" ||
			len(event) != 3 {
			t.Fatalf("Unexpected event in message 1 %v", event)
		}
	}

	message2 := hec.messages[1]
	if message2.Time != fmt.Sprintf("%f", float64(message2Time.UnixNano())/float64(time.Second)) ||
		message2.Host != hostname ||
		message2.Source != "" ||
		message2.SourceType != "splunk_connect_docker" ||
		message2.Index != "" {
		t.Fatalf("Unexpected values of message 2 %v", message2)
	}

	// If message cannot be parsed as JSON - it should be sent as a line
	if event, err := message2.EventAsMap(); err != nil {
		t.Fatal(err)
	} else {
		if event["line"] != "notjson" ||
			event["source"] != "stdout" ||
			event["tag"] != "containeriid" ||
			len(event) != 3 {
			t.Fatalf("Unexpected event in message 2 %v", event)
		}
	}

	err = hec.Close()
	if err != nil {
		t.Fatal(err)
	}
}

// Verify raw format
func TestRawFormat(t *testing.T) {
	hec := NewHTTPEventCollectorMock(t)

	go hec.Serve()

	info := logger.Info{
		Config: map[string]string{
			splunkURLKey:    hec.URL(),
			splunkTokenKey:  hec.token,
			splunkFormatKey: splunkFormatRaw,
		},
		ContainerID:        "containeriid",
		ContainerName:      "/container_name",
		ContainerImageID:   "contaimageid",
		ContainerImageName: "container_image_name",
	}

	hostname, err := info.Hostname()
	if err != nil {
		t.Fatal(err)
	}

	loggerDriver, err := New(info)
	if err != nil {
		t.Fatal(err)
	}

	if hec.connectionVerified {
		t.Fatal("By default connection should not be verified")
	}

	splunkLoggerDriver, ok := loggerDriver.(*splunkLoggerRaw)
	if !ok {
		t.Fatal("Unexpected Splunk Logging Driver type")
	}

	if splunkLoggerDriver.hec.url != hec.URL()+"/services/collector/event/1.0" ||
		splunkLoggerDriver.hec.auth != "Splunk "+hec.token ||
		splunkLoggerDriver.nullMessage.Host != hostname ||
		splunkLoggerDriver.nullMessage.Source != "" ||
		splunkLoggerDriver.nullMessage.SourceType != "splunk_connect_docker" ||
		splunkLoggerDriver.nullMessage.Index != "" ||
		splunkLoggerDriver.hec.gzipCompression != false ||
		splunkLoggerDriver.hec.postMessagesFrequency != defaultPostMessagesFrequency ||
		splunkLoggerDriver.hec.postMessagesBatchSize != defaultPostMessagesBatchSize ||
		splunkLoggerDriver.hec.bufferMaximum != defaultBufferMaximum ||
		splunkLoggerDriver.hec.retryBackoffInitial != defaultPostMessagesFrequency ||
		splunkLoggerDriver.hec.retryBackoffMax != defaultRetryBackoffMax ||
		splunkLoggerDriver.hec.client.Timeout != defaultHTTPTimeout ||
		cap(splunkLoggerDriver.stream) != defaultStreamChannelSize ||
		string(splunkLoggerDriver.prefix) != "containeriid " {
		t.Fatal("Values do not match configuration.")
	}

	message1Time := time.Now()
	if err := loggerDriver.Log(&logger.Message{Line: []byte("{\"a\":\"b\"}"), Source: "stdout", Timestamp: message1Time}); err != nil {
		t.Fatal(err)
	}
	message2Time := time.Now()
	if err := loggerDriver.Log(&logger.Message{Line: []byte("notjson"), Source: "stdout", Timestamp: message2Time}); err != nil {
		t.Fatal(err)
	}

	err = loggerDriver.Close()
	if err != nil {
		t.Fatal(err)
	}

	if len(hec.messages) != 2 {
		t.Fatal("Expected two messages")
	}

	message1 := hec.messages[0]
	if message1.Time != fmt.Sprintf("%f", float64(message1Time.UnixNano())/float64(time.Second)) ||
		message1.Host != hostname ||
		message1.Source != "" ||
		message1.SourceType != "splunk_connect_docker" ||
		message1.Index != "" {
		t.Fatalf("Unexpected values of message 1 %v", message1)
	}

	if event, err := message1.EventAsString(); err != nil {
		t.Fatal(err)
	} else {
		if event != "containeriid {\"a\":\"b\"}" {
			t.Fatalf("Unexpected event in message 1 %v", event)
		}
	}

	message2 := hec.messages[1]
	if message2.Time != fmt.Sprintf("%f", float64(message2Time.UnixNano())/float64(time.Second)) ||
		message2.Host != hostname ||
		message2.Source != "" ||
		message2.SourceType != "splunk_connect_docker" ||
		message2.Index != "" {
		t.Fatalf("Unexpected values of message 2 %v", message2)
	}

	if event, err := message2.EventAsString(); err != nil {
		t.Fatal(err)
	} else {
		if event != "containeriid notjson" {
			t.Fatalf("Unexpected event in message 1 %v", event)
		}
	}

	err = hec.Close()
	if err != nil {
		t.Fatal(err)
	}
}

// Verify raw format with labels
func TestRawFormatWithLabels(t *testing.T) {
	hec := NewHTTPEventCollectorMock(t)

	go hec.Serve()

	info := logger.Info{
		Config: map[string]string{
			splunkURLKey:    hec.URL(),
			splunkTokenKey:  hec.token,
			splunkFormatKey: splunkFormatRaw,
			labelsKey:       "a",
		},
		ContainerID:        "containeriid",
		ContainerName:      "/container_name",
		ContainerImageID:   "contaimageid",
		ContainerImageName: "container_image_name",
		ContainerLabels: map[string]string{
			"a": "b",
		},
	}

	hostname, err := info.Hostname()
	if err != nil {
		t.Fatal(err)
	}

	loggerDriver, err := New(info)
	if err != nil {
		t.Fatal(err)
	}

	if hec.connectionVerified {
		t.Fatal("By default connection should not be verified")
	}

	splunkLoggerDriver, ok := loggerDriver.(*splunkLoggerRaw)
	if !ok {
		t.Fatal("Unexpected Splunk Logging Driver type")
	}

	if splunkLoggerDriver.hec.url != hec.URL()+"/services/collector/event/1.0" ||
		splunkLoggerDriver.hec.auth != "Splunk "+hec.token ||
		splunkLoggerDriver.nullMessage.Host != hostname ||
		splunkLoggerDriver.nullMessage.Source != "" ||
		splunkLoggerDriver.nullMessage.SourceType != "splunk_connect_docker" ||
		splunkLoggerDriver.nullMessage.Index != "" ||
		splunkLoggerDriver.hec.gzipCompression != false ||
		splunkLoggerDriver.hec.postMessagesFrequency != defaultPostMessagesFrequency ||
		splunkLoggerDriver.hec.postMessagesBatchSize != defaultPostMessagesBatchSize ||
		splunkLoggerDriver.hec.bufferMaximum != defaultBufferMaximum ||
		splunkLoggerDriver.hec.retryBackoffInitial != defaultPostMessagesFrequency ||
		splunkLoggerDriver.hec.retryBackoffMax != defaultRetryBackoffMax ||
		splunkLoggerDriver.hec.client.Timeout != defaultHTTPTimeout ||
		cap(splunkLoggerDriver.stream) != defaultStreamChannelSize ||
		string(splunkLoggerDriver.prefix) != "containeriid a=b " {
		t.Fatal("Values do not match configuration.")
	}

	message1Time := time.Now()
	if err := loggerDriver.Log(&logger.Message{Line: []byte("{\"a\":\"b\"}"), Source: "stdout", Timestamp: message1Time}); err != nil {
		t.Fatal(err)
	}
	message2Time := time.Now()
	if err := loggerDriver.Log(&logger.Message{Line: []byte("notjson"), Source: "stdout", Timestamp: message2Time}); err != nil {
		t.Fatal(err)
	}

	err = loggerDriver.Close()
	if err != nil {
		t.Fatal(err)
	}

	if len(hec.messages) != 2 {
		t.Fatal("Expected two messages")
	}

	message1 := hec.messages[0]
	if message1.Time != fmt.Sprintf("%f", float64(message1Time.UnixNano())/float64(time.Second)) ||
		message1.Host != hostname ||
		message1.Source != "" ||
		message1.SourceType != "splunk_connect_docker" ||
		message1.Index != "" {
		t.Fatalf("Unexpected values of message 1 %v", message1)
	}

	if event, err := message1.EventAsString(); err != nil {
		t.Fatal(err)
	} else {
		if event != "containeriid a=b {\"a\":\"b\"}" {
			t.Fatalf("Unexpected event in message 1 %v", event)
		}
	}

	message2 := hec.messages[1]
	if message2.Time != fmt.Sprintf("%f", float64(message2Time.UnixNano())/float64(time.Second)) ||
		message2.Host != hostname ||
		message2.Source != "" ||
		message2.SourceType != "splunk_connect_docker" ||
		message2.Index != "" {
		t.Fatalf("Unexpected values of message 2 %v", message2)
	}

	if event, err := message2.EventAsString(); err != nil {
		t.Fatal(err)
	} else {
		if event != "containeriid a=b notjson" {
			t.Fatalf("Unexpected event in message 2 %v", event)
		}
	}

	err = hec.Close()
	if err != nil {
		t.Fatal(err)
	}
}

// Verify that Splunk Logging Driver can accept tag="" which will allow to send raw messages
// in the same way we get them in stdout/stderr
func TestRawFormatWithoutTag(t *testing.T) {
	hec := NewHTTPEventCollectorMock(t)

	go hec.Serve()

	info := logger.Info{
		Config: map[string]string{
			splunkURLKey:    hec.URL(),
			splunkTokenKey:  hec.token,
			splunkFormatKey: splunkFormatRaw,
			tagKey:          "",
		},
		ContainerID:        "containeriid",
		ContainerName:      "/container_name",
		ContainerImageID:   "contaimageid",
		ContainerImageName: "container_image_name",
	}

	hostname, err := info.Hostname()
	if err != nil {
		t.Fatal(err)
	}

	loggerDriver, err := New(info)
	if err != nil {
		t.Fatal(err)
	}

	if hec.connectionVerified {
		t.Fatal("By default connection should not be verified")
	}

	splunkLoggerDriver, ok := loggerDriver.(*splunkLoggerRaw)
	if !ok {
		t.Fatal("Unexpected Splunk Logging Driver type")
	}

	if splunkLoggerDriver.hec.url != hec.URL()+"/services/collector/event/1.0" ||
		splunkLoggerDriver.hec.auth != "Splunk "+hec.token ||
		splunkLoggerDriver.nullMessage.Host != hostname ||
		splunkLoggerDriver.nullMessage.Source != "" ||
		splunkLoggerDriver.nullMessage.SourceType != "splunk_connect_docker" ||
		splunkLoggerDriver.nullMessage.Index != "" ||
		splunkLoggerDriver.hec.gzipCompression != false ||
		splunkLoggerDriver.hec.postMessagesFrequency != defaultPostMessagesFrequency ||
		splunkLoggerDriver.hec.postMessagesBatchSize != defaultPostMessagesBatchSize ||
		splunkLoggerDriver.hec.bufferMaximum != defaultBufferMaximum ||
		splunkLoggerDriver.hec.retryBackoffInitial != defaultPostMessagesFrequency ||
		splunkLoggerDriver.hec.retryBackoffMax != defaultRetryBackoffMax ||
		splunkLoggerDriver.hec.client.Timeout != defaultHTTPTimeout ||
		cap(splunkLoggerDriver.stream) != defaultStreamChannelSize ||
		string(splunkLoggerDriver.prefix) != "" {
		t.Log(string(splunkLoggerDriver.prefix) + "a")
		t.Fatal("Values do not match configuration.")
	}

	message1Time := time.Now()
	if err := loggerDriver.Log(&logger.Message{Line: []byte("{\"a\":\"b\"}"), Source: "stdout", Timestamp: message1Time}); err != nil {
		t.Fatal(err)
	}
	message2Time := time.Now()
	if err := loggerDriver.Log(&logger.Message{Line: []byte("notjson"), Source: "stdout", Timestamp: message2Time}); err != nil {
		t.Fatal(err)
	}

	err = loggerDriver.Close()
	if err != nil {
		t.Fatal(err)
	}

	if len(hec.messages) != 2 {
		t.Fatal("Expected two messages")
	}

	message1 := hec.messages[0]
	if message1.Time != fmt.Sprintf("%f", float64(message1Time.UnixNano())/float64(time.Second)) ||
		message1.Host != hostname ||
		message1.Source != "" ||
		message1.SourceType != "splunk_connect_docker" ||
		message1.Index != "" {
		t.Fatalf("Unexpected values of message 1 %v", message1)
	}

	if event, err := message1.EventAsString(); err != nil {
		t.Fatal(err)
	} else {
		if event != "{\"a\":\"b\"}" {
			t.Fatalf("Unexpected event in message 1 %v", event)
		}
	}

	message2 := hec.messages[1]
	if message2.Time != fmt.Sprintf("%f", float64(message2Time.UnixNano())/float64(time.Second)) ||
		message2.Host != hostname ||
		message2.Source != "" ||
		message2.SourceType != "splunk_connect_docker" ||
		message2.Index != "" {
		t.Fatalf("Unexpected values of message 2 %v", message2)
	}

	if event, err := message2.EventAsString(); err != nil {
		t.Fatal(err)
	} else {
		if event != "notjson" {
			t.Fatalf("Unexpected event in message 2 %v", event)
		}
	}

	err = hec.Close()
	if err != nil {
		t.Fatal(err)
	}
}

// Verify that we will send messages in batches with default batching parameters,
// but change frequency to be sure that numOfRequests will match expected 17 requests
func TestBatching(t *testing.T) {
	if err := os.Setenv(envVarPostMessagesFrequency, "10h"); err != nil {
		t.Fatal(err)
	}

	hec := NewHTTPEventCollectorMock(t)

	go hec.Serve()

	info := logger.Info{
		Config: map[string]string{
			splunkURLKey:   hec.URL(),
			splunkTokenKey: hec.token,
		},
		ContainerID:        "containeriid",
		ContainerName:      "/container_name",
		ContainerImageID:   "contaimageid",
		ContainerImageName: "container_image_name",
	}

	loggerDriver, err := New(info)
	if err != nil {
		t.Fatal(err)
	}

	for i := 0; i < defaultStreamChannelSize*4; i++ {
		if err := loggerDriver.Log(&logger.Message{Line: []byte(fmt.Sprintf("%d", i)), Source: "stdout", Timestamp: time.Now()}); err != nil {
			t.Fatal(err)
		}
	}

	err = loggerDriver.Close()
	if err != nil {
		t.Fatal(err)
	}

	if len(hec.messages) != defaultStreamChannelSize*4 {
		t.Fatal("Not all messages delivered")
	}

	for i, message := range hec.messages {
		if event, err := message.EventAsMap(); err != nil {
			t.Fatal(err)
		} else {
			if event["line"] != fmt.Sprintf("%d", i) {
				t.Fatalf("Unexpected event in message %v", event)
			}
		}
	}

	// 16 batches
	if hec.requestCount() != 16 {
		t.Fatalf("Unexpected number of requests %d", hec.requestCount())
	}

	err = hec.Close()
	if err != nil {
		t.Fatal(err)
	}

	if err := os.Setenv(envVarPostMessagesFrequency, ""); err != nil {
		t.Fatal(err)
	}
}

// Verify that test is using time to fire events not rare than specified frequency
func TestFrequency(t *testing.T) {
	if err := os.Setenv(envVarPostMessagesFrequency, "5ms"); err != nil {
		t.Fatal(err)
	}

	hec := NewHTTPEventCollectorMock(t)

	go hec.Serve()

	info := logger.Info{
		Config: map[string]string{
			splunkURLKey:   hec.URL(),
			splunkTokenKey: hec.token,
		},
		ContainerID:        "containeriid",
		ContainerName:      "/container_name",
		ContainerImageID:   "contaimageid",
		ContainerImageName: "container_image_name",
	}

	loggerDriver, err := New(info)
	if err != nil {
		t.Fatal(err)
	}

	for i := 0; i < 10; i++ {
		if err := loggerDriver.Log(&logger.Message{Line: []byte(fmt.Sprintf("%d", i)), Source: "stdout", Timestamp: time.Now()}); err != nil {
			t.Fatal(err)
		}
		time.Sleep(15 * time.Millisecond)
	}

	err = loggerDriver.Close()
	if err != nil {
		t.Fatal(err)
	}

	if len(hec.messages) != 10 {
		t.Fatal("Not all messages delivered")
	}

	for i, message := range hec.messages {
		if event, err := message.EventAsMap(); err != nil {
			t.Fatal(err)
		} else {
			if event["line"] != fmt.Sprintf("%d", i) {
				t.Fatalf("Unexpected event in message %v", event)
			}
		}
	}

	// 1 to verify connection and 10 to verify that we have sent messages with required frequency,
	// but because frequency is too small (to keep test quick), instead of 11, use 9 if context switches will be slow
	if hec.requestCount() < 9 {
		t.Fatalf("Unexpected number of requests %d", hec.requestCount())
	}

	err = hec.Close()
	if err != nil {
		t.Fatal(err)
	}

	if err := os.Setenv(envVarPostMessagesFrequency, ""); err != nil {
		t.Fatal(err)
	}
}

// Simulate behavior similar to first version of Splunk Logging Driver, when we were sending one message
// per request
func TestOneMessagePerRequest(t *testing.T) {
	if err := os.Setenv(envVarPostMessagesFrequency, "10h"); err != nil {
		t.Fatal(err)
	}

	if err := os.Setenv(envVarPostMessagesBatchSize, "1"); err != nil {
		t.Fatal(err)
	}

	if err := os.Setenv(envVarBufferMaximum, "1"); err != nil {
		t.Fatal(err)
	}

	if err := os.Setenv(envVarStreamChannelSize, "0"); err != nil {
		t.Fatal(err)
	}

	hec := NewHTTPEventCollectorMock(t)

	go hec.Serve()

	info := logger.Info{
		Config: map[string]string{
			splunkURLKey:   hec.URL(),
			splunkTokenKey: hec.token,
		},
		ContainerID:        "containeriid",
		ContainerName:      "/container_name",
		ContainerImageID:   "contaimageid",
		ContainerImageName: "container_image_name",
	}

	loggerDriver, err := New(info)
	if err != nil {
		t.Fatal(err)
	}

	for i := 0; i < 10; i++ {
		if err := loggerDriver.Log(&logger.Message{Line: []byte(fmt.Sprintf("%d", i)), Source: "stdout", Timestamp: time.Now()}); err != nil {
			t.Fatal(err)
		}
	}

	err = loggerDriver.Close()
	if err != nil {
		t.Fatal(err)
	}

	if len(hec.messages) != 10 {
		t.Fatal("Not all messages delivered")
	}

	for i, message := range hec.messages {
		if event, err := message.EventAsMap(); err != nil {
			t.Fatal(err)
		} else {
			if event["line"] != fmt.Sprintf("%d", i) {
				t.Fatalf("Unexpected event in message %v", event)
			}
		}
	}

	// 10 messages
	if hec.requestCount() != 10 {
		t.Fatalf("Unexpected number of requests %d", hec.requestCount())
	}

	err = hec.Close()
	if err != nil {
		t.Fatal(err)
	}

	if err := os.Setenv(envVarPostMessagesFrequency, ""); err != nil {
		t.Fatal(err)
	}

	if err := os.Setenv(envVarPostMessagesBatchSize, ""); err != nil {
		t.Fatal(err)
	}

	if err := os.Setenv(envVarBufferMaximum, ""); err != nil {
		t.Fatal(err)
	}

	if err := os.Setenv(envVarStreamChannelSize, ""); err != nil {
		t.Fatal(err)
	}
}

// Driver should not be created when HEC is unresponsive
func TestVerify(t *testing.T) {
	hec := NewHTTPEventCollectorMock(t)
	hec.setServerError(true)
	go hec.Serve()

	info := logger.Info{
		Config: map[string]string{
			splunkURLKey:              hec.URL(),
			splunkTokenKey:            hec.token,
			splunkVerifyConnectionKey: "true",
		},
		ContainerID:        "containeriid",
		ContainerName:      "/container_name",
		ContainerImageID:   "contaimageid",
		ContainerImageName: "container_image_name",
	}

	_, err := New(info)
	if err == nil {
		t.Fatal("Expecting driver to fail, when server is unresponsive")
	}

	err = hec.Close()
	if err != nil {
		t.Fatal(err)
	}
}

// disableRetryBackoff makes the driver retry immediately after every failure,
// matching the legacy behavior where the retry cadence was not backed off.
func disableRetryBackoff(t *testing.T) {
	t.Helper()
	if err := os.Setenv(envVarRetryBackoffInitial, "0s"); err != nil {
		t.Fatal(err)
	}
	if err := os.Setenv(envVarRetryBackoffMax, "0s"); err != nil {
		t.Fatal(err)
	}
}

func restoreRetryBackoff(t *testing.T) {
	t.Helper()
	if err := os.Setenv(envVarRetryBackoffInitial, ""); err != nil {
		t.Fatal(err)
	}
	if err := os.Setenv(envVarRetryBackoffMax, ""); err != nil {
		t.Fatal(err)
	}
}

// Verify that user can specify to skip verification that Splunk HEC is working.
// Also in this test we verify retry logic.
func TestSkipVerify(t *testing.T) {
	disableRetryBackoff(t)
	defer restoreRetryBackoff(t)

	hec := NewHTTPEventCollectorMock(t)
	hec.setServerError(true)
	go hec.Serve()

	info := logger.Info{
		Config: map[string]string{
			splunkURLKey:              hec.URL(),
			splunkTokenKey:            hec.token,
			splunkVerifyConnectionKey: "false",
		},
		ContainerID:        "containeriid",
		ContainerName:      "/container_name",
		ContainerImageID:   "contaimageid",
		ContainerImageName: "container_image_name",
	}

	loggerDriver, err := New(info)
	if err != nil {
		t.Fatal(err)
	}

	if hec.connectionVerified {
		t.Fatal("Connection should not be verified")
	}

	for i := 0; i < defaultStreamChannelSize*2; i++ {
		if err := loggerDriver.Log(&logger.Message{Line: []byte(fmt.Sprintf("%d", i)), Source: "stdout", Timestamp: time.Now()}); err != nil {
			t.Fatal(err)
		}
	}

	if len(hec.messages) != 0 {
		t.Fatal("No messages should be accepted at this point")
	}

	hec.setServerError(false)

	for i := defaultStreamChannelSize * 2; i < defaultStreamChannelSize*4; i++ {
		if err := loggerDriver.Log(&logger.Message{Line: []byte(fmt.Sprintf("%d", i)), Source: "stdout", Timestamp: time.Now()}); err != nil {
			t.Fatal(err)
		}
	}

	err = loggerDriver.Close()
	if err != nil {
		t.Fatal(err)
	}

	if len(hec.messages) != defaultStreamChannelSize*4 {
		t.Fatal("Not all messages delivered")
	}

	for i, message := range hec.messages {
		if event, err := message.EventAsMap(); err != nil {
			t.Fatal(err)
		} else {
			if event["line"] != fmt.Sprintf("%d", i) {
				t.Fatalf("Unexpected event in message %v", event)
			}
		}
	}

	err = hec.Close()
	if err != nil {
		t.Fatal(err)
	}
}

// Verify logic for when we filled whole buffer
func TestBufferMaximum(t *testing.T) {
	disableRetryBackoff(t)
	defer restoreRetryBackoff(t)

	if err := os.Setenv(envVarPostMessagesBatchSize, "2"); err != nil {
		t.Fatal(err)
	}

	if err := os.Setenv(envVarBufferMaximum, "10"); err != nil {
		t.Fatal(err)
	}

	if err := os.Setenv(envVarStreamChannelSize, "0"); err != nil {
		t.Fatal(err)
	}

	hec := NewHTTPEventCollectorMock(t)
	hec.setServerError(true)
	go hec.Serve()

	info := logger.Info{
		Config: map[string]string{
			splunkURLKey:              hec.URL(),
			splunkTokenKey:            hec.token,
			splunkVerifyConnectionKey: "false",
		},
		ContainerID:        "containeriid",
		ContainerName:      "/container_name",
		ContainerImageID:   "contaimageid",
		ContainerImageName: "container_image_name",
	}

	loggerDriver, err := New(info)
	if err != nil {
		t.Fatal(err)
	}

	if hec.connectionVerified {
		t.Fatal("Connection should not be verified")
	}

	for i := 0; i < 11; i++ {
		if err := loggerDriver.Log(&logger.Message{Line: []byte(fmt.Sprintf("%d", i)), Source: "stdout", Timestamp: time.Now()}); err != nil {
			t.Fatal(err)
		}
	}

	if len(hec.messages) != 0 {
		t.Fatal("No messages should be accepted at this point")
	}

	hec.setServerError(false)

	err = loggerDriver.Close()
	if err != nil {
		t.Fatal(err)
	}

	if len(hec.messages) != 9 {
		t.Fatalf("Expected # of messages %d, got %d", 9, len(hec.messages))
	}

	// First 1000 messages are written to daemon log when buffer was full
	for i, message := range hec.messages {
		if event, err := message.EventAsMap(); err != nil {
			t.Fatal(err)
		} else {
			if event["line"] != fmt.Sprintf("%d", i+2) {
				t.Fatalf("Unexpected event in message %v", event)
			}
		}
	}

	err = hec.Close()
	if err != nil {
		t.Fatal(err)
	}

	if err := os.Setenv(envVarPostMessagesBatchSize, ""); err != nil {
		t.Fatal(err)
	}

	if err := os.Setenv(envVarBufferMaximum, ""); err != nil {
		t.Fatal(err)
	}

	if err := os.Setenv(envVarStreamChannelSize, ""); err != nil {
		t.Fatal(err)
	}
}

// Verify that we are not blocking close when HEC is down for the whole time
func TestServerAlwaysDown(t *testing.T) {
	disableRetryBackoff(t)
	defer restoreRetryBackoff(t)

	if err := os.Setenv(envVarPostMessagesBatchSize, "2"); err != nil {
		t.Fatal(err)
	}

	if err := os.Setenv(envVarBufferMaximum, "4"); err != nil {
		t.Fatal(err)
	}

	if err := os.Setenv(envVarStreamChannelSize, "0"); err != nil {
		t.Fatal(err)
	}

	hec := NewHTTPEventCollectorMock(t)
	hec.setServerError(true)
	go hec.Serve()

	info := logger.Info{
		Config: map[string]string{
			splunkURLKey:              hec.URL(),
			splunkTokenKey:            hec.token,
			splunkVerifyConnectionKey: "false",
		},
		ContainerID:        "containeriid",
		ContainerName:      "/container_name",
		ContainerImageID:   "contaimageid",
		ContainerImageName: "container_image_name",
	}

	loggerDriver, err := New(info)
	if err != nil {
		t.Fatal(err)
	}

	if hec.connectionVerified {
		t.Fatal("Connection should not be verified")
	}

	for i := 0; i < 5; i++ {
		if err := loggerDriver.Log(&logger.Message{Line: []byte(fmt.Sprintf("%d", i)), Source: "stdout", Timestamp: time.Now()}); err != nil {
			t.Fatal(err)
		}
	}

	err = loggerDriver.Close()
	if err != nil {
		t.Fatal(err)
	}

	if len(hec.messages) != 0 {
		t.Fatal("No messages should be sent")
	}

	err = hec.Close()
	if err != nil {
		t.Fatal(err)
	}

	if err := os.Setenv(envVarPostMessagesBatchSize, ""); err != nil {
		t.Fatal(err)
	}

	if err := os.Setenv(envVarBufferMaximum, ""); err != nil {
		t.Fatal(err)
	}

	if err := os.Setenv(envVarStreamChannelSize, ""); err != nil {
		t.Fatal(err)
	}
}

// Cannot send messages after we close driver
func TestCannotSendAfterClose(t *testing.T) {
	hec := NewHTTPEventCollectorMock(t)
	go hec.Serve()

	info := logger.Info{
		Config: map[string]string{
			splunkURLKey:   hec.URL(),
			splunkTokenKey: hec.token,
		},
		ContainerID:        "containeriid",
		ContainerName:      "/container_name",
		ContainerImageID:   "contaimageid",
		ContainerImageName: "container_image_name",
	}

	loggerDriver, err := New(info)
	if err != nil {
		t.Fatal(err)
	}

	if err := loggerDriver.Log(&logger.Message{Line: []byte("message1"), Source: "stdout", Timestamp: time.Now()}); err != nil {
		t.Fatal(err)
	}

	err = loggerDriver.Close()
	if err != nil {
		t.Fatal(err)
	}

	if err := loggerDriver.Log(&logger.Message{Line: []byte("message2"), Source: "stdout", Timestamp: time.Now()}); err == nil {
		t.Fatal("Driver should not allow to send messages after close")
	}

	if len(hec.messages) != 1 {
		t.Fatal("Only one message should be sent")
	}

	message := hec.messages[0]
	if event, err := message.EventAsMap(); err != nil {
		t.Fatal(err)
	} else {
		if event["line"] != "message1" {
			t.Fatalf("Unexpected event in message %v", event)
		}
	}

	err = hec.Close()
	if err != nil {
		t.Fatal(err)
	}
}

func TestSetTelemetry(t *testing.T) {
	// Restore the suite default set in TestMain.
	if err := os.Setenv(envVarSplunkTelemetry, "false"); err != nil {
		t.Fatal(err)
	}
}

// Verify that the retry backoff doubles up to the configured maximum.
func TestBackoffProgression(t *testing.T) {
	hec := &hecClient{
		retryBackoffInitial: 1 * time.Second,
		retryBackoffMax:     8 * time.Second,
	}

	if !hec.canAttempt() {
		t.Fatal("The first attempt should be allowed")
	}

	expectedDelays := []time.Duration{1, 2, 4, 8, 8}
	for i, expected := range expectedDelays {
		hec.recordFailure()
		if hec.retryBackoff != expected*time.Second {
			t.Fatalf("Failure %d: expected backoff %v, got %v", i, expected*time.Second, hec.retryBackoff)
		}
		if hec.canAttempt() {
			t.Fatalf("Failure %d: driver should be backing off", i)
		}
	}

	if hec.consecutiveFailures != len(expectedDelays) {
		t.Fatalf("Expected %d consecutive failures, got %d", len(expectedDelays), hec.consecutiveFailures)
	}
	if hec.failedAttempts != uint64(len(expectedDelays)) {
		t.Fatalf("Expected %d failed attempts, got %d", len(expectedDelays), hec.failedAttempts)
	}
}

// Verify that a successful post resets the backoff state.
func TestBackoffResetOnSuccess(t *testing.T) {
	hec := &hecClient{
		retryBackoffInitial: 1 * time.Second,
		retryBackoffMax:     8 * time.Second,
	}

	hec.recordFailure()
	if hec.canAttempt() {
		t.Fatal("Driver should be backing off after a failure")
	}

	hec.recordSuccess(5)
	if hec.consecutiveFailures != 0 || hec.retryBackoff != 0 || !hec.nextAttemptAt.IsZero() {
		t.Fatal("Backoff state should be reset after a success")
	}
	if !hec.canAttempt() {
		t.Fatal("Attempts should be allowed after a success")
	}
	if hec.failedAttempts != 1 {
		t.Fatalf("Expected 1 cumulative failed attempt, got %d", hec.failedAttempts)
	}
}

// Verify that the buffer is capped while the driver is backing off.
func TestEnforceBufferMaximum(t *testing.T) {
	hec := &hecClient{bufferMaximum: 3}
	messages := make([]*splunkMessage, 5)
	for i := range messages {
		messages[i] = &splunkMessage{Host: fmt.Sprintf("%d", i)}
	}

	remaining := hec.enforceBufferMaximum(messages)
	if len(remaining) != 3 {
		t.Fatalf("Expected buffer of 3, got %d", len(remaining))
	}
	if remaining[0].Host != "2" || remaining[2].Host != "4" {
		t.Fatal("Expected the oldest messages to be dropped")
	}
	if hec.droppedMessages != 2 {
		t.Fatalf("Expected 2 dropped messages, got %d", hec.droppedMessages)
	}

	underLimit := []*splunkMessage{{Host: "a"}}
	if got := hec.enforceBufferMaximum(underLimit); len(got) != 1 {
		t.Fatalf("Expected buffer to be left untouched, got %d", len(got))
	}
}

// withEnv sets environment variables for a test and returns a function that
// restores their previous values.
func withEnv(t *testing.T, vars map[string]string) func() {
	t.Helper()
	previous := make(map[string]string, len(vars))
	for name, value := range vars {
		previous[name] = os.Getenv(name)
		if err := os.Setenv(name, value); err != nil {
			t.Fatal(err)
		}
	}
	return func() {
		for name, value := range previous {
			if err := os.Setenv(name, value); err != nil {
				t.Fatal(err)
			}
		}
	}
}

func testLoggerInfo(url, token string) logger.Info {
	return logger.Info{
		Config: map[string]string{
			splunkURLKey:              url,
			splunkTokenKey:            token,
			splunkVerifyConnectionKey: "false",
		},
		ContainerID:        "containeriid",
		ContainerName:      "/container_name",
		ContainerImageID:   "contaimageid",
		ContainerImageName: "container_image_name",
	}
}

// waitFor polls condition until it is true or the timeout expires.
func waitFor(timeout time.Duration, condition func() bool) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if condition() {
			return true
		}
		time.Sleep(10 * time.Millisecond)
	}
	return condition()
}

// Verify that a single request to a hanging HEC endpoint fails after the
// configured HTTP timeout. The mock never replies on its own, so without the
// timeout this request would not return before the test deadline.
func TestHTTPTimeoutBoundsRequest(t *testing.T) {
	defer withEnv(t, map[string]string{
		envVarHTTPTimeout:     "200ms",
		envVarSplunkTelemetry: "false",
	})()

	hec := NewHTTPEventCollectorMock(t)
	hec.setHang(true)
	go hec.Serve()
	defer hec.Close()

	loggerDriver, err := New(testLoggerInfo(hec.URL(), hec.token))
	if err != nil {
		t.Fatal(err)
	}
	splunkLoggerDriver := loggerDriver.(*splunkLoggerInline)

	result := make(chan error, 1)
	start := time.Now()
	go func() {
		result <- splunkLoggerDriver.hec.tryPostMessages([]*splunkMessage{{Event: "hang"}})
	}()

	select {
	case err := <-result:
		elapsed := time.Since(start)
		if err == nil {
			t.Fatal("Expected the request to a hanging endpoint to fail")
		}
		if elapsed < 150*time.Millisecond || elapsed > 2*time.Second {
			t.Fatalf("Expected the request to fail after about 200ms, took %v", elapsed)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Request to a hanging endpoint was not bounded by the HTTP timeout")
	}

	if err := loggerDriver.Close(); err != nil {
		t.Fatal(err)
	}
}

// Verify that a hanging HEC endpoint cannot block the driver forever.
func TestHTTPTimeoutDoesNotBlock(t *testing.T) {
	defer withEnv(t, map[string]string{
		envVarHTTPTimeout:           "200ms",
		envVarPostMessagesFrequency: "50ms",
		envVarStreamChannelSize:     "1",
		envVarPostMessagesBatchSize: "1000",
		envVarShutdownFlushTimeout:  "300ms",
		envVarSplunkTelemetry:       "false",
	})()

	hec := NewHTTPEventCollectorMock(t)
	hec.setHang(true)
	go hec.Serve()

	loggerDriver, err := New(testLoggerInfo(hec.URL(), hec.token))
	if err != nil {
		t.Fatal(err)
	}

	done := make(chan struct{})
	go func() {
		// More messages than the channel buffer, so Log would block forever if
		// the worker got stuck on a hanging request.
		for i := 0; i < 50; i++ {
			if err := loggerDriver.Log(&logger.Message{Line: []byte(fmt.Sprintf("%d", i)), Source: "stdout", Timestamp: time.Now()}); err != nil {
				t.Errorf("Unexpected error logging message %d: %v", i, err)
				break
			}
		}
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Log blocked because the HTTP timeout is not effective")
	}

	// Close must also return even though HEC never responds: the in-flight
	// request is cancelled and the final flush is bounded to 300ms.
	closed := make(chan struct{})
	start := time.Now()
	go func() {
		if err := loggerDriver.Close(); err != nil {
			t.Errorf("Unexpected error closing driver: %v", err)
		}
		close(closed)
	}()
	select {
	case <-closed:
		if elapsed := time.Since(start); elapsed > 2*time.Second {
			t.Fatalf("Close took %v, expected it to be bounded by the shutdown flush timeout", elapsed)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Close blocked because the HTTP timeout is not effective")
	}

	if err := hec.Close(); err != nil {
		t.Fatal(err)
	}
}

// Verify that closing the driver cancels an in-flight request instead of
// waiting for the HTTP timeout, and bounds the final flush.
func TestCloseCancelsInFlightRequest(t *testing.T) {
	defer withEnv(t, map[string]string{
		envVarHTTPTimeout:           "30s",
		envVarShutdownFlushTimeout:  "300ms",
		envVarPostMessagesBatchSize: "1",
		envVarPostMessagesFrequency: "1h",
		envVarSplunkTelemetry:       "false",
	})()

	hec := NewHTTPEventCollectorMock(t)
	hec.setHang(true)
	go hec.Serve()
	defer hec.Close()

	loggerDriver, err := New(testLoggerInfo(hec.URL(), hec.token))
	if err != nil {
		t.Fatal(err)
	}

	if err := loggerDriver.Log(&logger.Message{Line: []byte("in flight"), Source: "stdout", Timestamp: time.Now()}); err != nil {
		t.Fatal(err)
	}
	if !waitFor(2*time.Second, func() bool { return hec.requestCount() >= 1 }) {
		t.Fatal("Expected a request to be in flight")
	}

	start := time.Now()
	if err := loggerDriver.Close(); err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Fatalf("Close took %v, expected the in-flight request to be cancelled", elapsed)
	}
}

// Verify that stopping a container with a backlog does not drop messages when
// HEC is healthy but slow: the drain may take longer than the shutdown budget
// as long as each request fits in it.
func TestCloseDrainsSlowHealthyHEC(t *testing.T) {
	defer withEnv(t, map[string]string{
		envVarShutdownFlushTimeout:  "300ms",
		envVarPostMessagesBatchSize: "10",
		envVarPostMessagesFrequency: "1h",
		envVarBufferMaximum:         "20",
		envVarStreamChannelSize:     "200",
		envVarSplunkTelemetry:       "false",
	})()

	hec := NewHTTPEventCollectorMock(t)
	hec.setDelay(100 * time.Millisecond)
	go hec.Serve()
	defer hec.Close()

	loggerDriver, err := New(testLoggerInfo(hec.URL(), hec.token))
	if err != nil {
		t.Fatal(err)
	}

	// 10 batches of 100ms each: about 1s of draining, well over the 300ms
	// budget, while every single request fits in it.
	for i := 0; i < 100; i++ {
		if err := loggerDriver.Log(&logger.Message{Line: []byte(fmt.Sprintf("%d", i)), Source: "stdout", Timestamp: time.Now()}); err != nil {
			t.Fatal(err)
		}
	}

	if err := loggerDriver.Close(); err != nil {
		t.Fatal(err)
	}

	if len(hec.messages) != 100 {
		t.Fatalf("Expected all 100 messages to be delivered on close, got %d", len(hec.messages))
	}
}

// Verify that the worker retries when the backoff expires, without waiting for
// the regular flush, and that it recovers once HEC is reachable again.
func TestRetryAfterBackoffExpires(t *testing.T) {
	defer withEnv(t, map[string]string{
		envVarRetryBackoffInitial:   "100ms",
		envVarRetryBackoffMax:       "100ms",
		envVarPostMessagesBatchSize: "1",
		envVarPostMessagesFrequency: "1h",
		envVarSplunkTelemetry:       "false",
	})()

	hec := NewHTTPEventCollectorMock(t)
	hec.setServerError(true)
	go hec.Serve()
	defer hec.Close()

	loggerDriver, err := New(testLoggerInfo(hec.URL(), hec.token))
	if err != nil {
		t.Fatal(err)
	}

	if err := loggerDriver.Log(&logger.Message{Line: []byte("retry me"), Source: "stdout", Timestamp: time.Now()}); err != nil {
		t.Fatal(err)
	}

	// The regular flush is 1h away, so every request after the first one
	// comes from the retry timer, spaced by the 100ms backoff.
	time.Sleep(650 * time.Millisecond)
	if count := hec.requestCount(); count < 3 || count > 10 {
		t.Fatalf("Expected retries spaced by the backoff, got %d requests in 650ms", count)
	}

	hec.setServerError(false)
	if !waitFor(2*time.Second, func() bool { return hec.acceptedPostCount() >= 1 }) {
		t.Fatal("Expected the buffered message to be delivered once HEC recovered")
	}

	if err := loggerDriver.Close(); err != nil {
		t.Fatal(err)
	}
	if len(hec.messages) != 1 {
		t.Fatalf("Expected exactly 1 delivered message, got %d", len(hec.messages))
	}
}

// Verify that the buffer never exceeds its maximum while backing off, even
// between batch boundaries, and that the oldest messages are the ones dropped.
func TestBufferMaximumStrictDuringBackoff(t *testing.T) {
	defer withEnv(t, map[string]string{
		envVarRetryBackoffInitial:   "1h",
		envVarRetryBackoffMax:       "1h",
		envVarPostMessagesBatchSize: "1",
		envVarPostMessagesFrequency: "1h",
		envVarBufferMaximum:         "10",
		envVarStreamChannelSize:     "0",
		envVarSplunkTelemetry:       "false",
	})()

	hec := NewHTTPEventCollectorMock(t)
	hec.setServerError(true)
	go hec.Serve()
	defer hec.Close()

	loggerDriver, err := New(testLoggerInfo(hec.URL(), hec.token))
	if err != nil {
		t.Fatal(err)
	}

	// The first message fails and starts a 1h backoff; the rest only go
	// through the buffer limit.
	for i := 0; i < 100; i++ {
		if err := loggerDriver.Log(&logger.Message{Line: []byte(fmt.Sprintf("%d", i)), Source: "stdout", Timestamp: time.Now()}); err != nil {
			t.Fatal(err)
		}
	}

	hec.setServerError(false)
	if err := loggerDriver.Close(); err != nil {
		t.Fatal(err)
	}

	if len(hec.messages) != 10 {
		t.Fatalf("Expected the final flush to deliver the 10 newest messages, got %d", len(hec.messages))
	}
	for i, message := range hec.messages {
		event, err := message.EventAsMap()
		if err != nil {
			t.Fatal(err)
		}
		if event["line"] != fmt.Sprintf("%d", 90+i) {
			t.Fatalf("Unexpected event in message %v", event)
		}
	}
}

// Verify that per-message drops during a backoff are counted but reported in
// a single rate-limited warning.
func TestEnforceBufferMaximumRateLimitsWarnings(t *testing.T) {
	hec := &hecClient{bufferMaximum: 1}
	messages := []*splunkMessage{{Host: "0"}}
	for i := 1; i <= 5; i++ {
		messages = append(messages, &splunkMessage{Host: fmt.Sprintf("%d", i)})
		messages = hec.enforceBufferMaximum(messages)
	}

	if hec.droppedMessages != 5 {
		t.Fatalf("Expected 5 dropped messages, got %d", hec.droppedMessages)
	}
	// The first drop is reported immediately, the next 4 wait for the interval.
	if hec.dropsSinceWarn != 4 {
		t.Fatalf("Expected 4 drops pending the next warning, got %d", hec.dropsSinceWarn)
	}

	hec.recordSuccess(1)
	if hec.dropsSinceWarn != 0 || !hec.lastDropWarnAt.IsZero() {
		t.Fatal("Expected the drop warning state to reset after a success")
	}
}

// Verify that a long post frequency alone does not make the derived initial
// backoff exceed the maximum and fail the driver.
func TestDerivedBackoffIsCappedByMax(t *testing.T) {
	defer withEnv(t, map[string]string{
		envVarPostMessagesFrequency: "2m",
		envVarSplunkTelemetry:       "false",
	})()

	loggerDriver, err := New(testLoggerInfo("http://127.0.0.1:1", "token"))
	if err != nil {
		t.Fatal(err)
	}
	defer loggerDriver.Close()

	hec := loggerDriver.(*splunkLoggerInline).hec
	if hec.retryBackoffInitial != defaultRetryBackoffMax {
		t.Fatalf("Expected the derived initial backoff to be capped to %v, got %v", defaultRetryBackoffMax, hec.retryBackoffInitial)
	}
}

// Verify that out-of-range advanced options are rejected when the driver starts.
func TestInvalidAdvancedOptions(t *testing.T) {
	cases := []struct {
		vars     map[string]string
		mentions string
	}{
		{map[string]string{envVarBufferMaximum: "-1"}, envVarBufferMaximum},
		{map[string]string{envVarBufferMaximum: "0"}, envVarBufferMaximum},
		{map[string]string{envVarPostMessagesBatchSize: "0"}, envVarPostMessagesBatchSize},
		{map[string]string{envVarPostMessagesFrequency: "0s"}, envVarPostMessagesFrequency},
		{map[string]string{envVarStreamChannelSize: "-1"}, envVarStreamChannelSize},
		{map[string]string{envVarHTTPTimeout: "-1s"}, envVarHTTPTimeout},
		{map[string]string{envVarRetryBackoffInitial: "-1s"}, envVarRetryBackoffInitial},
		{map[string]string{envVarRetryBackoffMax: "-1s"}, envVarRetryBackoffMax},
		{map[string]string{envVarRetryBackoffInitial: "10s", envVarRetryBackoffMax: "1s"}, envVarRetryBackoffInitial},
		{map[string]string{envVarShutdownFlushTimeout: "0s"}, envVarShutdownFlushTimeout},
	}

	for _, c := range cases {
		restore := withEnv(t, c.vars)
		_, err := New(testLoggerInfo("http://127.0.0.1:1", "token"))
		restore()
		if err == nil {
			t.Fatalf("Expected %v to be rejected", c.vars)
		}
		if !strings.Contains(err.Error(), c.mentions) {
			t.Fatalf("Expected error for %v to mention %s, got: %v", c.vars, c.mentions, err)
		}
	}
}
