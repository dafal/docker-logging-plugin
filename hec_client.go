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
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/Sirupsen/logrus"
)

type hecClient struct {
	client    *http.Client
	transport *http.Transport

	url            string
	healthCheckURL string
	auth           string

	// http compression
	gzipCompression      bool
	gzipCompressionLevel int

	// Advanced options
	postMessagesFrequency time.Duration
	postMessagesBatchSize int
	bufferMaximum         int

	// Retry backoff state. Only accessed by the logger worker goroutine, except
	// for the counters which are read for observability.
	retryBackoffInitial time.Duration
	retryBackoffMax     time.Duration
	retryBackoff        time.Duration
	consecutiveFailures int
	firstFailureAt      time.Time
	nextAttemptAt       time.Time

	// Observability counters
	droppedMessages uint64
	failedAttempts  uint64

	// Drops while backing off happen one message at a time, so their warning
	// is rate-limited to avoid flooding the daemon log during an outage.
	dropsSinceWarn uint64
	lastDropWarnAt time.Time

	// Context for regular requests. When the logger closes, the request in
	// flight at that time is cancelled once the shutdown budget is spent.
	ctx                  context.Context
	cancel               context.CancelFunc
	shutdownFlushTimeout time.Duration
	// Set (atomically) when the logger starts closing. From then on every
	// request gets its own shutdown budget instead of the regular context.
	closing int32
}

func (hec *hecClient) startClosing() {
	atomic.StoreInt32(&hec.closing, 1)
}

func (hec *hecClient) isClosing() bool {
	return atomic.LoadInt32(&hec.closing) == 1
}

func (hec *hecClient) requestContext() context.Context {
	if hec.ctx == nil {
		return context.Background()
	}
	return hec.ctx
}

// cancelRequests aborts any in-flight request. Safe to call concurrently and
// more than once.
func (hec *hecClient) cancelRequests() {
	if hec.cancel != nil {
		hec.cancel()
	}
}

func (hec *hecClient) finalFlushTimeout() time.Duration {
	if hec.shutdownFlushTimeout <= 0 {
		return defaultShutdownFlushTimeout
	}
	return hec.shutdownFlushTimeout
}

// canAttempt reports whether enough time has passed since the last failure to
// try reaching Splunk HEC again.
func (hec *hecClient) canAttempt() bool {
	return !time.Now().Before(hec.nextAttemptAt)
}

// retryWait returns how long until the next retry is allowed, if a backoff is
// pending. With backoff disabled there is no pending retry, so the worker
// keeps its regular cadence instead of retrying in a tight loop.
func (hec *hecClient) retryWait() (time.Duration, bool) {
	if hec.retryBackoff <= 0 || hec.nextAttemptAt.IsZero() {
		return 0, false
	}
	wait := time.Until(hec.nextAttemptAt)
	if wait < 0 {
		wait = 0
	}
	return wait, true
}

// retainFrom moves messages[from:] to the start of the buffer and clears the
// remaining slots, so sent or dropped messages are not kept alive by the
// backing array.
func retainFrom(messages []*splunkMessage, from int) []*splunkMessage {
	n := copy(messages, messages[from:])
	for i := n; i < len(messages); i++ {
		messages[i] = nil
	}
	return messages[:n]
}

// recordFailure increases the backoff delay (up to retryBackoffMax) and
// schedules the next attempt.
func (hec *hecClient) recordFailure() {
	hec.failedAttempts++
	hec.consecutiveFailures++
	if hec.firstFailureAt.IsZero() {
		hec.firstFailureAt = time.Now()
	}
	if hec.retryBackoff <= 0 {
		hec.retryBackoff = hec.retryBackoffInitial
	} else {
		hec.retryBackoff *= 2
	}
	if hec.retryBackoffMax > 0 && hec.retryBackoff > hec.retryBackoffMax {
		hec.retryBackoff = hec.retryBackoffMax
	}
	hec.nextAttemptAt = time.Now().Add(hec.retryBackoff)
	logrus.WithFields(logrus.Fields{
		"consecutiveFailures": hec.consecutiveFailures,
		"retryIn":             hec.retryBackoff,
		"failedAttempts":      hec.failedAttempts,
	}).Warn("Failed to send messages to Splunk HEC, will retry later")
}

// recordSuccess resets the backoff state after a fully successful post.
func (hec *hecClient) recordSuccess(sent int) {
	if hec.consecutiveFailures > 0 {
		logrus.WithFields(logrus.Fields{
			"consecutiveFailures": hec.consecutiveFailures,
			"outageDuration":      time.Since(hec.firstFailureAt),
			"messagesSent":        sent,
		}).Info("Connection to Splunk HEC restored, buffer flushed")
	}
	hec.consecutiveFailures = 0
	hec.firstFailureAt = time.Time{}
	hec.retryBackoff = 0
	hec.nextAttemptAt = time.Time{}
	// The next outage reports its first drop immediately.
	hec.dropsSinceWarn = 0
	hec.lastDropWarnAt = time.Time{}
}

// enforceBufferMaximum drops the oldest messages if the buffer grew past its
// maximum while the driver was backing off from an HEC failure.
func (hec *hecClient) enforceBufferMaximum(messages []*splunkMessage) []*splunkMessage {
	messagesLen := len(messages)
	if hec.bufferMaximum <= 0 || messagesLen <= hec.bufferMaximum {
		return messages
	}
	dropped := messagesLen - hec.bufferMaximum
	hec.droppedMessages += uint64(dropped)
	hec.dropsSinceWarn += uint64(dropped)
	if hec.lastDropWarnAt.IsZero() || time.Since(hec.lastDropWarnAt) >= dropWarnInterval {
		logrus.WithFields(logrus.Fields{
			"dropped":       hec.dropsSinceWarn,
			"totalDropped":  hec.droppedMessages,
			"bufferMaximum": hec.bufferMaximum,
		}).Warn("Splunk HEC buffer is full while backing off, dropping oldest messages")
		hec.dropsSinceWarn = 0
		hec.lastDropWarnAt = time.Now()
	}
	return retainFrom(messages, dropped)
}

func (hec *hecClient) postMessages(messages []*splunkMessage, lastChance bool) []*splunkMessage {
	logrus.Debugf("Received %d messages.", len(messages))
	messagesLen := len(messages)
	if messagesLen == 0 {
		logrus.Debug("No message to post")
		return messages
	}

	// While backing off after a failure, don't hit HEC. Keep the buffer bounded
	// so it cannot grow without limit. The final flush on close always attempts.
	if !lastChance && !hec.canAttempt() {
		remaining := hec.enforceBufferMaximum(messages)
		logrus.Debugf("Splunk HEC is unreachable, backing off, %d messages buffered", len(remaining))
		return remaining
	}

	for i := 0; i < messagesLen; i += hec.postMessagesBatchSize {
		upperBound := i + hec.postMessagesBatchSize
		if upperBound > messagesLen {
			upperBound = messagesLen
		}
		if err := hec.postBatch(messages[i:upperBound], lastChance); err != nil {
			logrus.Error(err)
			if messagesLen-i >= hec.bufferMaximum || lastChance {
				// If this is last chance - print them all to the daemon log
				if lastChance {
					upperBound = messagesLen
				}
				// Not all sent, but buffer has got to its maximum, let's log all messages
				// we could not send and return buffer minus one batch size
				dropped := upperBound - i
				hec.droppedMessages += uint64(dropped)
				for j := i; j < upperBound; j++ {
					if jsonEvent, err := json.Marshal(messages[j]); err != nil {
						logrus.Error(err)
					} else {
						logrus.Debug(fmt.Errorf("Dropped a message '%s'", string(jsonEvent)))
					}
				}
				if lastChance {
					hec.failedAttempts++
					logrus.WithFields(logrus.Fields{
						"dropped":      dropped,
						"totalDropped": hec.droppedMessages,
					}).Error("Final flush to Splunk HEC failed while closing the driver, dropping messages without retry")
					return retainFrom(messages, messagesLen)
				}
				logrus.WithFields(logrus.Fields{
					"dropped":      dropped,
					"totalDropped": hec.droppedMessages,
				}).Warn("Splunk HEC buffer is full, dropping messages")
				hec.recordFailure()
				return retainFrom(messages, upperBound)
			}
			// Not all sent, returning buffer from where we have not sent messages
			logrus.Debugf("%d messages failed to send", messagesLen)
			hec.recordFailure()
			return retainFrom(messages, i)
		}
	}
	// All sent, return empty buffer
	hec.recordSuccess(messagesLen)
	logrus.Debugf("%d messages were sent successfully", messagesLen)
	return retainFrom(messages, messagesLen)
}

// postBatch sends one batch. Once the logger is closing (and for the final
// flush) each batch gets its own short budget, independent of the regular
// context: a healthy HEC still receives the whole backlog, while a hung one
// costs at most one budget per request.
func (hec *hecClient) postBatch(messages []*splunkMessage, lastChance bool) error {
	if !lastChance && !hec.isClosing() {
		return hec.tryPostMessagesContext(hec.requestContext(), messages)
	}
	ctx, cancel := context.WithTimeout(context.Background(), hec.finalFlushTimeout())
	defer cancel()
	return hec.tryPostMessagesContext(ctx, messages)
}

func (hec *hecClient) tryPostMessages(messages []*splunkMessage) error {
	return hec.tryPostMessagesContext(hec.requestContext(), messages)
}

func (hec *hecClient) tryPostMessagesContext(ctx context.Context, messages []*splunkMessage) error {
	if len(messages) == 0 {
		logrus.Debug("No message to post")
		return nil
	}
	var buffer bytes.Buffer
	var writer io.Writer
	var gzipWriter *gzip.Writer
	var err error
	// If gzip compression is enabled - create gzip writer with specified compression
	// level. If gzip compression is disabled, use standard buffer as a writer
	if hec.gzipCompression {
		gzipWriter, err = gzip.NewWriterLevel(&buffer, hec.gzipCompressionLevel)
		if err != nil {
			return err
		}
		writer = gzipWriter
	} else {
		writer = &buffer
	}
	for _, message := range messages {
		jsonEvent, err := json.Marshal(message)
		if err != nil {
			return err
		}
		if _, err := writer.Write(jsonEvent); err != nil {
			return err
		}
	}
	// If gzip compression is enabled, tell it, that we are done
	if hec.gzipCompression {
		err = gzipWriter.Close()
		if err != nil {
			return err
		}
	}
	req, err := http.NewRequest("POST", hec.url, bytes.NewBuffer(buffer.Bytes()))
	if err != nil {
		return err
	}
	req = req.WithContext(ctx)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", hec.auth)
	// Tell if we are sending gzip compressed body
	if hec.gzipCompression {
		req.Header.Set("Content-Encoding", "gzip")
	}
	res, err := hec.client.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		var body []byte
		body, err = ioutil.ReadAll(res.Body)
		if err != nil {
			return err
		}
		return fmt.Errorf("%s: failed to send event - %s - %s", driverName, res.Status, body)
	}
	io.Copy(ioutil.Discard, res.Body)
	return nil
}

func (hec *hecClient) verifySplunkConnection(l *splunkLogger) error {
	req, err := http.NewRequest(http.MethodGet, hec.healthCheckURL, nil)
	if err != nil {
		return err
	}
	res, err := hec.client.Do(req)
	if err != nil {
		return err
	}
	if res.Body != nil {
		defer res.Body.Close()
	}
	if res.StatusCode != http.StatusOK {
		var body []byte
		body, err = ioutil.ReadAll(res.Body)
		if err != nil {
			return err
		}
		return fmt.Errorf("%s: failed to verify connection - %s - %s", driverName, res.Status, body)
	}
	return nil
}
