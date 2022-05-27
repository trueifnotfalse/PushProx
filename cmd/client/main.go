// Copyright 2020 The Prometheus Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"github.com/spf13/pflag"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/cenkalti/backoff/v4"
	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/pkg/errors"
	"github.com/prometheus-community/pushprox/util"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/prometheus/common/promlog"
	"github.com/spf13/viper"
)

const (
	fqdnEnv              = "FQDN"
	fqdnFlag             = "fqdn"
	proxyURLEnv          = "PROXY_URL"
	proxyURLFlag         = "proxy-url"
	tlsCacertEnv         = "TLS_CACERT"
	tlsCacertFlag        = "tls.cacert"
	tlsCertEnv           = "TLS_CERT"
	tlsCertFlag          = "tls.cert"
	tlsKeyEnv            = "TLS_KEY"
	tlsKeyFlag           = "tls.key"
	metricsAddrEnv       = "METRICS_ADDR"
	metricsAddrFlag      = "metrics-addr"
	retryInitialWaitEnv  = "RETRY_INITIAL_WAIT"
	retryInitialWaitFlag = "proxy.retry.initial-wait"
	retryMaxWaitEnv      = "RETRY_MAX_WAIT"
	retryMaxWaitFlag     = "proxy.retry.max-wait"
	logLevelEnv          = "LOG_LEVEL"
	logLevelFlag         = "log.level"
)

var (
	fqdn             string
	proxyURL         string
	caCertFile       string
	tlsCert          string
	tlsKey           string
	metricsAddr      string
	retryInitialWait time.Duration
	retryMaxWait     time.Duration
	logLevel         string
)

var (
	scrapeErrorCounter = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "pushprox_client_scrape_errors_total",
			Help: "Number of scrape errors",
		},
	)
	pushErrorCounter = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "pushprox_client_push_errors_total",
			Help: "Number of push errors",
		},
	)
	pollErrorCounter = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "pushprox_client_poll_errors_total",
			Help: "Number of poll errors",
		},
	)
)

func initEnv() {
	viper.BindEnv(fqdnFlag, fqdnEnv)
	viper.BindEnv(proxyURLFlag, proxyURLEnv)
	viper.BindEnv(tlsCacertFlag, tlsCacertEnv)
	viper.BindEnv(tlsCertFlag, tlsCertEnv)
	viper.BindEnv(tlsKeyFlag, tlsKeyEnv)
	viper.BindEnv(metricsAddrFlag, metricsAddrEnv)
	viper.BindEnv(retryInitialWaitFlag, retryInitialWaitEnv)
	viper.BindEnv(retryMaxWaitFlag, retryMaxWaitEnv)
	viper.BindEnv(logLevelFlag, logLevelEnv)

	viper.SetDefault(metricsAddrEnv, ":9369")
	viper.SetDefault(retryInitialWaitEnv, time.Duration(time.Second))
	viper.SetDefault(retryMaxWaitEnv, time.Duration(5*time.Second))
	viper.SetDefault(logLevelEnv, "info")
}

func initFlags() {
	pflag.String(fqdnFlag, "", "FQDN to register with")
	pflag.String(proxyURLFlag, "", "Push proxy to talk to.")
	pflag.String(tlsCacertFlag, "", "<file> CA certificate to verify peer against")
	pflag.String(tlsCertFlag, "", "<cert> Client certificate file")
	pflag.String(tlsKeyFlag, "", "<key> Private key file")
	pflag.String(metricsAddrFlag, ":9369", "Serve Prometheus metrics at this address")
	pflag.Duration(retryInitialWaitFlag, time.Duration(time.Second), "Amount of seconds to wait after proxy failure")
	pflag.Duration(retryMaxWaitFlag, time.Duration(5*time.Second), "Maximum amount of seconds to wait between proxy poll retries")
	pflag.String(logLevelFlag, "info", "Only log messages with the given severity or above. One of: [debug, info, warn, error]")
	pflag.CommandLine.AddGoFlagSet(flag.CommandLine)
	pflag.Parse()
	viper.BindPFlags(pflag.CommandLine)
}

func loadConfigParams() {
	fqdn = viper.GetString(fqdnFlag)
	proxyURL = viper.GetString(proxyURLFlag)
	caCertFile = viper.GetString(tlsCacertFlag)
	tlsCert = viper.GetString(tlsCertFlag)
	tlsKey = viper.GetString(tlsCertFlag)
	metricsAddr = viper.GetString(metricsAddrFlag)
	retryInitialWait = viper.GetDuration(retryInitialWaitFlag)
	retryMaxWait = viper.GetDuration(retryMaxWaitFlag)
	logLevel = viper.GetString(logLevelFlag)
}

func init() {
	initEnv()
	initFlags()
	loadConfigParams()
	prometheus.MustRegister(pushErrorCounter, pollErrorCounter, scrapeErrorCounter)
}

func newBackOffFromFlags() backoff.BackOff {
	b := backoff.NewExponentialBackOff()
	b.InitialInterval = retryInitialWait
	b.Multiplier = 1.5
	b.MaxInterval = retryMaxWait
	b.MaxElapsedTime = time.Duration(0)
	return b
}

// Coordinator for scrape requests and responses
type Coordinator struct {
	logger log.Logger
}

func (c *Coordinator) handleErr(request *http.Request, client *http.Client, err error) {
	level.Error(c.logger).Log("err", err)
	scrapeErrorCounter.Inc()
	resp := &http.Response{
		StatusCode: http.StatusInternalServerError,
		Body:       ioutil.NopCloser(strings.NewReader(err.Error())),
		Header:     http.Header{},
	}
	if err = c.doPush(resp, request, client); err != nil {
		pushErrorCounter.Inc()
		level.Warn(c.logger).Log("msg", "Failed to push failed scrape response:", "err", err)
		return
	}
	level.Info(c.logger).Log("msg", "Pushed failed scrape response")
}

func (c *Coordinator) doScrape(request *http.Request, client *http.Client) {
	logger := log.With(c.logger, "scrape_id", request.Header.Get("id"))
	timeout, err := util.GetHeaderTimeout(request.Header)
	if err != nil {
		c.handleErr(request, client, err)
		return
	}
	ctx, cancel := context.WithTimeout(request.Context(), timeout)
	defer cancel()
	request = request.WithContext(ctx)
	// We cannot handle https requests at the proxy, as we would only
	// see a CONNECT, so use a URL parameter to trigger it.
	params := request.URL.Query()
	if params.Get("_scheme") == "https" {
		request.URL.Scheme = "https"
		params.Del("_scheme")
		request.URL.RawQuery = params.Encode()
	}

	if request.URL.Hostname() != fqdn {
		c.handleErr(request, client, errors.New("scrape target doesn't match client fqdn"))
		return
	}

	scrapeResp, err := client.Do(request)
	if err != nil {
		msg := fmt.Sprintf("failed to scrape %s", request.URL.String())
		c.handleErr(request, client, errors.Wrap(err, msg))
		return
	}
	level.Info(logger).Log("msg", "Retrieved scrape response")
	if err = c.doPush(scrapeResp, request, client); err != nil {
		pushErrorCounter.Inc()
		level.Warn(logger).Log("msg", "Failed to push scrape response:", "err", err)
		return
	}
	level.Info(logger).Log("msg", "Pushed scrape result")
}

// Report the result of the scrape back up to the proxy.
func (c *Coordinator) doPush(resp *http.Response, origRequest *http.Request, client *http.Client) error {
	resp.Header.Set("id", origRequest.Header.Get("id")) // Link the request and response
	// Remaining scrape deadline.
	deadline, _ := origRequest.Context().Deadline()
	resp.Header.Set("X-Prometheus-Scrape-Timeout", fmt.Sprintf("%f", float64(time.Until(deadline))/1e9))

	base, err := url.Parse(proxyURL)
	if err != nil {
		return err
	}
	u, err := url.Parse("push")
	if err != nil {
		return err
	}
	url := base.ResolveReference(u)

	buf := &bytes.Buffer{}
	//nolint:errcheck // https://github.com/prometheus-community/PushProx/issues/111
	resp.Write(buf)
	request := &http.Request{
		Method:        "POST",
		URL:           url,
		Body:          ioutil.NopCloser(buf),
		ContentLength: int64(buf.Len()),
	}
	request = request.WithContext(origRequest.Context())
	if _, err = client.Do(request); err != nil {
		return err
	}
	return nil
}

func (c *Coordinator) doPoll(client *http.Client) error {
	base, err := url.Parse(proxyURL)
	if err != nil {
		level.Error(c.logger).Log("msg", "Error parsing url:", "err", err)
		return errors.Wrap(err, "error parsing url")
	}
	u, err := url.Parse("poll")
	if err != nil {
		level.Error(c.logger).Log("msg", "Error parsing url:", "err", err)
		return errors.Wrap(err, "error parsing url poll")
	}
	url := base.ResolveReference(u)
	resp, err := client.Post(url.String(), "", strings.NewReader(fqdn))
	if err != nil {
		level.Error(c.logger).Log("msg", "Error polling:", "err", err)
		return errors.Wrap(err, "error polling")
	}
	defer resp.Body.Close()

	request, err := http.ReadRequest(bufio.NewReader(resp.Body))
	if err != nil {
		level.Error(c.logger).Log("msg", "Error reading request:", "err", err)
		return errors.Wrap(err, "error reading request")
	}
	level.Info(c.logger).Log("msg", "Got scrape request", "scrape_id", request.Header.Get("id"), "url", request.URL)

	request.RequestURI = ""

	go c.doScrape(request, client)

	return nil
}

func (c *Coordinator) loop(bo backoff.BackOff, client *http.Client) {
	op := func() error {
		return c.doPoll(client)
	}

	for {
		if err := backoff.RetryNotify(op, bo, func(err error, _ time.Duration) {
			pollErrorCounter.Inc()
		}); err != nil {
			level.Error(c.logger).Log("err", err)
		}
	}
}

func main() {
	var logL promlog.AllowedLevel
	logL.Set(logLevel)
	promlogConfig := promlog.Config{Level: &logL}
	logger := promlog.New(&promlogConfig)
	coordinator := Coordinator{logger: logger}

	if proxyURL == "" {
		level.Error(coordinator.logger).Log("msg", "--proxy-url flag must be specified.")
		os.Exit(1)
	}
	// Make sure proxyURL ends with a single '/'
	proxyURL = strings.TrimRight(proxyURL, "/") + "/"
	level.Info(coordinator.logger).Log("msg", "URL and FQDN info", "proxy_url", proxyURL, "fqdn", fqdn)

	tlsConfig := &tls.Config{}
	if tlsCert != "" {
		cert, err := tls.LoadX509KeyPair(tlsCert, tlsKey)
		if err != nil {
			level.Error(coordinator.logger).Log("msg", "Certificate or Key is invalid", "err", err)
			os.Exit(1)
		}

		// Setup HTTPS client
		tlsConfig.Certificates = []tls.Certificate{cert}

		tlsConfig.BuildNameToCertificate()
	}

	if caCertFile != "" {
		caCert, err := ioutil.ReadFile(caCertFile)
		if err != nil {
			level.Error(coordinator.logger).Log("msg", "Not able to read cacert file", "err", err)
			os.Exit(1)
		}
		caCertPool := x509.NewCertPool()
		if ok := caCertPool.AppendCertsFromPEM(caCert); !ok {
			level.Error(coordinator.logger).Log("msg", "Failed to use cacert file as ca certificate")
			os.Exit(1)
		}

		tlsConfig.RootCAs = caCertPool
	}

	if metricsAddr != "" {
		go func() {
			if err := http.ListenAndServe(metricsAddr, promhttp.Handler()); err != nil {
				level.Warn(coordinator.logger).Log("msg", "ListenAndServe", "err", err)
			}
		}()
	}

	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
			DualStack: true,
		}).DialContext,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		TLSClientConfig:       tlsConfig,
	}

	client := &http.Client{Transport: transport}

	coordinator.loop(newBackOffFromFlags(), client)
}
