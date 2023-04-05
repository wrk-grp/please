package please

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/dgrr/http2"
	"github.com/valyala/fasthttp"
	"github.com/wrk-grp/errnie"
)

/*
Request is a much faster implementation compared to the standard
library one, at the cost of not being 100% compliant.
*/
type Request struct {
	conn     *fasthttp.Client
	endpoint string
	headers  map[string]string
	handle   *fasthttp.Request
	response *fasthttp.Response
}

/*
NewRequest returns a pointer to a new instance of the client.
You should store the client on the object level and re-use it,
it makes less sense to actually instantiate a new one inside of
individual methods, as you lose out on the builtin concurrency and
buffer pools.
*/
func NewRequest(endpoint string) *Request {
	errnie.Debugs("NewRequest() <-", endpoint)

	readTimeout, _ := time.ParseDuration("30s")
	writeTimeout, _ := time.ParseDuration("30s")
	maxIdleConnDuration, _ := time.ParseDuration("1h")

	return &Request{
		conn: &fasthttp.Client{
			ReadTimeout:                   readTimeout,
			WriteTimeout:                  writeTimeout,
			MaxIdleConnDuration:           maxIdleConnDuration,
			NoDefaultUserAgentHeader:      true,
			DisableHeaderNamesNormalizing: true,
			DisablePathNormalizing:        true,
			Dial: (&fasthttp.TCPDialer{
				Concurrency:      4096,
				DNSCacheDuration: 5 * time.Minute,
			}).Dial,
		},
		endpoint: endpoint,
		headers:  make(map[string]string),
		handle:   fasthttp.AcquireRequest(),
		response: fasthttp.AcquireResponse(),
	}
}

/*
AddHeaders allows you to pass in a map[string]string object which will
be iterated over to be converted into HTTP request headers.
*/
func (request *Request) AddHeaders(headers map[string]string) *Request {
	errnie.Trace()
	request.headers = headers
	return request
}

func (request *Request) GetHeader(key string) string {
	return string(request.response.Header.Peek(key))
}

/*
AddClientCert configures a client certificate for accessing services that
require this type of authorization.
*/
func (request *Request) AddClientCert(certs *tls.Config) *Request {
	errnie.Trace()
	request.conn.TLSConfig = certs
	return request
}

func (request *Request) Get(path string, data map[string]interface{}) []byte {
	errnie.Trace()
	return request.do("GET", path, data)
}

func (request *Request) Post(path string, data map[string]interface{}) []byte {
	errnie.Trace()
	return request.do("POST", path, data)
}

func (request *Request) Put(path string, data map[string]interface{}) []byte {
	errnie.Trace()
	return request.do("PUT", path, data)
}

/*
do implements the Job interface, which enables the HTTP request to
be scheduled onto a worker pool.
TODO: Only handles POST for now, but that is all we use anyway.
*/
func (request *Request) do(
	method string, path string, data map[string]interface{},
) []byte {
	errnie.Trace()

	hc := &fasthttp.HostClient{
		Addr:  request.getAddr(),
		IsTLS: true,
	}

	errnie.Handles(http2.ConfigureClient(hc, http2.ClientOpts{}))

	request.response.Reset()
	request.handle.Header.SetMethod(method)
	request.handle.URI().Update(request.endpoint + path)

	for key, value := range request.headers {
		request.handle.Header.Add(key, value)
	}

	buf, err := json.Marshal(&data)
	errnie.Handles(err)

	if method == "POST" {
		request.handle.SetBody(buf)
	}

	if method == "GET" {
		url := request.endpoint + path + "?"

		for key, value := range data {
			url += fmt.Sprintf("&%s=%v", key, value)
		}

		request.handle.URI().Update(url)
	}

	errnie.Handles(hc.Do(request.handle, request.response))
	return request.response.Body()
}

func (request *Request) getAddr() string {
	return strings.Split(request.endpoint, "/")[2] + ":443"
}
