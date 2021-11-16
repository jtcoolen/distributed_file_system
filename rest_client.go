package main

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"
)

var ErrNotFound = errors.New("not found")
var ErrNoPublicKey = errors.New("no public key")
var ErrNoRoot = errors.New("no root")
var ErrWrongKeySize = errors.New("wrong key size")
var ErrWrongHashSize = errors.New("wrong hash size")

var serverBaseUrl = "https://jch.irif.fr:8082"
var peersUrl = fmt.Sprintf("%s/peers", serverBaseUrl)

func peerAddressesUrl(peer string) string {
	return fmt.Sprintf("%s/peers/%s/addresses", serverBaseUrl, peer)
}

func peerKeyUrl(peer string) string {
	return fmt.Sprintf("%s/peers/%s/key", serverBaseUrl, peer)
}

func peerRootUrl(peer string) string {
	return fmt.Sprintf("%s/peers/%s/root", serverBaseUrl, peer)
}

func getHttpRequestResponseBody(method string, url string) ([]byte, *http.Response, error) {
	transport := http.DefaultTransport.(*http.Transport)
	transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	client := &http.Client{
		Transport: transport,
		Timeout:   50 * time.Second,
	}

	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("newrequest: %v", err)
	}

	r, err := client.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("do: %v", err)
	}

	body, err := ioutil.ReadAll(r.Body)
	r.Body.Close()
	if err != nil {
		return nil, nil, fmt.Errorf("readall: %v", err)
	}

	return body, r, nil
}

func splitLines(body []byte) [][]byte {
	lines := bytes.Split(body, []byte{byte('\n')})
	if len(lines) > 0 {
		last := len(lines) - 1
		if len(lines[last]) == 0 {
			lines = lines[:last]
		}
	}
	return lines
}

func getPeers() ([][]byte, error) {
	body, r, err := getHttpRequestResponseBody("GET", peersUrl)
	if err != nil {
		return nil, err
	}
	if r.StatusCode != 200 {
		return nil, ErrNotFound
	}
	return splitLines(body), nil
}

func getPeerAddresses(peer string) ([][]byte, error) {
	body, r, err := getHttpRequestResponseBody("GET", peerAddressesUrl(peer))
	if err != nil {
		return nil, err
	}
	if r.StatusCode == 404 {
		return nil, ErrNotFound
	}
	return splitLines(body), nil
}

func getPeerKey(peer string) ([]byte, error) {
	body, r, err := getHttpRequestResponseBody("GET", peerKeyUrl(peer))
	if err != nil {
		return nil, err
	}
	if len(body) != publicKeyLength {
		return nil, ErrWrongKeySize
	}
	switch r.StatusCode {
	case 404:
		return nil, ErrNotFound
	case 204:
		return nil, ErrNoPublicKey
	default:
		return body, nil
	}
}

func getPeerRoot(peer string) ([]byte, error) {
	body, r, err := getHttpRequestResponseBody("GET", peerRootUrl(peer))
	if err != nil {
		return nil, err
	}
	if len(body) != sha256.Size {
		return nil, ErrWrongHashSize
	}
	switch r.StatusCode {
	case 404:
		return nil, ErrNotFound
	case 204:
		return nil, ErrNoRoot
	default:
		return body, nil
	}
}
