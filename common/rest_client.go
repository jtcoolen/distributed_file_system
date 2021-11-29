package common

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"
)

var ServerBaseUrl = "https://jch.irif.fr:8082"
var PeersUrl = fmt.Sprintf("%s/peers", ServerBaseUrl)

func PeerAddressesUrl(peer string) string {
	return fmt.Sprintf("%s/peers/%s/addresses", ServerBaseUrl, peer)
}

func PeerKeyUrl(peer string) string {
	return fmt.Sprintf("%s/peers/%s/key", ServerBaseUrl, peer)
}

func PeerRootUrl(peer string) string {
	return fmt.Sprintf("%s/peers/%s/root", ServerBaseUrl, peer)
}

func GetHttpRequestResponseBody(method string, url string) ([]byte, *http.Response, error) {
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

func SplitLines(body []byte) [][]byte {
	lines := bytes.Split(body, []byte{byte('\n')})
	if len(lines) > 0 {
		last := len(lines) - 1
		if len(lines[last]) == 0 {
			lines = lines[:last]
		}
	}
	return lines
}

func GetPeers() ([][]byte, error) {
	body, r, err := GetHttpRequestResponseBody("GET", PeersUrl)
	if err != nil {
		return nil, err
	}
	if r.StatusCode != 200 {
		return nil, ErrNotFound
	}
	return SplitLines(body), nil
}

func GetPeerAddresses(peer string) ([][]byte, error) {
	body, r, err := GetHttpRequestResponseBody("GET", PeerAddressesUrl(peer))
	if err != nil {
		return nil, err
	}
	if r.StatusCode == 404 {
		return nil, ErrNotFound
	}
	return SplitLines(body), nil
}

func GetPeerKey(peer string) ([]byte, error) {
	body, r, err := GetHttpRequestResponseBody("GET", PeerKeyUrl(peer))
	if err != nil {
		return nil, err
	}
	if len(body) != PublicKeyLength {
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

func GetPeerRoot(peer string) ([32]byte, error) {
	h := [32]byte{}
	body, r, err := GetHttpRequestResponseBody("GET", PeerRootUrl(peer))
	if err != nil {
		return h, err
	}
	if len(body) != sha256.Size {
		return h, ErrWrongHashSize
	}
	switch r.StatusCode {
	case 404:
		return h, ErrNotFound
	case 204:
		return h, ErrNoRoot
	default:
		copy(h[:], body[:32])
		return h, nil
	}
}
