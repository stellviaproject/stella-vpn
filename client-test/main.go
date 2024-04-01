package main

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
)

func main() {
	Test()
}

func Test() error {
	URL, err := url.Parse("http://127.0.0.1:9090/")
	if err != nil {
		return err
	}
	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(URL),
		},
	}
	res, err := client.Get("http://www.google.com/")
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if data, err := io.ReadAll(res.Body); err != nil {
		return err
	} else {
		fmt.Println(string(data))
	}
	return nil
}
