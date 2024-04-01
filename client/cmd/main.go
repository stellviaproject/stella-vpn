package main

import (
	"flag"
	"log"
	"math"
	"os"

	"github.com/stellviaproject/stella-vpn/client"
)

func main() {
	cfgFile := flag.String("cfg", "./config.json", "the configuration file of vpn client")
	flag.Parse()
	if *cfgFile == "" {
		log.Fatalln("the path of configuration file could not be empty")
		return
	}

	if _, err := os.Stat(*cfgFile); err != nil && os.IsNotExist(err) {
		cfg := &client.TunnelConfig{
			AppURL:   "-",
			Port:     8080,
			Username: "-",
			Password: "-",
			OTP:      "",
			Proxy: client.ProxyConfig{
				URL:      "http://0.0.0.0:0",
				Username: "-",
				Password: "-",
				Domain:   "-",
				Ntlm:     false,
			},
		}
		if err := cfg.SaveConfig(*cfgFile); err != nil {
			log.Fatalln(err)
		}
		log.Println("the configuration file has been created")
		return
	}
	cfg := client.TunnelConfig{}
	if err := (&cfg).LoadConfig(*cfgFile); err != nil {
		log.Fatalln(err)
	}
	max := cfg.MaxRetry
	if max < 0 {
		max = math.MaxInt
	}
	for i := 0; i < max; i++ {
		log.Println(client.Connect(cfg))
	}
}
