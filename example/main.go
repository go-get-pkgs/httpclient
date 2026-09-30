package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/go-get-pkgs/httpclient"
)

func main() {
	fmt.Println("Initializing resilient anti-detect HTTP client...")

	client, err := httpclient.New(httpclient.ClientSettings{
		Timeout:   20 * time.Second,
		StrictSSL: true,
		Browser:   httpclient.BrowserChrome,
		Retry:     httpclient.DefaultRetryConfig,
	})
	if err != nil {
		log.Fatalf("failed to create client: %v", err)
	}

	fmt.Printf("Active Browser Identity: %s (v%d)\n",
		client.BrowserVersion.FullVersion, client.BrowserVersion.MajorVersion)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	target := "https://tls.peet.ws/api/all"
	fmt.Printf("Executing GET request to %s ...\n", target)

	body, status, err := client.GetString(ctx, target)
	if err != nil {
		log.Fatalf("request failed: %v", err)
	}

	fmt.Printf("HTTP Status: %d\n", status)
	fmt.Println("Response Preview (first 600 chars):")
	if len(body) > 600 {
		fmt.Println(body[:600] + "\n...[truncated]")
	} else {
		fmt.Println(body)
	}
}
