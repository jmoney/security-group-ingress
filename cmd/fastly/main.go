package main

import (
	"context"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/fastly/go-fastly/fastly"
	"github.com/jmoney/security-group-ingress/internal"
)

func Ipv4Source() []string {
	// the only time an error comes back is if the host is not resolvable.  The key can be optional and will not
	// error out so it is safe to ignore the error
	fastlyClient, _ := fastly.NewClient("")

	ipAddrs, err := fastlyClient.IPs()
	if err != nil {
		panic(err)
	}

	return ipAddrs
}

func main() {
	ctx := context.WithValue(context.Background(), internal.SOURCE, Ipv4Source)
	lambda.StartWithContext(ctx,internal.HandleRequest)
}