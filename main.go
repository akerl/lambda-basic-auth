package main

import (
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/akerl/go-lambda/s3"
	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
)

var c *config

type config struct {
	Users map[string]string `json:"users"`
}

func loadConfig() error {
	cf, err := s3.GetConfigFromEnv(&c)
	if err != nil {
		return err
	}

	cf.OnError = func(_ *s3.ConfigFile, err error) {
		fmt.Println(err)
	}
	cf.Autoreload(60)

	return nil
}

func main() {
	if err := loadConfig(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	lambda.Start(handler)
}

func handler(req events.APIGatewayCustomAuthorizerRequest) (events.APIGatewayCustomAuthorizerResponse, error) { //revive:disable-line:line-length-limit
	user, pass, ok := parseBasicAuth(req.AuthorizationToken)
	fmt.Printf("Token: %s\n", req.AuthorizationToken)
	fmt.Printf("%s / %s / %t\n", user, pass, ok)
	if !ok || c.Users[user] == "" || subtle.ConstantTimeCompare([]byte(c.Users[user]), []byte(pass)) != 1 { //revive:disable-line:line-length-limit
		return events.APIGatewayCustomAuthorizerResponse{}, errors.New("Unauthorized") //revive:disable-line
	}

	return events.APIGatewayCustomAuthorizerResponse{
		PrincipalID: "user",
		PolicyDocument: events.APIGatewayCustomAuthorizerPolicy{
			Version: "2012-10-17",
			Statement: []events.IAMPolicyStatement{
				{
					Action:   []string{"execute-api:Invoke"},
					Effect:   "allow",
					Resource: []string{req.MethodArn},
				},
			},
		},
	}, nil
}

func parseBasicAuth(auth string) (username, password string, ok bool) {
	if !strings.HasPrefix(auth, "Basic ") {
		return "", "", false
	}
	c, err := base64.StdEncoding.DecodeString(auth[6:])
	if err != nil {
		return "", "", false
	}
	cs := string(c)
	username, password, ok = strings.Cut(cs, ":")
	if !ok {
		return "", "", false
	}
	return username, password, true
}
