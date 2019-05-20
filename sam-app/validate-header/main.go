package main

import (
	"context"
	// "errors"
	"strings"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
)

// Help function to generate an IAM policy
func generatePolicy(principalId, effect, resource string, ua string) events.APIGatewayCustomAuthorizerResponse {
	authResponse := events.APIGatewayCustomAuthorizerResponse{PrincipalID: principalId}

	if effect != "" && resource != "" {
		authResponse.PolicyDocument = events.APIGatewayCustomAuthorizerPolicy{
			Version: "2012-10-17",
			Statement: []events.IAMPolicyStatement{
				{
					Action:   []string{"execute-api:Invoke"},
					Effect:   effect,
					Resource: []string{resource},
				},
			},
		}
	}

	// Optional output with custom properties of the String, Number or Boolean type.
	authResponse.Context = map[string]interface{}{
		"UserAgent": ua,
		// "stringKey":  "stringval",
		// "numberKey":  123,
		// "booleanKey": true,
	}
	return authResponse
}

func handleRequest(ctx context.Context, event events.APIGatewayCustomAuthorizerRequest) (events.APIGatewayCustomAuthorizerResponse, error) {
	token := event.AuthorizationToken
	switch strings.ToLower(token) {
	case "dalvik":
		return generatePolicy("user", "Allow", event.MethodArn, token), nil
	// case "deny":
	// 	return generatePolicy("user", "Deny", event.MethodArn), nil
	// case "unauthorized":
	// 	return events.APIGatewayCustomAuthorizerResponse{}, errors.New("Unauthorized") // Return a 401 Unauthorized response
	default:
		// return events.APIGatewayCustomAuthorizerResponse{}, errors.New("Error: Invalid token")
		return generatePolicy("user", "Deny", event.MethodArn, token), nil
	}
}

func main() {
	lambda.Start(handleRequest)
}
