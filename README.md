# Sample to Support Governance for Moesif AWS API Gateway Integration

This is an example AWS API Gateway Lambda Authorizer that enforces Moesif governance rules and quotas. 

By default, the [Moesif AWS API Gateway integration](https://www.moesif.com/docs/server-integration/aws-api-gateway/) doesn't enforce governance rules because traffic is logged via Amazon Data Firehose. However, you can integrate with the Moesif governance rules APIs within your custom lambda authorizer for AWS API Gateway.

You'll 

This example contains a sample Python Lambda that loads and caches the users that need to be blocked. 
This is a MVP project but can be expanded to download rules dynamically as well by consuming another API to get the governance rules from Moesif:
`GET https://api.moesif.net/v1/rules`