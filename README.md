# AWS Revoke Session Action

Revoke AWS IAM role sessions by applying a deny policy for tokens issued before a specific time. This action is commonly used for security incidents, compromised credentials, or forcing re-authentication for IAM roles.

## Overview

This SGNL action integrates with the AWS IAM API to revoke active sessions for an IAM role. When executed, the action attaches an inline policy (`AWSRevokeOlderSessions`) that denies all actions for tokens issued before a specified timestamp, immediately invalidating those sessions.

## Prerequisites

- AWS account with IAM permissions
- Appropriate authentication credentials (Basic auth or OAuth2 with AssumeRoleWithWebIdentity)
- `iam:PutRolePolicy` permission for the target role
- IAM role name to revoke sessions for

## Configuration

### Required Secrets

The configured auth type will determine which secrets are needed:

- **Basic Authentication**: `BASIC_USERNAME` (AWS Access Key ID) and `BASIC_PASSWORD` (AWS Secret Access Key)
- **OAuth2 with AssumeRoleWithWebIdentity**: `OAUTH2_CLIENT_CREDENTIALS_CLIENT_SECRET`

### Optional Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `OAUTH2_CLIENT_CREDENTIALS_CLIENT_ID` | - | OAuth2 client ID |
| `OAUTH2_CLIENT_CREDENTIALS_TOKEN_URL` | - | OAuth2 token endpoint URL |
| `OAUTH2_CLIENT_CREDENTIALS_SCOPE` | - | OAuth2 scope (optional) |
| `OAUTH2_CLIENT_CREDENTIALS_AUDIENCE` | - | OAuth2 audience (optional) |
| `OAUTH2_CLIENT_CREDENTIALS_AUTH_STYLE` | - | OAuth2 auth style: `in_params` or `in_header` (optional) |
| `AWS_ASSUME_ROLE_WEB_IDENTITY_REGION` | - | AWS region for AssumeRoleWithWebIdentity |
| `AWS_ASSUME_ROLE_WEB_IDENTITY_ROLE_ARN` | - | ARN of the AWS role to assume |
| `AWS_ASSUME_ROLE_WEB_IDENTITY_SESSION_NAME` | Auto-generated | Session name for AssumeRoleWithWebIdentity |
| `AWS_ASSUME_ROLE_WEB_IDENTITY_SESSION_DURATION_SECONDS` | 3600 | Session duration in seconds (900-43200) |

### Input Parameters

| Parameter | Type | Required | Description | Example |
|-----------|------|----------|-------------|---------|
| `roleName` | string | Yes | Name of the IAM role to revoke sessions for | `MyApplicationRole` |
| `region` | string | Yes | AWS region | `us-east-1` |
| `tokenIssueTime` | string (ISO 8601) | No | Revoke tokens issued before this time (defaults to current time) | `2024-01-15T10:30:00Z` |
| `conditions` | object/string | No | Additional IAM policy conditions to merge into the deny policy | `{"StringEquals": {"aws:userid": "AIDAI123"}}` |

### Output Structure

| Field | Type | Description |
|-------|------|-------------|
| `roleName` | string | Name of the IAM role |
| `policyName` | string | Name of the applied policy (`AWSRevokeOlderSessions`) |
| `tokenIssueTime` | string | Timestamp used for revocation cutoff (ISO 8601) |
| `applied` | boolean | Whether the policy was successfully applied |
| `appliedAt` | string | When the policy was applied (ISO 8601) |

## Usage Example

### Job Request

```json
{
  "id": "revoke-session-001",
  "type": "nodejs-20",
  "script": {
    "repository": "github.com/sgnl-actions/aws-revoke-session",
    "version": "v1.0.0",
    "type": "nodejs"
  },
  "script_inputs": {
    "roleName": "MyApplicationRole",
    "region": "us-east-1"
  }
}
```

### Successful Response

```json
{
  "roleName": "MyApplicationRole",
  "policyName": "AWSRevokeOlderSessions",
  "tokenIssueTime": "2024-01-15T10:30:00Z",
  "applied": true,
  "appliedAt": "2024-01-15T10:30:01Z"
}
```

## Authentication Methods

This action supports multiple authentication methods:

### 1. Basic Authentication (Static Credentials)
Use AWS Access Key ID and Secret Access Key directly:
```json
"secrets": {
  "BASIC_USERNAME": "AKIAIOSFODNN7EXAMPLE",
  "BASIC_PASSWORD": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
}
```

### 2. OAuth2 with AssumeRoleWithWebIdentity (Recommended)
Use OAuth2 Client Credentials flow to obtain an OIDC token, then assume an AWS role. This provides temporary credentials that are more secure:

```json
"secrets": {
  "OAUTH2_CLIENT_CREDENTIALS_CLIENT_SECRET": "your-client-secret"
},
"environment": {
  "OAUTH2_CLIENT_CREDENTIALS_CLIENT_ID": "your-client-id",
  "OAUTH2_CLIENT_CREDENTIALS_TOKEN_URL": "https://login.microsoftonline.com/tenant-id/oauth2/v2.0/token",
  "OAUTH2_CLIENT_CREDENTIALS_SCOPE": "api://aud/.default",
  "AWS_ASSUME_ROLE_WEB_IDENTITY_REGION": "us-east-1",
  "AWS_ASSUME_ROLE_WEB_IDENTITY_ROLE_ARN": "arn:aws:iam::123456789012:role/MyRole"
}
```

**How it works:**
1. Obtains OAuth2 access token using client credentials
2. Calls AWS STS `AssumeRoleWithWebIdentity` with the token
3. Receives temporary AWS credentials (access key, secret, session token)
4. Uses temporary credentials to call AWS IAM APIs

## Error Handling

The action includes comprehensive error handling:

### Successful Cases
- **200 OK**: Policy successfully applied to role

### Error Cases
- **NoSuchEntityException**: Role not found
- **AccessDeniedException**: Insufficient IAM permissions
- **InvalidClientTokenId**: Invalid AWS credentials
- **Throttling**: Rate limit exceeded (retryable)
- **MalformedPolicyDocument**: Invalid policy syntax
- **ServiceUnavailableException**: AWS service temporarily unavailable (retryable)

## Advanced Usage

### Revoke Sessions Before Specific Time

```json
{
  "roleName": "MyApplicationRole",
  "region": "us-east-1",
  "tokenIssueTime": "2024-01-15T10:30:00Z"
}
```

### With Additional Policy Conditions

Add extra IAM policy conditions to the deny policy:

```json
{
  "roleName": "MyApplicationRole",
  "region": "us-east-1",
  "conditions": {
    "StringEquals": {
      "aws:userid": "AIDAI1234567890EXAMPLE"
    }
  }
}
```

This creates a deny policy that targets specific user IDs in addition to the time-based condition.

## IAM Permissions Required

The AWS credentials (or assumed role) must have the following IAM permission:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "iam:PutRolePolicy",
      "Resource": "arn:aws:iam::*:role/*"
    }
  ]
}
```

## Development

### Local Testing

```bash
# Install dependencies
npm install

# Run tests
npm test

# Test locally with mock data
npm run dev

# Build for production
npm run build
```

### Running Tests

The action includes comprehensive unit tests covering:
- Input validation (roleName, region)
- Successful session revocation
- Both authentication methods (Basic and AssumeRoleWithWebIdentity)
- Error handling (role not found, invalid credentials, etc.)
- Additional conditions merging
- Invalid JSON conditions

```bash
# Run all tests
npm test

# Run tests in watch mode
npm run test:watch

# Check test coverage (92%+)
npm run test:coverage

# Validate metadata schema
npm run validate
```

## Security Considerations

- **Credential Protection**: Never log or expose AWS credentials or OAuth tokens
- **Audit Logging**: All session revocations are logged with timestamps
- **Input Validation**: Role name and region are validated before API calls
- **Temporary Credentials**: AssumeRoleWithWebIdentity provides time-limited credentials
- **Least Privilege**: Use IAM policies to restrict which roles can be modified

## AWS IAM API Reference

This action uses the following AWS IAM API endpoint:
- [PutRolePolicy](https://docs.aws.amazon.com/IAM/latest/APIReference/API_PutRolePolicy.html)

And for AssumeRoleWithWebIdentity authentication:
- [AssumeRoleWithWebIdentity](https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRoleWithWebIdentity.html)

## Troubleshooting

### Common Issues

1. **"Invalid or missing roleName parameter"**
   - Ensure the `roleName` parameter is provided and is a non-empty string
   - The roleName should be just the name, not the full ARN

2. **"Invalid or missing region parameter"**
   - Ensure the `region` parameter is provided (e.g., `us-east-1`, `eu-west-1`)

3. **Authentication Errors (AccessDeniedException)**
   - Verify your AWS credentials are valid and haven't expired
   - Ensure the credentials have `iam:PutRolePolicy` permission
   - For AssumeRoleWithWebIdentity, verify the trust policy allows your OIDC provider

4. **Role Not Found (NoSuchEntityException)**
   - Verify the roleName is correct
   - Check that the role exists in your AWS account
   - Ensure you're using the correct region

5. **"OAuth2ClientCredentials missing required AwsAssumeRoleWebIdentity configuration"**
   - When using OAuth2, you must provide AWS AssumeRoleWithWebIdentity environment variables
   - Ensure `AWS_ASSUME_ROLE_WEB_IDENTITY_REGION` and `AWS_ASSUME_ROLE_WEB_IDENTITY_ROLE_ARN` are set

6. **"Failed to assume AWS role with web identity"**
   - Verify the IAM role's trust policy allows your OIDC provider
   - Check that the OAuth2 token is valid and has the correct audience
   - Ensure the role ARN is correct

## Related Actions

- **[aws-revoke-user-access-tokens](https://github.com/sgnl-actions/aws-revoke-user-access-tokens)** - Revoke IAM user access keys by deleting them

## License

MIT

## Support

For issues or questions, please contact SGNL Engineering or create an issue in this repository.
