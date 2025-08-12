import { IAMClient, PutRolePolicyCommand } from '@aws-sdk/client-iam';

class RetryableError extends Error {
  constructor(message) {
    super(message);
    this.retryable = true;
  }
}

class FatalError extends Error {
  constructor(message) {
    super(message);
    this.retryable = false;
  }
}

const POLICY_NAME = 'AWSRevokeOlderSessions';
const POLICY_VERSION = '2012-10-17';

function createRevocationPolicy(tokenIssueTime, additionalConditions) {
  const policy = {
    Version: POLICY_VERSION,
    Statement: [{
      Effect: 'Deny',
      Action: ['*'],
      Resource: ['*'],
      Condition: {
        DateLessThan: {
          'aws:TokenIssueTime': tokenIssueTime.toISOString()
        }
      }
    }]
  };

  // Merge additional conditions if provided
  if (additionalConditions) {
    try {
      const conditions = typeof additionalConditions === 'string' 
        ? JSON.parse(additionalConditions) 
        : additionalConditions;
      
      Object.entries(conditions).forEach(([operator, context]) => {
        policy.Statement[0].Condition[operator] = {
          ...policy.Statement[0].Condition[operator],
          ...context
        };
      });
    } catch (error) {
      throw new FatalError(`Invalid conditions JSON: ${error.message}`);
    }
  }

  return JSON.stringify(policy);
}

async function applyRevocationPolicy(client, roleName, policyDocument) {
  const command = new PutRolePolicyCommand({
    RoleName: roleName,
    PolicyName: POLICY_NAME,
    PolicyDocument: policyDocument
  });

  try {
    await client.send(command);
    return true;
  } catch (error) {
    if (error.name === 'NoSuchEntityException') {
      throw new FatalError(`Role not found: ${roleName}`);
    }
    if (error.name === 'MalformedPolicyDocumentException') {
      throw new FatalError(`Invalid policy document: ${error.message}`);
    }
    if (error.name === 'UnauthorizedException' || error.name === 'AccessDeniedException') {
      throw new FatalError(`Access denied: ${error.message}`);
    }
    if (error.name === 'ThrottlingException' || error.name === 'ServiceUnavailableException') {
      throw new RetryableError(`AWS service temporarily unavailable: ${error.message}`);
    }
    throw new FatalError(`Failed to apply policy: ${error.message}`);
  }
}

function validateInputs(params) {
  if (!params.roleName || typeof params.roleName !== 'string' || params.roleName.trim() === '') {
    throw new FatalError('Invalid or missing roleName parameter');
  }
  
  if (!params.region || typeof params.region !== 'string' || params.region.trim() === '') {
    throw new FatalError('Invalid or missing region parameter');
  }
}

export default {
  invoke: async (params, context) => {
    console.log('Starting AWS Revoke Session action');
    
    try {
      validateInputs(params);
      
      const { roleName, region, conditions, tokenIssueTime } = params;
      
      console.log(`Processing role: ${roleName} in region: ${region}`);
      
      if (!context.secrets?.AWS_ACCESS_KEY_ID || !context.secrets?.AWS_SECRET_ACCESS_KEY) {
        throw new FatalError('Missing required AWS credentials in secrets');
      }
      
      // Create AWS IAM client
      const client = new IAMClient({
        region: region,
        credentials: {
          accessKeyId: context.secrets.AWS_ACCESS_KEY_ID,
          secretAccessKey: context.secrets.AWS_SECRET_ACCESS_KEY
        }
      });
      
      // Use provided tokenIssueTime or current time
      const revokeBeforeTime = tokenIssueTime ? new Date(tokenIssueTime) : new Date();
      
      console.log(`Revoking sessions with tokens issued before: ${revokeBeforeTime.toISOString()}`);
      
      // Create the revocation policy
      const policyDocument = createRevocationPolicy(revokeBeforeTime, conditions);
      
      // Apply the policy to the role
      await applyRevocationPolicy(client, roleName, policyDocument);
      
      const result = {
        roleName,
        policyName: POLICY_NAME,
        tokenIssueTime: revokeBeforeTime.toISOString(),
        applied: true,
        appliedAt: new Date().toISOString()
      };
      
      console.log('Session revocation policy applied successfully');
      return result;
      
    } catch (error) {
      console.error(`Error applying revocation policy: ${error.message}`);
      
      if (error instanceof RetryableError || error instanceof FatalError) {
        throw error;
      }
      
      throw new FatalError(`Unexpected error: ${error.message}`);
    }
  },

  error: async (params, _context) => {
    const { error } = params;
    console.error(`Error handler invoked: ${error?.message}`);
    
    // Re-throw to let framework handle retries
    throw error;
  },

  halt: async (params, _context) => {
    const { reason, roleName } = params;
    console.log(`Job is being halted (${reason})`);
    
    return {
      roleName: roleName || 'unknown',
      reason: reason || 'unknown',
      haltedAt: new Date().toISOString(),
      cleanupCompleted: true
    };
  }
};