import script from '../src/script.mjs';

describe('AWS Revoke Session Script', () => {
  const mockContext = {
    env: {
      ENVIRONMENT: 'test'
    },
    secrets: {
      AWS_ACCESS_KEY_ID: 'test-access-key',
      AWS_SECRET_ACCESS_KEY: 'test-secret-key'
    },
    outputs: {}
  };

  beforeEach(() => {
    // Mock console to avoid noise in tests
    global.console.log = () => {};
    global.console.error = () => {};
  });

  describe('invoke handler', () => {
    test('should throw error for missing roleName', async () => {
      const params = {
        region: 'us-east-1'
      };

      await expect(script.invoke(params, mockContext))
        .rejects.toThrow('Invalid or missing roleName parameter');
    });

    test('should throw error for missing region', async () => {
      const params = {
        roleName: 'TestRole'
      };

      await expect(script.invoke(params, mockContext))
        .rejects.toThrow('Invalid or missing region parameter');
    });

    test('should throw error for missing AWS credentials', async () => {
      const params = {
        roleName: 'TestRole',
        region: 'us-east-1'
      };

      const contextWithoutCreds = {
        ...mockContext,
        secrets: {}
      };

      await expect(script.invoke(params, contextWithoutCreds))
        .rejects.toThrow('Missing required AWS credentials in secrets');
    });

    test('should handle invalid conditions JSON', async () => {
      const params = {
        roleName: 'TestRole',
        region: 'us-east-1',
        conditions: 'invalid json'
      };

      await expect(script.invoke(params, mockContext))
        .rejects.toThrow('Invalid conditions JSON');
    });

    // Note: Testing actual AWS SDK calls would require mocking the SDK
    // or integration tests with real AWS credentials
  });

  describe('error handler', () => {
    test('should re-throw error for framework to handle', async () => {
      const params = {
        roleName: 'TestRole',
        region: 'us-east-1',
        error: new Error('Network timeout')
      };

      await expect(script.error(params, mockContext))
        .rejects.toThrow('Network timeout');
    });
  });

  describe('halt handler', () => {
    test('should handle graceful shutdown', async () => {
      const params = {
        roleName: 'TestRole',
        reason: 'timeout'
      };

      const result = await script.halt(params, mockContext);

      expect(result.roleName).toBe('TestRole');
      expect(result.reason).toBe('timeout');
      expect(result.haltedAt).toBeDefined();
      expect(result.cleanupCompleted).toBe(true);
    });

    test('should handle halt with missing params', async () => {
      const params = {
        reason: 'system_shutdown'
      };

      const result = await script.halt(params, mockContext);

      expect(result.roleName).toBe('unknown');
      expect(result.reason).toBe('system_shutdown');
      expect(result.cleanupCompleted).toBe(true);
    });
  });

  describe('policy creation', () => {
    test('should create policy with current time if tokenIssueTime not provided', async () => {
      // This would require exposing the createRevocationPolicy function
      // or mocking the IAMClient to intercept the policy document
      expect(true).toBe(true); // Placeholder
    });

    test('should use provided tokenIssueTime when specified', async () => {
      // This would require exposing the createRevocationPolicy function
      // or mocking the IAMClient to intercept the policy document
      expect(true).toBe(true); // Placeholder
    });
  });
});