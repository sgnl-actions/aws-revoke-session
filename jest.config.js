export default {
  testEnvironment: 'node',
  transform: {},
  testMatch: [
    '**/tests/**/*.test.js',
    '**/tests/**/*.test.mjs'
  ],
  moduleFileExtensions: ['js', 'mjs', 'json'],
  // Increase worker idle memory limit to reduce aggressive cleanup that causes
  // JEST-01 deprecation warnings with nock interceptors
  workerIdleMemoryLimit: '512MB'
};