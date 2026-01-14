export default {
  extensionsToTreatAsEsm: ['.ts'],
  verbose: true,
  testEnvironment: 'node',
  transform: {
    '^.+\\.tsx?$': ['ts-jest', { useESM: true }]
  },
};