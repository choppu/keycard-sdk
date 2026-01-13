module.exports =  {
  extensionsToTreatAsEsm: ['.ts'],
  verbose: true,
  testEnvironment: 'node',
  transform: {
    '^.+\\.tsx?$': ['ts-jest', { useESM: true }]
  },
};