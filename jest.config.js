export default {
  extensionsToTreatAsEsm: ['.ts'],
  verbose: true,
  testEnvironment: 'node',
  transform: {
    '^.+\\.tsx?$': ['ts-jest', { useESM: true }]
  },
  moduleNameMapper: {
    '^\\./(.+)\\.js$': './$1'
  },
  modulePathIgnorePatterns: ['node_modules/'],
};