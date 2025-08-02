// Jest setup file for WebSocket server tests

// Set test environment
process.env.NODE_ENV = 'test'

// Global test timeout
jest.setTimeout(10000)

// Clean up console output during tests
const originalConsoleLog = console.log
const originalConsoleError = console.error

beforeEach(() => {
  // Suppress console output during tests unless debugging
  if (!process.env.DEBUG_TESTS) {
    console.log = jest.fn()
    console.error = jest.fn()
  }
})

afterEach(() => {
  // Restore console output
  if (!process.env.DEBUG_TESTS) {
    console.log = originalConsoleLog
    console.error = originalConsoleError
  }
})