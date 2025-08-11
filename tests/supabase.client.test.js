const { getAdminClient, getUserClient } = require('../src/lib/supabase')

describe('Supabase client factory', () => {
  const env = process.env
  beforeEach(() => {
    jest.resetModules()
    process.env = { ...env, SUPABASE_URL: 'https://project.supabase.co', SUPABASE_SERVICE_ROLE_KEY: 'service-key', SUPABASE_ANON_KEY: 'anon-key' }
  })
  afterEach(() => { process.env = env })

  test('getAdminClient throws when missing service key', () => {
    process.env.SUPABASE_SERVICE_ROLE_KEY = ''
    expect(() => getAdminClient()).toThrow('Missing SUPABASE_SERVICE_ROLE_KEY')
  })

  test('getAdminClient returns singleton', () => {
    const a = getAdminClient()
    const b = getAdminClient()
    expect(a).toBe(b)
  })

  test('getUserClient uses anon key', () => {
    const client = getUserClient()
    expect(client).toBeTruthy()
  })
})

