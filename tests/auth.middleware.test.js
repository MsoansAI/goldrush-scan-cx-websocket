const request = require('supertest')
const express = require('express')

jest.mock('../src/lib/supabase', () => ({
  getUserClient: jest.fn()
}))

const { getUserClient } = require('../src/lib/supabase')
const { requireAuth } = require('../src/middleware/auth')

describe('Auth middleware: requireAuth', () => {
  let app

  beforeEach(() => {
    app = express()
    app.get('/protected', requireAuth, (req, res) => {
      res.json({ ok: true, userId: req.user.id })
    })
  })

  test('returns 401 when Authorization header missing', async () => {
    const res = await request(app).get('/protected')
    expect(res.statusCode).toBe(401)
    expect(res.body).toEqual({ success: false, error: 'Authentication required' })
  })

  test('returns 401 when token invalid', async () => {
    getUserClient.mockReturnValue({
      auth: {
        getUser: async () => ({ data: null, error: new Error('invalid') })
      }
    })
    const res = await request(app).get('/protected').set('Authorization', 'Bearer invalid')
    expect(res.statusCode).toBe(401)
    expect(res.body).toEqual({ success: false, error: 'Invalid authentication token' })
  })

  test('calls next and exposes req.user and req.supabase on valid token', async () => {
    getUserClient.mockReturnValue({
      auth: {
        getUser: async () => ({ data: { user: { id: 'user-123' } }, error: null })
      }
    })
    const res = await request(app).get('/protected').set('Authorization', 'Bearer good')
    expect(res.statusCode).toBe(200)
    expect(res.body).toEqual({ ok: true, userId: 'user-123' })
  })
})

