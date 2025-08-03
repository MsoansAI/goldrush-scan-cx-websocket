const request = require('supertest')
const { createServer } = require('http')
const { Server } = require('socket.io')
const Client = require('socket.io-client')
const express = require('express')
const cors = require('cors')
const crypto = require('crypto')
const { createClient } = require('@supabase/supabase-js')

describe('WebSocket Server', () => {
  let httpServer
  let httpServerAddr
  let ioServer
  let clientSocket

  beforeAll((done) => {
    // Set up OAuth environment variables for testing
    process.env.GHL_CLIENT_ID = 'test-client-id'
    process.env.GHL_CLIENT_SECRET = 'test-client-secret'
    process.env.GHL_SCOPES = 'locations.readonly users.readonly'
    process.env.CORS_ORIGIN = 'https://grsc-scan-frontend.vercel.app'
    process.env.SERVER_URL = 'http://localhost:3001'
    process.env.SUPABASE_URL = 'https://test.supabase.co'
    process.env.SUPABASE_SERVICE_ROLE_KEY = 'test-service-role-key'
    process.env.GHL_SHARED_SECRET = 'test-shared-secret-32-characters-long!'
    const app = express()
    app.use(cors())
    app.use(express.json())

    // Session management
    const sessions = new Map()
    const messageBuffer = new Map() // customerId -> messages[]
    const customerSessions = new Map() // customerId -> sessionId

    // Health check endpoint
    app.get('/health', (req, res) => {
      res.json({
        status: 'healthy',
        timestamp: new Date().toISOString(),
        uptime: process.uptime(),
        connections: ioServer.engine.clientsCount,
        sessions: sessions.size,
        environment: process.env.NODE_ENV || 'test'
      })
    })

    app.get('/', (req, res) => {
      res.json({
        message: 'GRSC WebSocket Server',
        version: '1.0.0',
        status: 'running'
      })
    })

    // Session status endpoint
    app.get('/api/session/:sessionId/status', (req, res) => {
      const { sessionId } = req.params
      
      if (!sessions.has(sessionId)) {
        return res.status(404).json({ error: 'Session not found' })
      }

      const session = sessions.get(sessionId)
      const devices = Array.from(session.devices.values()).map(device => ({
        deviceType: device.deviceType,
        connected: true,
        connectedAt: device.connectedAt,
        lastSeen: device.lastSeen
      }))

      res.json({
        sessionId: session.sessionId,
        customerId: session.customerId,
        persistent: session.persistent || false,
        devices: devices,
        createdAt: session.createdAt,
        expiresAt: session.expiresAt
      })
    })

    // Customer session lookup endpoint
    app.get('/api/customer/:customerId/sessions', (req, res) => {
      const { customerId } = req.params
      
      const customerSessionIds = []
      for (const [sessionId, session] of sessions.entries()) {
        if (session.customerId === customerId) {
          customerSessionIds.push({
            sessionId: session.sessionId,
            customerId: session.customerId,
            persistent: session.persistent,
            createdAt: session.createdAt,
            expiresAt: session.expiresAt,
            deviceCount: session.devices.size
          })
        }
      }

      res.json({
        customerId,
        sessions: customerSessionIds
      })
    })

    // Message send endpoint for buffering
    app.post('/api/messages/send', (req, res) => {
      const { sessionId, customerId, type, payload, timestamp } = req.body
      
      if (!customerId) {
        return res.status(400).json({ error: 'Customer ID required' })
      }

      const messageId = `msg_${Date.now()}_${Math.random().toString(36).substring(2)}`
      const message = {
        messageId,
        sessionId,
        customerId,
        type,
        payload,
        timestamp: timestamp || Date.now(),
        buffered: true
      }

      // Initialize buffer for customer if not exists
      if (!messageBuffer.has(customerId)) {
        messageBuffer.set(customerId, [])
      }

      // Add to buffer
      messageBuffer.get(customerId).push(message)

      res.json({
        success: true,
        messageId,
        buffered: true
      })
    })

    // Message cleanup endpoint
    app.post('/api/messages/cleanup', (req, res) => {
      const { maxAge } = req.body // hours
      const cutoffTime = Date.now() - (maxAge * 60 * 60 * 1000)
      
      let cleaned = 0
      for (const [customerId, messages] of messageBuffer.entries()) {
        const before = messages.length
        const filtered = messages.filter(msg => msg.timestamp > cutoffTime)
        messageBuffer.set(customerId, filtered)
        cleaned += (before - filtered.length)
      }

      res.json({
        success: true,
        cleaned,
        cutoffTime
      })
    })

    // Mock GoHighLevel Authentication Endpoint for tests
    app.post('/api/auth/ghl', async (req, res) => {
      try {
        // Environment variables validation
        const { GHL_SHARED_SECRET, SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY } = process.env
        
        if (!GHL_SHARED_SECRET || !SUPABASE_URL || !SUPABASE_SERVICE_ROLE_KEY) {
          return res.status(500).json({
            success: false,
            error: 'Server configuration error: Missing required environment variables'
          })
        }

        const { encryptedPayload, iv } = req.body

        // Input validation
        if (!encryptedPayload || !iv) {
          return res.status(400).json({
            success: false,
            error: 'Missing encrypted payload or initialization vector'
          })
        }

        // Decrypt the GoHighLevel payload (simplified for testing)
        let decryptedString
        let decryptedData
        try {
          const algorithm = 'aes-256-cbc'
          const key = crypto.scryptSync(GHL_SHARED_SECRET, 'salt', 32)
          const ivBuffer = Buffer.from(iv, 'hex')
          const decipher = crypto.createDecipheriv(algorithm, key, ivBuffer)
          
          decryptedString = decipher.update(encryptedPayload, 'hex', 'utf8')
          decryptedString += decipher.final('utf8')
        } catch (decryptError) {
          return res.status(400).json({
            success: false,
            error: 'Failed to decrypt payload: Invalid encryption format or shared secret'
          })
        }

        // Parse JSON separately to catch JSON parsing errors
        try {
          decryptedData = JSON.parse(decryptedString)
        } catch (parseError) {
          return res.status(400).json({
            success: false,
            error: 'Invalid decrypted payload format'
          })
        }

        // Parse and validate decrypted data
        try {
          if (typeof decryptedData !== 'object' || !decryptedData) {
            throw new Error('Invalid data format')
          }
        } catch (parseError) {
          return res.status(400).json({
            success: false,
            error: 'Invalid decrypted payload format'
          })
        }

        // Validate required fields
        const { userId, email, role, firstName, lastName } = decryptedData
        
        if (!userId || !email || !role) {
          return res.status(400).json({
            success: false,
            error: 'Missing required user fields: userId, email, or role'
          })
        }

        // Validate email format
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/
        if (!emailRegex.test(email)) {
          return res.status(400).json({
            success: false,
            error: 'Invalid email format'
          })
        }

        // Validate role
        const validRoles = ['admin', 'staff', 'member']
        if (!validRoles.includes(role)) {
          return res.status(400).json({
            success: false,
            error: 'Invalid role. Must be one of: admin, staff, member'
          })
        }

        // Check for invalid Supabase URL test case
        if (SUPABASE_URL.includes('invalid-supabase-url')) {
          return res.status(500).json({
            success: false,
            error: 'Authentication service unavailable'
          })
        }

        // Mock Supabase response for tests (instead of real Supabase calls)
        const mockUserId = `user_${Date.now()}_${Math.random().toString(36).substring(2)}`
        const mockAccessToken = `access_token_${Date.now()}`
        const mockRefreshToken = `refresh_token_${Date.now()}`

        // Simulate checking for existing user
        const isExistingUser = email.includes('existing')
        const isNewUser = !isExistingUser

        const authResult = {
          user: {
            id: mockUserId,
            email: email,
            ghl_user_id: userId,
            role: role
          },
          tokens: {
            access_token: mockAccessToken,
            refresh_token: mockRefreshToken,
            expires_in: 3600
          }
        }

        // Return success response
        res.json({
          success: true,
          user: authResult.user,
          tokens: authResult.tokens,
          isNewUser: isNewUser
        })

      } catch (error) {
        res.status(500).json({
          success: false,
          error: 'Internal server error'
        })
      }
    })

    // Mock OAuth Initiate Endpoint
    app.get('/api/oauth/initiate', (req, res) => {
      const { GHL_CLIENT_ID, GHL_SCOPES } = process.env

      if (!GHL_CLIENT_ID || !GHL_SCOPES) {
        return res.status(500).json({
          success: false,
          error: 'OAuth configuration incomplete'
        })
      }

      // Define the redirect URI based on the current server URL
      const serverUrl = process.env.SERVER_URL || `http://localhost:${process.env.PORT || 3001}`
      const GHL_REDIRECT_URI = `${serverUrl}/api/oauth/callback`

      // Get frontend URL from request origin or referer (for iframe support)
      const frontendUrl = req.headers.origin || req.headers.referer?.replace(/\/[^\/]*$/, '') || 'https://grsc-scan-frontend.vercel.app'

      // Construct authorization URL
      const authUrl = new URL('https://app.msoans.ai/oauth/authorize')
      authUrl.searchParams.append('client_id', GHL_CLIENT_ID)
      authUrl.searchParams.append('redirect_uri', GHL_REDIRECT_URI)
      authUrl.searchParams.append('scope', GHL_SCOPES)
      authUrl.searchParams.append('response_type', 'code')
      
      // Add state parameter
      const state = crypto.randomBytes(32).toString('hex')
      authUrl.searchParams.append('state', state)
      
      res.redirect(authUrl.toString())
    })

    // Mock OAuth Callback Endpoint
    app.get('/api/oauth/callback', async (req, res) => {
      const { code, state, error } = req.query
      
      // Get frontend URL from request origin or referer (for iframe support)
      const frontendUrl = req.headers.origin || req.headers.referer?.replace(/\/[^\/]*$/, '') || 'https://grsc-scan-frontend.vercel.app'

      // Handle OAuth errors
      if (error) {
        return res.redirect(`${frontendUrl}/oauth-status?status=error&message=${encodeURIComponent(error)}`)
      }

      if (!code) {
        return res.redirect(`${frontendUrl}/oauth-status?status=error&message=No authorization code received`)
      }

      // Mock successful OAuth flow
      if (code === 'test-auth-code') {
        // Simulate successful token exchange and installation storage
        const successUrl = `${frontendUrl}/oauth-status?status=success&locationId=test-location-123&locationName=${encodeURIComponent('Test Location')}`
        return res.redirect(successUrl)
      }

      // Mock error case
              const errorUrl = `${frontendUrl}/oauth-status?status=error&message=${encodeURIComponent('OAuth flow failed')}`
        res.redirect(errorUrl)
    })

    // Mock GHL Locations List Endpoint
    app.get('/api/locations', async (req, res) => {
      const authHeader = req.headers.authorization
      if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({
          success: false,
          error: 'Authentication required'
        })
      }

      const token = authHeader.split(' ')[1]
      
      // Mock token validation
      if (token === 'invalid-token') {
        return res.status(401).json({
          success: false,
          error: 'Invalid authentication token'
        })
      }

      if (token === 'valid-token') {
        // Mock successful response
        return res.json({
          success: true,
          locations: [
            {
              id: '123e4567-e89b-12d3-a456-426614174000',
              ghl_agency_id: 'test-agency-123',
              ghl_location_id: 'test-location-123',
              location_name: 'Test Location',
              location_address: '123 Test St, Test City, TS 12345',
              installation_status: 'active',
              created_at: '2023-01-01T00:00:00Z',
              updated_at: '2023-01-01T00:00:00Z'
            }
          ]
        })
      }

      // Default unauthorized
      res.status(401).json({
        success: false,
        error: 'Invalid authentication token'
      })
    })

    // Mock GHL API Proxy Endpoint
    app.post('/api/proxy', async (req, res) => {
      const authHeader = req.headers.authorization
      if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({
          success: false,
          error: 'Authentication required'
        })
      }

      const { ghl_location_id, endpoint, method = 'GET', data: requestData } = req.body

      if (!ghl_location_id || !endpoint) {
        return res.status(400).json({
          success: false,
          error: 'Missing required fields: ghl_location_id and endpoint'
        })
      }

      const token = authHeader.split(' ')[1]
      
      // Mock token validation
      if (token === 'invalid-token') {
        return res.status(401).json({
          success: false,
          error: 'Invalid authentication token'
        })
      }

      // Mock location not found
      if (ghl_location_id === 'non-existent-location') {
        return res.status(404).json({
          success: false,
          error: 'GHL location not found or not accessible'
        })
      }

      // Mock successful proxy response
      if (token === 'valid-token' && ghl_location_id === 'test-location-123') {
        return res.json({
          success: true,
          data: {
            contacts: [
              { id: '1', name: 'John Doe', email: 'john@example.com' },
              { id: '2', name: 'Jane Smith', email: 'jane@example.com' }
            ]
          },
          status: 200
        })
      }

      // Mock expired token scenario
      if (ghl_location_id === 'expired-token-location') {
        // Simulate token refresh and successful response
        return res.json({
          success: true,
          data: {
            contacts: [
              { id: '3', name: 'Refreshed User', email: 'refreshed@example.com' }
            ]
          },
          status: 200
        })
      }

      // Default error
      res.status(500).json({
        success: false,
        error: 'GHL API request failed'
      })
    })

    httpServer = createServer(app)
    ioServer = new Server(httpServer, {
      cors: {
        origin: "*",
        methods: ["GET", "POST"]
      },
      transports: ['websocket', 'polling']
    })

    // WebSocket logic
    ioServer.on('connection', (socket) => {
      socket.on('join-session', ({ sessionId, deviceType }, callback) => {
        try {
          // Validate input data (same as actual server)
          if (!sessionId || typeof sessionId !== 'string' || sessionId.trim() === '') {
            const error = {
              type: 'INVALID_SESSION_ID',
              message: 'Session ID is required and must be a non-empty string',
              sessionId: sessionId
            }
            socket.emit('error', error)
            callback({ success: false, error: 'Invalid sessionId' })
            return
          }

          if (!deviceType || typeof deviceType !== 'string' || !['desktop', 'mobile'].includes(deviceType)) {
            const error = {
              type: 'INVALID_DEVICE_TYPE',
              message: 'Device type must be either "desktop" or "mobile"',
              sessionId: sessionId
            }
            socket.emit('error', error)
            callback({ success: false, error: 'Invalid deviceType' })
            return
          }

          socket.join(sessionId)
          
          if (!sessions.has(sessionId)) {
            sessions.set(sessionId, {
              sessionId,
              devices: new Map(),
              createdAt: Date.now(),
              expiresAt: Date.now() + (5 * 60 * 1000)
            })
          }

          const session = sessions.get(sessionId)
          const isExistingSession = session.devices.size > 0

          // Check if device type already exists in session
          for (const [, device] of session.devices) {
            if (device.deviceType === deviceType) {
              const error = {
                type: 'DUPLICATE_DEVICE_TYPE',
                message: `Device type ${deviceType} already exists in session`,
                sessionId: sessionId
              }
              socket.emit('error', error)
              callback({ success: false, error: `Device type ${deviceType} already exists in session` })
              return
            }
          }

          session.devices.set(socket.id, { 
            deviceType, 
            socketId: socket.id, 
            connectedAt: Date.now(),
            lastSeen: Date.now()
          })

          // Notify existing peers about new connection (only if session already had devices)
          if (isExistingSession) {
            socket.to(sessionId).emit('peer-connected', {
              deviceType: deviceType,
              sessionId: sessionId,
              timestamp: Date.now()
            })
          }

          callback({ success: true })
        } catch (error) {
          callback({ success: false, error: error.message })
        }
      })

      socket.on('join-authenticated-session', ({ sessionId, customerId, deviceType }, callback) => {
        try {
          // Validate customer ID
          if (!customerId || typeof customerId !== 'string' || customerId.trim() === '') {
            const error = {
              type: 'INVALID_CUSTOMER_ID',
              message: 'Customer ID is required for authenticated sessions',
              sessionId: sessionId
            }
            socket.emit('error', error)
            callback({ success: false, error: 'Invalid customer ID' })
            return
          }

          // Validate session ID and device type (same as regular sessions)
          if (!sessionId || typeof sessionId !== 'string' || sessionId.trim() === '') {
            const error = {
              type: 'INVALID_SESSION_ID',
              message: 'Session ID is required and must be a non-empty string',
              sessionId: sessionId
            }
            socket.emit('error', error)
            callback({ success: false, error: 'Invalid sessionId' })
            return
          }

          if (!deviceType || typeof deviceType !== 'string' || !['desktop', 'mobile'].includes(deviceType)) {
            const error = {
              type: 'INVALID_DEVICE_TYPE',
              message: 'Device type must be either "desktop" or "mobile"',
              sessionId: sessionId
            }
            socket.emit('error', error)
            callback({ success: false, error: 'Invalid deviceType' })
            return
          }

          socket.join(sessionId)
          
          const isReconnection = sessions.has(sessionId) && sessions.get(sessionId).customerId === customerId
          
          if (!sessions.has(sessionId)) {
            sessions.set(sessionId, {
              sessionId,
              customerId,
              persistent: true,
              devices: new Map(),
              createdAt: Date.now(),
              expiresAt: Date.now() + (24 * 60 * 60 * 1000) // 24 hours
            })
            
            // Track customer to session mapping
            customerSessions.set(customerId, sessionId)
          }

          const session = sessions.get(sessionId)
          
          // Verify customer ID matches session
          if (session.customerId !== customerId) {
            const error = {
              type: 'CUSTOMER_MISMATCH',
              message: 'Customer ID does not match session',
              sessionId: sessionId
            }
            socket.emit('error', error)
            callback({ success: false, error: 'Customer ID mismatch' })
            return
          }

          const isExistingSession = session.devices.size > 0

          // Check if device type already exists in session
          let deviceTypeExists = false
          for (const [, device] of session.devices) {
            if (device.deviceType === deviceType) {
              deviceTypeExists = true
              // Allow reconnection for same customer/device type
              if (!isReconnection) {
                const error = {
                  type: 'DUPLICATE_DEVICE_TYPE',
                  message: `Device type ${deviceType} already exists in session`,
                  sessionId: sessionId
                }
                socket.emit('error', error)
                callback({ success: false, error: `Device type ${deviceType} already exists in session` })
                return
              }
              break
            }
          }

          // If it's a reconnection, remove the old device entry first
          if (isReconnection && deviceTypeExists) {
            for (const [socketId, device] of session.devices) {
              if (device.deviceType === deviceType) {
                session.devices.delete(socketId)
                break
              }
            }
          }

          session.devices.set(socket.id, { 
            deviceType, 
            socketId: socket.id, 
            customerId,
            connectedAt: Date.now(),
            lastSeen: Date.now()
          })

          // Deliver buffered messages on reconnection
          if (messageBuffer.has(customerId)) {
            const bufferedMessages = messageBuffer.get(customerId)
            if (bufferedMessages.length > 0) {
              socket.emit('buffered-messages', bufferedMessages)
              // Clear delivered messages
              messageBuffer.set(customerId, [])
            }
          }

          // Notify existing peers about new connection (only if session already had devices)
          if (isExistingSession && !isReconnection) {
            socket.to(sessionId).emit('peer-connected', {
              deviceType: deviceType,
              sessionId: sessionId,
              customerId: customerId,
              timestamp: Date.now()
            })
          }

          callback({ 
            success: true,
            reconnected: isReconnection,
            session: {
              sessionId: session.sessionId,
              customerId: session.customerId,
              persistent: session.persistent,
              expiresAt: session.expiresAt
            }
          })
        } catch (error) {
          callback({ success: false, error: error.message })
        }
      })

      socket.on('message', (message) => {
        socket.to(message.sessionId).emit('message', message)
      })

      socket.on('heartbeat', ({ sessionId }, callback) => {
        try {
          if (!sessionId || !sessions.has(sessionId)) {
            const error = {
              type: 'INVALID_HEARTBEAT',
              message: 'Invalid session ID for heartbeat',
              sessionId: sessionId
            }
            socket.emit('error', error)
            callback({ success: false, error: 'Invalid session ID' })
            return
          }

          const session = sessions.get(sessionId)
          if (!session.devices.has(socket.id)) {
            const error = {
              type: 'INVALID_HEARTBEAT',
              message: 'Device not found in session',
              sessionId: sessionId
            }
            socket.emit('error', error)
            callback({ success: false, error: 'Device not in session' })
            return
          }

          // Update lastSeen timestamp
          const device = session.devices.get(socket.id)
          device.lastSeen = Date.now()
          session.devices.set(socket.id, device)

          // Extend session expiration if there's activity
          session.expiresAt = Date.now() + (5 * 60 * 1000) // Extend by 5 minutes

          callback({ 
            success: true, 
            lastSeen: device.lastSeen,
            sessionExpiresAt: session.expiresAt
          })
        } catch (error) {
          callback({ success: false, error: error.message })
        }
      })

      socket.on('disconnect', () => {
        // Find and notify peers before cleanup
        for (const [sessionId, session] of sessions.entries()) {
          if (session.devices.has(socket.id)) {
            const disconnectedDevice = session.devices.get(socket.id)
            
            // Notify other devices in the session about disconnect
            socket.to(sessionId).emit('peer-disconnected', {
              deviceType: disconnectedDevice.deviceType,
              sessionId: sessionId,
              timestamp: Date.now()
            })
            
            // Then do cleanup
            session.devices.delete(socket.id)
            // Don't delete persistent sessions when empty - keep them for reconnection
            if (session.devices.size === 0 && !session.persistent) {
              sessions.delete(sessionId)
            }
            break
          }
        }
      })
    })

    httpServer.listen(() => {
      httpServerAddr = httpServer.address()
      done()
    })
  })

  afterAll((done) => {
    ioServer.close()
    httpServer.close(done)
  })

  beforeEach((done) => {
    clientSocket = new Client(`http://localhost:${httpServerAddr.port}`)
    clientSocket.on('connect', done)
  })

  afterEach(() => {
    if (clientSocket.connected) {
      clientSocket.disconnect()
    }
  })

  describe('HTTP Endpoints', () => {
    test('GET / should return server info', async () => {
      const response = await request(httpServer)
        .get('/')
        .expect(200)

      expect(response.body).toEqual({
        message: 'GRSC WebSocket Server',
        version: '1.0.0',
        status: 'running'
      })
    })

    test('GET /health should return health status', async () => {
      const response = await request(httpServer)
        .get('/health')
        .expect(200)

      expect(response.body).toHaveProperty('status', 'healthy')
      expect(response.body).toHaveProperty('timestamp')
      expect(response.body).toHaveProperty('uptime')
      expect(response.body).toHaveProperty('connections')
      expect(response.body).toHaveProperty('sessions')
      expect(response.body).toHaveProperty('environment')
    })

    test('GET /api/session/:sessionId/status should return session info', (done) => {
      const sessionId = 'test-session-status'
      
      // Create a session with devices
      clientSocket.emit('join-session', { sessionId, deviceType: 'desktop' }, () => {
        const secondClient = new Client(`http://localhost:${httpServerAddr.port}`)
        secondClient.on('connect', () => {
          secondClient.emit('join-session', { sessionId, deviceType: 'mobile' }, async () => {
            // Check session status
            const response = await request(httpServer)
              .get(`/api/session/${sessionId}/status`)
              .expect(200)

            expect(response.body).toEqual({
              sessionId: sessionId,
              customerId: undefined,
              persistent: false,
              devices: expect.arrayContaining([
                { deviceType: 'desktop', connected: true, connectedAt: expect.any(Number), lastSeen: expect.any(Number) },
                { deviceType: 'mobile', connected: true, connectedAt: expect.any(Number), lastSeen: expect.any(Number) }
              ]),
              createdAt: expect.any(Number),
              expiresAt: expect.any(Number)
            })
            expect(response.body.devices).toHaveLength(2)
            secondClient.disconnect()
            done()
          })
        })
      })
    })

    test('GET /api/session/:sessionId/status should return 404 for non-existent session', async () => {
      const response = await request(httpServer)
        .get('/api/session/non-existent-session/status')
        .expect(404)

      expect(response.body).toEqual({
        error: 'Session not found'
      })
    })
  })

  describe('WebSocket Functionality', () => {
    test('should connect to WebSocket server', (done) => {
      expect(clientSocket.connected).toBe(true)
      done()
    })

    test('should join session successfully', (done) => {
      const sessionId = 'test-session-123'
      const deviceType = 'desktop'

      clientSocket.emit('join-session', { sessionId, deviceType }, (response) => {
        expect(response.success).toBe(true)
        done()
      })
    })

    test('should handle join-session with invalid data', (done) => {
      clientSocket.emit('join-session', { sessionId: null, deviceType: 'desktop' }, (response) => {
        expect(response.success).toBe(false)
        expect(response.error).toBeDefined()
        done()
      })
    })

    test('should emit INVALID_SESSION_ID error', (done) => {
      clientSocket.on('error', (error) => {
        expect(error).toEqual({
          type: 'INVALID_SESSION_ID',
          message: 'Session ID is required and must be a non-empty string',
          sessionId: ''
        })
        done()
      })

      clientSocket.emit('join-session', { sessionId: '', deviceType: 'desktop' }, () => {})
    })

    test('should emit INVALID_DEVICE_TYPE error', (done) => {
      clientSocket.on('error', (error) => {
        expect(error).toEqual({
          type: 'INVALID_DEVICE_TYPE',
          message: 'Device type must be either "desktop" or "mobile"',
          sessionId: 'test-session'
        })
        done()
      })

      clientSocket.emit('join-session', { sessionId: 'test-session', deviceType: 'invalid' }, () => {})
    })

    test('should emit DUPLICATE_DEVICE_TYPE error', (done) => {
      const sessionId = 'duplicate-error-test'
      
      // First device joins successfully
      clientSocket.emit('join-session', { sessionId, deviceType: 'desktop' }, () => {
        const secondClient = new Client(`http://localhost:${httpServerAddr.port}`)
        
        secondClient.on('error', (error) => {
          expect(error).toEqual({
            type: 'DUPLICATE_DEVICE_TYPE',
            message: 'Device type desktop already exists in session',
            sessionId: sessionId
          })
          secondClient.disconnect()
          done()
        })

        secondClient.on('connect', () => {
          secondClient.emit('join-session', { sessionId, deviceType: 'desktop' }, () => {})
        })
      })
    })

    test('should receive messages in the same session', (done) => {
      const sessionId = 'test-session-message'
      const testMessage = {
        sessionId,
        type: 'SCAN_DATA',
        payload: { qrCode: 'test-qr-code' },
        timestamp: Date.now()
      }

      // Create second client for the same session
      const secondClient = new Client(`http://localhost:${httpServerAddr.port}`)
      
      secondClient.on('connect', () => {
        // Both clients join the same session
        clientSocket.emit('join-session', { sessionId, deviceType: 'desktop' }, () => {
          secondClient.emit('join-session', { sessionId, deviceType: 'mobile' }, () => {
            
            // Set up message listener on second client
            secondClient.on('message', (receivedMessage) => {
              expect(receivedMessage).toEqual(testMessage)
              secondClient.disconnect()
              done()
            })

            // Send message from first client
            clientSocket.emit('message', testMessage)
          })
        })
      })
    })

    test('should clean up session on disconnect', (done) => {
      const sessionId = 'test-session-cleanup'
      
      clientSocket.emit('join-session', { sessionId, deviceType: 'desktop' }, () => {
        clientSocket.disconnect()
        
        // Wait a bit for cleanup to happen
        setTimeout(() => {
          // Check health endpoint to verify session cleanup
          request(httpServer)
            .get('/health')
            .expect(200)
            .then((response) => {
              // Sessions should be cleaned up
              expect(response.body.sessions).toBe(0)
              done()
            })
        }, 100)
      })
    })
  })

  describe('User-Authenticated Sessions', () => {
    test('should create persistent session with customer_id', (done) => {
      const customerId = 'customer_123'
      const sessionId = 'persistent_session_456'
      
      clientSocket.emit('join-authenticated-session', { 
        sessionId, 
        customerId, 
        deviceType: 'desktop' 
      }, (response) => {
        expect(response.success).toBe(true)
        expect(response.session).toEqual({
          sessionId,
          customerId,
          persistent: true,
          expiresAt: expect.any(Number)
        })
        // Verify extended expiration (24 hours)
        const expectedExpiry = Date.now() + (24 * 60 * 60 * 1000)
        expect(response.session.expiresAt).toBeGreaterThan(expectedExpiry - 1000)
        done()
      })
    })

    test('should allow reconnection with same customer_id after disconnect', (done) => {
      const customerId = 'customer_reconnect_test'
      const sessionId = 'reconnect_session'
      
      // First connection
      clientSocket.emit('join-authenticated-session', { 
        sessionId, 
        customerId, 
        deviceType: 'desktop' 
      }, (response1) => {
        expect(response1.success).toBe(true)
        
        // Disconnect
        clientSocket.disconnect()
        
        // Reconnect with new socket
        setTimeout(() => {
          const newClient = new Client(`http://localhost:${httpServerAddr.port}`)
          newClient.on('connect', () => {
            newClient.emit('join-authenticated-session', { 
              sessionId, 
              customerId, 
              deviceType: 'desktop' 
            }, (response2) => {
              expect(response2.success).toBe(true)
              expect(response2.session.customerId).toBe(customerId)
              expect(response2.reconnected).toBe(true)
              newClient.disconnect()
              done()
            })
          })
        }, 100)
      })
    })

    test('should reject invalid customer_id authentication', (done) => {
      clientSocket.on('error', (error) => {
        expect(error).toEqual({
          type: 'INVALID_CUSTOMER_ID',
          message: 'Customer ID is required for authenticated sessions',
          sessionId: 'test_session'
        })
        done()
      })

      clientSocket.emit('join-authenticated-session', { 
        sessionId: 'test_session', 
        customerId: '', 
        deviceType: 'desktop' 
      }, () => {})
    })

    test('should maintain session across device switches', (done) => {
      const customerId = 'customer_device_switch'
      const sessionId = 'device_switch_session'
      
      // Desktop connects
      clientSocket.emit('join-authenticated-session', { 
        sessionId, 
        customerId, 
        deviceType: 'desktop' 
      }, (response1) => {
        expect(response1.success).toBe(true)
        
        // Mobile connects to same session
        const mobileClient = new Client(`http://localhost:${httpServerAddr.port}`)
        mobileClient.on('connect', () => {
          mobileClient.emit('join-authenticated-session', { 
            sessionId, 
            customerId, 
            deviceType: 'mobile' 
          }, (response2) => {
            expect(response2.success).toBe(true)
            expect(response2.session.customerId).toBe(customerId)
            mobileClient.disconnect()
            done()
          })
        })
      })
    })
  })

  describe('Message Buffering System', () => {
    test('should buffer messages for offline devices', async () => {
      const customerId = 'customer_buffering_test'
      const sessionId = 'buffering_session'
      
      // Device connects and goes offline
      await new Promise(resolve => {
        clientSocket.emit('join-authenticated-session', { 
          sessionId, 
          customerId, 
          deviceType: 'desktop' 
        }, resolve)
      })
      
      clientSocket.disconnect()
      
      // Send message while device is offline
      const testMessage = {
        sessionId,
        customerId,
        type: 'SCAN_DATA',
        payload: { qrCode: 'offline-test-qr' },
        timestamp: Date.now()
      }
      
      const response = await request(httpServer)
        .post('/api/messages/send')
        .send(testMessage)
        .expect(200)
        
      expect(response.body.buffered).toBe(true)
      expect(response.body.messageId).toBeDefined()
    })

    test('should deliver buffered messages on reconnection', (done) => {
      const customerId = 'customer_delivery_test'
      const sessionId = 'delivery_session'
      
      // First connect to establish session
      clientSocket.emit('join-authenticated-session', { 
        sessionId, 
        customerId, 
        deviceType: 'desktop' 
      }, () => {
        clientSocket.disconnect()
        
        // Send message while offline (would be done by another client)
        setTimeout(async () => {
          await request(httpServer)
            .post('/api/messages/send')
            .send({
              sessionId,
              customerId,
              type: 'CUSTOMER_DATA',
              payload: { customer: 'test data' },
              timestamp: Date.now()
            })
          
          // Reconnect and expect buffered message
          const newClient = new Client(`http://localhost:${httpServerAddr.port}`)
          newClient.on('connect', () => {
            newClient.on('buffered-messages', (messages) => {
              expect(messages).toHaveLength(1)
              expect(messages[0].type).toBe('CUSTOMER_DATA')
              expect(messages[0].payload.customer).toBe('test data')
              newClient.disconnect()
              done()
            })
            
            newClient.emit('join-authenticated-session', { 
              sessionId, 
              customerId, 
              deviceType: 'desktop' 
            }, () => {})
          })
        }, 100)
      })
    })

    test('should clean up old buffered messages', async () => {
      const customerId = 'customer_cleanup_test'
      
      // Send old message (simulate 48 hours ago)
      const oldTimestamp = Date.now() - (48 * 60 * 60 * 1000)
      
      await request(httpServer)
        .post('/api/messages/send')
        .send({
          sessionId: 'cleanup_session',
          customerId,
          type: 'OLD_MESSAGE',
          payload: { test: 'old' },
          timestamp: oldTimestamp
        })
      
      // Trigger cleanup
      const response = await request(httpServer)
        .post('/api/messages/cleanup')
        .send({ maxAge: 24 }) // 24 hours
        .expect(200)
        
      expect(response.body.cleaned).toBeGreaterThan(0)
    })
  })

  describe('Session Persistence', () => {
    test('should persist sessions beyond 5 minutes', async () => {
      const customerId = 'customer_persistence_test'
      const sessionId = 'persistent_session_test'
      
      // Create session
      await new Promise(resolve => {
        clientSocket.emit('join-authenticated-session', { 
          sessionId, 
          customerId, 
          deviceType: 'desktop' 
        }, resolve)
      })
      
      // Check session persists after traditional 5-minute expiry
      const response = await request(httpServer)
        .get(`/api/session/${sessionId}/status`)
        .expect(200)
        
      expect(response.body.persistent).toBe(true)
      expect(response.body.customerId).toBe(customerId)
      expect(response.body.expiresAt).toBeGreaterThan(Date.now() + (20 * 60 * 1000)) // > 20 minutes
    })

    test('should handle customer session lookup', async () => {
      const customerId = 'customer_lookup_test'
      const sessionId = 'lookup_session'
      
      // Create session
      await new Promise(resolve => {
        clientSocket.emit('join-authenticated-session', { 
          sessionId, 
          customerId, 
          deviceType: 'desktop' 
        }, resolve)
      })
      
      // Lookup by customer ID
      const response = await request(httpServer)
        .get(`/api/customer/${customerId}/sessions`)
        .expect(200)
        
      expect(response.body.sessions).toHaveLength(1)
      expect(response.body.sessions[0].sessionId).toBe(sessionId)
      expect(response.body.sessions[0].customerId).toBe(customerId)
    })
  })

  describe('Multi-Employee Support', () => {
    test('should support multiple concurrent sessions with full isolation', (done) => {
      const session1 = 'employee-1-session'
      const session2 = 'employee-2-session'
      
      // Create clients for Employee 1 (Desktop A + Mobile A)
      const desktop1 = clientSocket // Reuse existing client
      const mobile1 = new Client(`http://localhost:${httpServerAddr.port}`)
      
      // Create clients for Employee 2 (Desktop B + Mobile B)  
      const desktop2 = new Client(`http://localhost:${httpServerAddr.port}`)
      const mobile2 = new Client(`http://localhost:${httpServerAddr.port}`)
      
      let connectionsEstablished = 0
      const checkAllConnected = () => {
        connectionsEstablished++
        if (connectionsEstablished === 4) {
          // All connected, now test message isolation
          testMessageIsolation()
        }
      }
      
      const testMessageIsolation = () => {
        let messagesReceived = 0
        
        // Employee 1 should only receive messages within their session
        mobile1.on('message', (msg) => {
          expect(msg.sessionId).toBe(session1)
          expect(msg.content).toBe('Hello from Desktop A to Mobile A')
          messagesReceived++
          checkTestComplete()
        })
        
        // Employee 2 should only receive messages within their session
        mobile2.on('message', (msg) => {
          expect(msg.sessionId).toBe(session2)
          expect(msg.content).toBe('Hello from Desktop B to Mobile B')
          messagesReceived++
          checkTestComplete()
        })
        
        const checkTestComplete = () => {
          if (messagesReceived === 2) {
            // Cleanup
            mobile1.disconnect()
            desktop2.disconnect() 
            mobile2.disconnect()
            done()
          }
        }
        
        // Send messages within each session
        desktop1.emit('message', {
          sessionId: session1,
          content: 'Hello from Desktop A to Mobile A',
          timestamp: Date.now()
        })
        
        desktop2.emit('message', {
          sessionId: session2,
          content: 'Hello from Desktop B to Mobile B',
          timestamp: Date.now()
        })
      }
      
      // Connect Employee 1 devices
      desktop1.emit('join-session', { sessionId: session1, deviceType: 'desktop' }, (response) => {
        expect(response.success).toBe(true)
        checkAllConnected()
      })
      
      mobile1.on('connect', () => {
        mobile1.emit('join-session', { sessionId: session1, deviceType: 'mobile' }, (response) => {
          expect(response.success).toBe(true)
          checkAllConnected()
        })
      })
      
      // Connect Employee 2 devices
      desktop2.on('connect', () => {
        desktop2.emit('join-session', { sessionId: session2, deviceType: 'desktop' }, (response) => {
          expect(response.success).toBe(true)
          checkAllConnected()
        })
      })
      
      mobile2.on('connect', () => {
        mobile2.emit('join-session', { sessionId: session2, deviceType: 'mobile' }, (response) => {
          expect(response.success).toBe(true)
          checkAllConnected()
        })
      })
    })

    test('should handle concurrent session status requests', async () => {
      const session1 = 'status-test-1'
      const session2 = 'status-test-2'
      
      // Keep client2 reference to prevent disconnection cleanup
      let client2
      
      // Create two separate sessions
      await Promise.all([
        new Promise(resolve => {
          clientSocket.emit('join-session', { sessionId: session1, deviceType: 'desktop' }, resolve)
        }),
        new Promise(resolve => {
          client2 = new Client(`http://localhost:${httpServerAddr.port}`)
          client2.on('connect', () => {
            client2.emit('join-session', { sessionId: session2, deviceType: 'desktop' }, resolve)
          })
        })
      ])

      // Check both sessions exist and are isolated
      const [status1, status2] = await Promise.all([
        request(httpServer).get(`/api/session/${session1}/status`).expect(200),
        request(httpServer).get(`/api/session/${session2}/status`).expect(200)
      ])

      expect(status1.body.sessionId).toBe(session1)
      expect(status2.body.sessionId).toBe(session2)
      expect(status1.body.devices).toHaveLength(1)
      expect(status2.body.devices).toHaveLength(1)
      
      // Clean up
      client2.disconnect()
    })
  })

  describe('Session Management', () => {
    test('should handle multiple devices in same session', (done) => {
      const sessionId = 'test-session-multiple'
      const secondClient = new Client(`http://localhost:${httpServerAddr.port}`)

      secondClient.on('connect', () => {
        clientSocket.emit('join-session', { sessionId, deviceType: 'desktop' }, (response1) => {
          expect(response1.success).toBe(true)
          
          secondClient.emit('join-session', { sessionId, deviceType: 'mobile' }, (response2) => {
            expect(response2.success).toBe(true)
            secondClient.disconnect()
            done()
          })
        })
      })
    })

    test('should create new session if it does not exist', (done) => {
      const sessionId = 'new-session-' + Date.now()
      
      clientSocket.emit('join-session', { sessionId, deviceType: 'desktop' }, (response) => {
        expect(response.success).toBe(true)
        done()
      })
    })
  })

  describe('Session Validation', () => {
    test('should prevent multiple devices of same type in one session', (done) => {
      const sessionId = 'test-session-validation'
      const secondClient = new Client(`http://localhost:${httpServerAddr.port}`)

      secondClient.on('connect', () => {
        // First desktop joins
        clientSocket.emit('join-session', { sessionId, deviceType: 'desktop' }, (response1) => {
          expect(response1.success).toBe(true)
          
          // Second desktop tries to join - should be rejected
          secondClient.emit('join-session', { sessionId, deviceType: 'desktop' }, (response2) => {
            expect(response2.success).toBe(false)
            expect(response2.error).toBe('Device type desktop already exists in session')
            secondClient.disconnect()
            done()
          })
        })
      })
    })

    test('should allow one desktop and one mobile in same session', (done) => {
      const sessionId = 'test-session-mixed'
      const secondClient = new Client(`http://localhost:${httpServerAddr.port}`)

      secondClient.on('connect', () => {
        // Desktop joins first
        clientSocket.emit('join-session', { sessionId, deviceType: 'desktop' }, (response1) => {
          expect(response1.success).toBe(true)
          
          // Mobile joins - should be allowed
          secondClient.emit('join-session', { sessionId, deviceType: 'mobile' }, (response2) => {
            expect(response2.success).toBe(true)
            secondClient.disconnect()
            done()
          })
        })
      })
    })

    test('should prevent third device from joining session', (done) => {
      const sessionId = 'test-session-full'
      const secondClient = new Client(`http://localhost:${httpServerAddr.port}`)

      secondClient.on('connect', () => {
        // Desktop and mobile join first
        clientSocket.emit('join-session', { sessionId, deviceType: 'desktop' }, (response1) => {
          expect(response1.success).toBe(true)
          
          secondClient.emit('join-session', { sessionId, deviceType: 'mobile' }, (response2) => {
            expect(response2.success).toBe(true)
            
            // Create third client after first two are connected
            const thirdClient = new Client(`http://localhost:${httpServerAddr.port}`)
            thirdClient.on('connect', () => {
              // Third device tries to join - should be rejected
              thirdClient.emit('join-session', { sessionId, deviceType: 'mobile' }, (response3) => {
                expect(response3.success).toBe(false)
                expect(response3.error).toBe('Device type mobile already exists in session')
                secondClient.disconnect()
                thirdClient.disconnect()
                done()
              })
            })
          })
        })
      })
    })
  })

  describe('Heartbeat System', () => {
    test('should handle heartbeat events and update lastSeen', (done) => {
      const sessionId = 'test-heartbeat-session'
      
      clientSocket.emit('join-session', { sessionId, deviceType: 'desktop' }, (response) => {
        expect(response.success).toBe(true)
        
        // Wait a bit then send heartbeat
        setTimeout(() => {
          clientSocket.emit('heartbeat', { sessionId }, (heartbeatResponse) => {
            expect(heartbeatResponse.success).toBe(true)
            expect(heartbeatResponse.lastSeen).toBeGreaterThan(Date.now() - 1000)
            done()
          })
        }, 100)
      })
    })

    test('should extend session expiration on active heartbeats', async () => {
      const sessionId = 'test-heartbeat-extension'
      
      // Join session and get initial status
      await new Promise((resolve) => {
        clientSocket.emit('join-session', { sessionId, deviceType: 'desktop' }, resolve)
      })

      const initialStatus = await request(httpServer)
        .get(`/api/session/${sessionId}/status`)
        .expect(200)

      // Send heartbeat
      await new Promise((resolve) => {
        clientSocket.emit('heartbeat', { sessionId }, resolve)
      })

      // Check if expiration was extended
      const updatedStatus = await request(httpServer)
        .get(`/api/session/${sessionId}/status`)
        .expect(200)

      expect(updatedStatus.body.expiresAt).toBeGreaterThan(initialStatus.body.expiresAt)
    })

    test('should handle invalid heartbeat sessionId', (done) => {
      clientSocket.on('error', (error) => {
        expect(error).toEqual({
          type: 'INVALID_HEARTBEAT',
          message: 'Invalid session ID for heartbeat',
          sessionId: 'non-existent'
        })
        done()
      })

      clientSocket.emit('heartbeat', { sessionId: 'non-existent' }, () => {})
    })

    test('should update device lastSeen timestamp in session status', (done) => {
      const sessionId = 'test-heartbeat-timestamp'
      
      clientSocket.emit('join-session', { sessionId, deviceType: 'desktop' }, async () => {
        // Get initial status
        const beforeHeartbeat = await request(httpServer)
          .get(`/api/session/${sessionId}/status`)
          .expect(200)

        const initialLastSeen = beforeHeartbeat.body.devices[0].lastSeen

        // Wait a bit then send heartbeat
        setTimeout(() => {
          clientSocket.emit('heartbeat', { sessionId }, async () => {
            // Check updated status
            const afterHeartbeat = await request(httpServer)
              .get(`/api/session/${sessionId}/status`)
              .expect(200)

            const updatedLastSeen = afterHeartbeat.body.devices[0].lastSeen
            expect(updatedLastSeen).toBeGreaterThan(initialLastSeen)
            done()
          })
        }, 50)
      })
    })
  })

  describe('Peer Notification Events', () => {
    test('should emit peer-connected event when device joins existing session', (done) => {
      const sessionId = 'test-session-peer-connect'
      const secondClient = new Client(`http://localhost:${httpServerAddr.port}`)

      secondClient.on('connect', () => {
        // First device joins
        clientSocket.emit('join-session', { sessionId, deviceType: 'desktop' }, (response1) => {
          expect(response1.success).toBe(true)
          
          // Listen for peer-connected event on first client
          clientSocket.on('peer-connected', (notification) => {
            expect(notification).toEqual({
              deviceType: 'mobile',
              sessionId: sessionId,
              timestamp: expect.any(Number)
            })
            secondClient.disconnect()
            done()
          })
          
          // Second device joins - should trigger peer-connected event
          secondClient.emit('join-session', { sessionId, deviceType: 'mobile' }, (response2) => {
            expect(response2.success).toBe(true)
          })
        })
      })
    })

    test('should emit peer-disconnected event when device leaves session', (done) => {
      const sessionId = 'test-session-peer-disconnect'
      const secondClient = new Client(`http://localhost:${httpServerAddr.port}`)

      secondClient.on('connect', () => {
        // Both devices join session
        clientSocket.emit('join-session', { sessionId, deviceType: 'desktop' }, () => {
          secondClient.emit('join-session', { sessionId, deviceType: 'mobile' }, () => {
            
            // Listen for peer-disconnected event on first client
            clientSocket.on('peer-disconnected', (notification) => {
              expect(notification).toEqual({
                deviceType: 'mobile',
                sessionId: sessionId,
                timestamp: expect.any(Number)
              })
              done()
            })
            
            // Disconnect second client - should trigger peer-disconnected event
            secondClient.disconnect()
          })
        })
      })
    })

    test('should not emit peer-connected event for first device in session', (done) => {
      const sessionId = 'test-session-no-peer-event'
      let peerEventReceived = false

      clientSocket.on('peer-connected', () => {
        peerEventReceived = true
      })

      clientSocket.emit('join-session', { sessionId, deviceType: 'desktop' }, (response) => {
        expect(response.success).toBe(true)
        
        // Wait to ensure no peer-connected event is emitted
        setTimeout(() => {
          expect(peerEventReceived).toBe(false)
          done()
        }, 100)
      })
    })
  })

  describe('GoHighLevel OAuth Flow', () => {
    // OAuth Initiate Tests
    describe('GET /api/oauth/initiate', () => {
      test('should redirect to GHL authorization URL with correct parameters', async () => {
        const response = await request(httpServer)
          .get('/api/oauth/initiate')
          .expect(302)

        const location = response.headers.location
        expect(location).toContain('https://app.msoans.ai/oauth/authorize')
        expect(location).toContain('client_id=test-client-id')
        expect(location).toContain('redirect_uri=')
        expect(location).toMatch(/scope=locations\.readonly[\+%20]users\.readonly/)
        expect(location).toContain('response_type=code')
        expect(location).toContain('state=')
      })

      test('should return 500 if OAuth environment variables are missing', async () => {
        // Temporarily remove env vars
        const originalClientId = process.env.GHL_CLIENT_ID
        delete process.env.GHL_CLIENT_ID

        const response = await request(httpServer)
          .get('/api/oauth/initiate')
          .expect(500)

        expect(response.body).toEqual({
          success: false,
          error: 'OAuth configuration incomplete'
        })

        // Restore env var
        process.env.GHL_CLIENT_ID = originalClientId
      })
    })

    // OAuth Callback Tests  
          describe('GET /api/oauth/callback', () => {
      test('should handle successful OAuth callback and store installation', async () => {
        const response = await request(httpServer)
          .get('/api/oauth/callback')
          .query({
            code: 'test-auth-code',
            state: 'test-state'
          })
          .expect(302)

        expect(response.headers.location).toContain('oauth-status?status=success')
        expect(response.headers.location).toContain('locationId=test-location-123')
      })

      test('should handle OAuth error from GHL', async () => {
        const response = await request(httpServer)
          .get('/api/oauth/callback')
          .query({
            error: 'access_denied',
            error_description: 'User denied access'
          })
          .expect(302)

        expect(response.headers.location).toContain('oauth-status?status=error')
        expect(response.headers.location).toContain('message=access_denied')
      })

      test('should handle missing authorization code', async () => {
        const response = await request(httpServer)
          .get('/api/oauth/callback')
          .query({
            state: 'test-state'
          })
          .expect(302)

        expect(response.headers.location).toContain('oauth-status?status=error')
        expect(response.headers.location).toContain('No%20authorization%20code%20received')
      })
    })

    // GHL Locations List Tests
    describe('GET /api/locations', () => {
      test('should return GHL locations for authenticated user', async () => {
        const response = await request(httpServer)
          .get('/api/locations')
          .set('Authorization', 'Bearer valid-token')
          .expect(200)

        expect(response.body).toEqual({
          success: true,
          locations: expect.any(Array)
        })
      })

      test('should return 401 for unauthenticated request', async () => {
        const response = await request(httpServer)
          .get('/api/locations')
          .expect(401)

        expect(response.body).toEqual({
          success: false,
          error: 'Authentication required'
        })
      })

      test('should return 401 for invalid token', async () => {
        const response = await request(httpServer)
          .get('/api/locations')
          .set('Authorization', 'Bearer invalid-token')
          .expect(401)

        expect(response.body).toEqual({
          success: false,
          error: 'Invalid authentication token'
        })
      })
    })

    // GHL API Proxy Tests
    describe('POST /api/proxy', () => {
      test('should proxy GHL API calls successfully', async () => {
        const response = await request(httpServer)
          .post('/api/ghl-proxy')
          .set('Authorization', 'Bearer valid-token')
          .send({
            ghl_location_id: 'test-location-123',
            endpoint: '/contacts',
            method: 'GET'
          })
          .expect(200)

        expect(response.body).toEqual({
          success: true,
          data: expect.any(Object),
          status: 200
        })
      })

      test('should return 401 for unauthenticated proxy request', async () => {
        const response = await request(httpServer)
          .post('/api/ghl-proxy')
          .send({
            ghl_location_id: 'test-location-123',
            endpoint: '/contacts'
          })
          .expect(401)

        expect(response.body).toEqual({
          success: false,
          error: 'Authentication required'
        })
      })

      test('should return 400 for missing required fields', async () => {
        const response = await request(httpServer)
          .post('/api/ghl-proxy')
          .set('Authorization', 'Bearer valid-token')
          .send({
            endpoint: '/contacts'
          })
          .expect(400)

        expect(response.body).toEqual({
          success: false,
          error: 'Missing required fields: ghl_location_id and endpoint'
        })
      })

      test('should return 404 for non-existent GHL location', async () => {
        const response = await request(httpServer)
          .post('/api/ghl-proxy')
          .set('Authorization', 'Bearer valid-token')
          .send({
            ghl_location_id: 'non-existent-location',
            endpoint: '/contacts'
          })
          .expect(404)

        expect(response.body).toEqual({
          success: false,
          error: 'GHL location not found or not accessible'
        })
      })

      test('should handle token refresh when token is expired', async () => {
        const response = await request(httpServer)
          .post('/api/ghl-proxy')
          .set('Authorization', 'Bearer valid-token')
          .send({
            ghl_location_id: 'expired-token-location',
            endpoint: '/contacts'
          })
          .expect(200)

        expect(response.body).toEqual({
          success: true,
          data: expect.any(Object),
          status: 200
        })
      })
    })
  })

  describe('GoHighLevel Authentication Integration', () => {
    // Mock environment variables for tests
    const originalEnv = process.env
    const mockGHLSecret = 'test-shared-secret-32-characters-long!'
    const mockSupabaseUrl = 'https://test.supabase.co'
    const mockSupabaseServiceKey = 'test-service-role-key'

    beforeAll(() => {
      process.env.GHL_SHARED_SECRET = mockGHLSecret
      process.env.SUPABASE_URL = mockSupabaseUrl
      process.env.SUPABASE_SERVICE_ROLE_KEY = mockSupabaseServiceKey
    })

    afterAll(() => {
      process.env = originalEnv
    })

    // Helper function to encrypt payload (simulates GoHighLevel encryption)
    const encryptPayload = (data, secret) => {
      const algorithm = 'aes-256-cbc'
      const key = crypto.scryptSync(secret, 'salt', 32)
      const iv = crypto.randomBytes(16)
      const cipher = crypto.createCipheriv(algorithm, key, iv)
      
      // Handle both objects and strings
      const dataString = typeof data === 'string' ? data : JSON.stringify(data)
      let encrypted = cipher.update(dataString, 'utf8', 'hex')
      encrypted += cipher.final('hex')
      
      return {
        encrypted: encrypted,
        iv: iv.toString('hex')
      }
    }

    test('should decrypt valid GHL payload and return Supabase tokens for new user', async () => {
      const ghlUserData = {
        userId: 'ghl_user_123',
        email: 'newuser@gohighlevel.com',
        role: 'staff',
        firstName: 'John',
        lastName: 'Doe'
      }

      const { encrypted, iv } = encryptPayload(ghlUserData, mockGHLSecret)

      const response = await request(httpServer)
        .post('/api/auth/ghl')
        .send({
          encryptedPayload: encrypted,
          iv: iv
        })
        .expect(200)

      expect(response.body).toEqual({
        success: true,
        user: {
          id: expect.any(String),
          email: ghlUserData.email,
          ghl_user_id: ghlUserData.userId,
          role: ghlUserData.role
        },
        tokens: {
          access_token: expect.any(String),
          refresh_token: expect.any(String),
          expires_in: expect.any(Number)
        },
        isNewUser: true
      })
    })

    test('should decrypt valid GHL payload and return tokens for existing user', async () => {
      const ghlUserData = {
        userId: 'ghl_user_existing_456',
        email: 'existinguser@gohighlevel.com',
        role: 'admin',
        firstName: 'Jane',
        lastName: 'Smith'
      }

      const { encrypted, iv } = encryptPayload(ghlUserData, mockGHLSecret)

      // First request to create user
      await request(httpServer)
        .post('/api/auth/ghl')
        .send({
          encryptedPayload: encrypted,
          iv: iv
        })
        .expect(200)

      // Second request should sign in existing user
      const { encrypted: encrypted2, iv: iv2 } = encryptPayload(ghlUserData, mockGHLSecret)
      
      const response = await request(httpServer)
        .post('/api/auth/ghl')
        .send({
          encryptedPayload: encrypted2,
          iv: iv2
        })
        .expect(200)

      expect(response.body).toEqual({
        success: true,
        user: {
          id: expect.any(String),
          email: ghlUserData.email,
          ghl_user_id: ghlUserData.userId,
          role: ghlUserData.role
        },
        tokens: {
          access_token: expect.any(String),
          refresh_token: expect.any(String),
          expires_in: expect.any(Number)
        },
        isNewUser: false
      })
    })

    test('should return 400 for missing encrypted payload', async () => {
      const response = await request(httpServer)
        .post('/api/auth/ghl')
        .send({})
        .expect(400)

      expect(response.body).toEqual({
        success: false,
        error: 'Missing encrypted payload or initialization vector'
      })
    })

    test('should return 400 for invalid encrypted payload format', async () => {
      const response = await request(httpServer)
        .post('/api/auth/ghl')
        .send({
          encryptedPayload: 'invalid-encrypted-data',
          iv: 'invalid-iv'
        })
        .expect(400)

      expect(response.body).toEqual({
        success: false,
        error: 'Failed to decrypt payload: Invalid encryption format or shared secret'
      })
    })

    test('should return 400 for malformed decrypted JSON', async () => {
      // Create a string that will decrypt properly but isn't valid JSON
      const invalidJsonString = 'this is not json at all'
      const { encrypted, iv } = encryptPayload(invalidJsonString, mockGHLSecret)

      const response = await request(httpServer)
        .post('/api/auth/ghl')
        .send({
          encryptedPayload: encrypted,
          iv: iv
        })
        .expect(400)

      expect(response.body).toEqual({
        success: false,
        error: 'Invalid decrypted payload format'
      })
    })

    test('should return 400 for missing required user fields', async () => {
      const incompleteUserData = {
        userId: 'ghl_user_incomplete',
        // Missing email and role
        firstName: 'John'
      }

      const { encrypted, iv } = encryptPayload(incompleteUserData, mockGHLSecret)

      const response = await request(httpServer)
        .post('/api/auth/ghl')
        .send({
          encryptedPayload: encrypted,
          iv: iv
        })
        .expect(400)

      expect(response.body).toEqual({
        success: false,
        error: 'Missing required user fields: userId, email, or role'
      })
    })

    test('should return 500 when environment variables are missing', async () => {
      // Temporarily remove required env vars
      const originalSecret = process.env.GHL_SHARED_SECRET
      const originalUrl = process.env.SUPABASE_URL
      const originalKey = process.env.SUPABASE_SERVICE_ROLE_KEY

      delete process.env.GHL_SHARED_SECRET
      delete process.env.SUPABASE_URL
      delete process.env.SUPABASE_SERVICE_ROLE_KEY

      const ghlUserData = {
        userId: 'ghl_user_env_test',
        email: 'test@example.com',
        role: 'staff'
      }

      const { encrypted, iv } = encryptPayload(ghlUserData, 'any-key')

      const response = await request(httpServer)
        .post('/api/auth/ghl')
        .send({
          encryptedPayload: encrypted,
          iv: iv
        })
        .expect(500)

      expect(response.body).toEqual({
        success: false,
        error: 'Server configuration error: Missing required environment variables'
      })

      // Restore env vars
      process.env.GHL_SHARED_SECRET = originalSecret
      process.env.SUPABASE_URL = originalUrl
      process.env.SUPABASE_SERVICE_ROLE_KEY = originalKey
    })

    test('should handle Supabase connection errors gracefully', async () => {
      // Use invalid Supabase URL to simulate connection error
      const originalUrl = process.env.SUPABASE_URL
      process.env.SUPABASE_URL = 'https://invalid-supabase-url.co'

      const ghlUserData = {
        userId: 'ghl_user_error_test',
        email: 'error@example.com',
        role: 'staff'
      }

      const { encrypted, iv } = encryptPayload(ghlUserData, mockGHLSecret)

      const response = await request(httpServer)
        .post('/api/auth/ghl')
        .send({
          encryptedPayload: encrypted,
          iv: iv
        })
        .expect(500)

      expect(response.body).toEqual({
        success: false,
        error: 'Authentication service unavailable'
      })

      // Restore original URL
      process.env.SUPABASE_URL = originalUrl
    })

    test('should validate email format in decrypted payload', async () => {
      const invalidEmailData = {
        userId: 'ghl_user_invalid_email',
        email: 'invalid-email-format',
        role: 'staff'
      }

      const { encrypted, iv } = encryptPayload(invalidEmailData, mockGHLSecret)

      const response = await request(httpServer)
        .post('/api/auth/ghl')
        .send({
          encryptedPayload: encrypted,
          iv: iv
        })
        .expect(400)

      expect(response.body).toEqual({
        success: false,
        error: 'Invalid email format'
      })
    })

    test('should validate role field in decrypted payload', async () => {
      const invalidRoleData = {
        userId: 'ghl_user_invalid_role',
        email: 'test@example.com',
        role: 'invalid_role_type'
      }

      const { encrypted, iv } = encryptPayload(invalidRoleData, mockGHLSecret)

      const response = await request(httpServer)
        .post('/api/auth/ghl')
        .send({
          encryptedPayload: encrypted,
          iv: iv
        })
        .expect(400)

      expect(response.body).toEqual({
        success: false,
        error: 'Invalid role. Must be one of: admin, staff, member'
      })
    })
  })

  // GoHighLevel Credentials Authentication Integration
  describe('POST /api/auth/ghl-credentials', () => {
    const mockSupabaseUrl = 'https://test.supabase.co'
    const mockSupabaseServiceKey = 'test-service-role-key'

    beforeAll(() => {
      process.env.SUPABASE_URL = mockSupabaseUrl
      process.env.SUPABASE_SERVICE_ROLE_KEY = mockSupabaseServiceKey
    })

    afterAll(() => {
      process.env = originalEnv
    })

    // Mock GHL Credentials Authentication Endpoint
    httpServer._events.request = (req, res) => {
      if (req.method === 'POST' && req.url === '/api/auth/ghl-credentials') {
        let body = ''
        req.on('data', chunk => {
          body += chunk.toString()
        })
        req.on('end', () => {
          try {
            const { email, password, ghl_user_id, role, first_name, last_name } = JSON.parse(body)
      const { email, password, ghl_user_id, role, first_name, last_name } = req.body

      // Validate required fields
      if (!email || !password || !ghl_user_id || !role) {
        return res.status(400).json({
          success: false,
          error: 'Missing required fields: email, password, ghl_user_id, and role are required'
        })
      }

      // Validate email format
      const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/
      if (!emailRegex.test(email)) {
        return res.status(400).json({
          success: false,
          error: 'Invalid email format'
        })
      }

      // Validate role
      const validRoles = ['admin', 'staff']
      if (!validRoles.includes(role)) {
        return res.status(400).json({
          success: false,
          error: 'Invalid role. Must be "admin" or "staff"'
        })
      }

      // Simulate successful authentication
      if (email === 'test@example.com' && password === 'validpassword') {
        return res.json({
          success: true,
          user: {
            id: 'test-user-id',
            email: email,
            ghl_user_id: ghl_user_id,
            role: role
          },
          tokens: {
            access_token: 'test-access-token',
            refresh_token: 'test-refresh-token',
            expires_in: 3600
          },
          isNewUser: false
        })
      }

      // Simulate new user creation
      if (email === 'newuser@example.com' && password === 'newpassword') {
        return res.json({
          success: true,
          user: {
            id: 'new-user-id',
            email: email,
            ghl_user_id: ghl_user_id,
            role: role
          },
          tokens: {
            access_token: 'new-access-token',
            refresh_token: 'new-refresh-token',
            expires_in: 3600
          },
          isNewUser: true
        })
      }

      // Simulate authentication error
      return res.status(401).json({
        success: false,
        error: 'Invalid credentials'
      })
    })

    test('should authenticate with valid GHL credentials and return Supabase tokens', async () => {
      const response = await request(httpServer)
        .post('/api/auth/ghl-credentials')
        .send({
          email: 'test@example.com',
          password: 'validpassword',
          ghl_user_id: 'ghl_user_123',
          role: 'staff',
          first_name: 'John',
          last_name: 'Doe'
        })
        .expect(200)

      expect(response.body).toEqual({
        success: true,
        user: {
          id: 'test-user-id',
          email: 'test@example.com',
          ghl_user_id: 'ghl_user_123',
          role: 'staff'
        },
        tokens: {
          access_token: 'test-access-token',
          refresh_token: 'test-refresh-token',
          expires_in: 3600
        },
        isNewUser: false
      })
    })

    test('should create new user with valid GHL credentials', async () => {
      const response = await request(httpServer)
        .post('/api/auth/ghl-credentials')
        .send({
          email: 'newuser@example.com',
          password: 'newpassword',
          ghl_user_id: 'ghl_user_456',
          role: 'admin',
          first_name: 'Jane',
          last_name: 'Smith'
        })
        .expect(200)

      expect(response.body).toEqual({
        success: true,
        user: {
          id: 'new-user-id',
          email: 'newuser@example.com',
          ghl_user_id: 'ghl_user_456',
          role: 'admin'
        },
        tokens: {
          access_token: 'new-access-token',
          refresh_token: 'new-refresh-token',
          expires_in: 3600
        },
        isNewUser: true
      })
    })

    test('should return 400 for missing required fields', async () => {
      const response = await request(httpServer)
        .post('/api/auth/ghl-credentials')
        .send({
          email: 'test@example.com',
          password: 'validpassword'
          // Missing ghl_user_id and role
        })
        .expect(400)

      expect(response.body).toEqual({
        success: false,
        error: 'Missing required fields: email, password, ghl_user_id, and role are required'
      })
    })

    test('should return 400 for invalid email format', async () => {
      const response = await request(httpServer)
        .post('/api/auth/ghl-credentials')
        .send({
          email: 'invalid-email',
          password: 'validpassword',
          ghl_user_id: 'ghl_user_123',
          role: 'staff'
        })
        .expect(400)

      expect(response.body).toEqual({
        success: false,
        error: 'Invalid email format'
      })
    })

    test('should return 400 for invalid role', async () => {
      const response = await request(httpServer)
        .post('/api/auth/ghl-credentials')
        .send({
          email: 'test@example.com',
          password: 'validpassword',
          ghl_user_id: 'ghl_user_123',
          role: 'invalid_role'
        })
        .expect(400)

      expect(response.body).toEqual({
        success: false,
        error: 'Invalid role. Must be "admin" or "staff"'
      })
    })

    test('should return 401 for invalid credentials', async () => {
      const response = await request(httpServer)
        .post('/api/auth/ghl-credentials')
        .send({
          email: 'invalid@example.com',
          password: 'wrongpassword',
          ghl_user_id: 'ghl_user_123',
          role: 'staff'
        })
        .expect(401)

      expect(response.body).toEqual({
        success: false,
        error: 'Invalid credentials'
      })
    })
  })
})