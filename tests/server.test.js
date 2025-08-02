const request = require('supertest')
const { createServer } = require('http')
const { Server } = require('socket.io')
const Client = require('socket.io-client')
const express = require('express')
const cors = require('cors')

describe('WebSocket Server', () => {
  let httpServer
  let httpServerAddr
  let ioServer
  let clientSocket

  beforeAll((done) => {
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
})