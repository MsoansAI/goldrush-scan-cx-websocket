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
            callback({ success: false, error: 'Invalid sessionId' })
            return
          }

          if (!deviceType || typeof deviceType !== 'string' || !['desktop', 'mobile'].includes(deviceType)) {
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
          session.devices.set(socket.id, { deviceType, socketId: socket.id })

          callback({ success: true })
        } catch (error) {
          callback({ success: false, error: error.message })
        }
      })

      socket.on('message', (message) => {
        socket.to(message.sessionId).emit('message', message)
      })

      socket.on('disconnect', () => {
        for (const [sessionId, session] of sessions.entries()) {
          if (session.devices.has(socket.id)) {
            session.devices.delete(socket.id)
            if (session.devices.size === 0) {
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
})