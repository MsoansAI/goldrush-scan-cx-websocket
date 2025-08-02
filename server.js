// server.js
const express = require('express')
const { createServer } = require('http')
const { Server } = require('socket.io')
const cors = require('cors')

const app = express()
const server = createServer(app)

// Middleware
app.use(cors())
app.use(express.json())

// Health check endpoint for Railway and monitoring
app.get('/health', (req, res) => {
  res.json({
    status: 'healthy',
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    connections: io.engine.clientsCount,
    sessions: sessions.size,
    environment: process.env.NODE_ENV || 'development'
  })
})

// Basic API endpoint
app.get('/', (req, res) => {
  res.json({
    message: 'GRSC WebSocket Server',
    version: '1.0.0',
    status: 'running'
  })
})

const io = new Server(server, {
  cors: {
    origin: process.env.CORS_ORIGIN,
    methods: ["GET", "POST"]
  },
  transports: ['websocket', 'polling']
})

// Session management
const sessions = new Map()

// Error handling
process.on('uncaughtException', (error) => {
  console.error('Uncaught Exception:', error)
  process.exit(1)
})

process.on('unhandledRejection', (reason, promise) => {
  console.error('Unhandled Rejection at:', promise, 'reason:', reason)
  process.exit(1)
})

io.on('connection', (socket) => {
  console.log(`[${new Date().toISOString()}] Client connected:`, socket.id)

  socket.on('join-session', ({ sessionId, deviceType }, callback) => {
    try {
      // Validate input data
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
          expiresAt: Date.now() + (5 * 60 * 1000) // 5 minutes
        })
      }

      const session = sessions.get(sessionId)
      session.devices.set(socket.id, { deviceType, socketId: socket.id })

      console.log(`[${new Date().toISOString()}] Device ${deviceType} joined session ${sessionId}`)
      callback({ success: true })
    } catch (error) {
      console.error(`[${new Date().toISOString()}] Error in join-session:`, error)
      callback({ success: false, error: error.message })
    }
  })

  socket.on('message', (message) => {
    socket.to(message.sessionId).emit('message', message)
  })

  socket.on('disconnect', () => {
    console.log(`[${new Date().toISOString()}] Client disconnected:`, socket.id)
    
    // Cleanup session data
    for (const [sessionId, session] of sessions.entries()) {
      if (session.devices.has(socket.id)) {
        session.devices.delete(socket.id)
        console.log(`[${new Date().toISOString()}] Removed device from session ${sessionId}`)
        
        if (session.devices.size === 0) {
          sessions.delete(sessionId)
          console.log(`[${new Date().toISOString()}] Session ${sessionId} cleaned up (no devices left)`)
        }
        break
      }
    }
  })

  socket.on('error', (error) => {
    console.error(`[${new Date().toISOString()}] Socket error for ${socket.id}:`, error)
  })
})

// Cleanup expired sessions
setInterval(() => {
  const now = Date.now()
  for (const [sessionId, session] of sessions.entries()) {
    if (now > session.expiresAt) {
      sessions.delete(sessionId)
      console.log(`[${new Date().toISOString()}] Expired session ${sessionId} cleaned up`)
    }
  }
}, 60000) // Check every minute

const PORT = process.env.PORT || 3001
server.listen(PORT, () => {
  console.log(`[${new Date().toISOString()}] 🚀 GRSC WebSocket server running on port ${PORT}`)
  console.log(`[${new Date().toISOString()}] Environment: ${process.env.NODE_ENV || 'development'}`)
  console.log(`[${new Date().toISOString()}] CORS Origin: ${process.env.CORS_ORIGIN || 'Not set'}`)
})