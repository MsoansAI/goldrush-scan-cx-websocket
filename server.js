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
    devices: devices,
    createdAt: session.createdAt,
    expiresAt: session.expiresAt
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
          expiresAt: Date.now() + (5 * 60 * 1000) // 5 minutes
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

      console.log(`[${new Date().toISOString()}] Device ${deviceType} joined session ${sessionId}`)

      // Notify existing peers about new connection (only if session already had devices)
      if (isExistingSession) {
        socket.to(sessionId).emit('peer-connected', {
          deviceType: deviceType,
          sessionId: sessionId,
          timestamp: Date.now()
        })
        console.log(`[${new Date().toISOString()}] Notified peers in session ${sessionId} about ${deviceType} connection`)
      }

      callback({ success: true })
    } catch (error) {
      console.error(`[${new Date().toISOString()}] Error in join-session:`, error)
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

      console.log(`[${new Date().toISOString()}] Heartbeat received from ${device.deviceType} in session ${sessionId}`)

      callback({ 
        success: true, 
        lastSeen: device.lastSeen,
        sessionExpiresAt: session.expiresAt
      })
    } catch (error) {
      console.error(`[${new Date().toISOString()}] Error in heartbeat:`, error)
      callback({ success: false, error: error.message })
    }
  })

  socket.on('disconnect', () => {
    console.log(`[${new Date().toISOString()}] Client disconnected:`, socket.id)
    
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
        console.log(`[${new Date().toISOString()}] Notified peers in session ${sessionId} about ${disconnectedDevice.deviceType} disconnection`)
        
        // Then do cleanup
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