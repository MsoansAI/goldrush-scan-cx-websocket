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

  console.log(`[${new Date().toISOString()}] Buffered message for customer ${customerId}: ${type}`)

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

  console.log(`[${new Date().toISOString()}] Cleaned ${cleaned} old buffered messages`)

  res.json({
    success: true,
    cleaned,
    cutoffTime
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
const messageBuffer = new Map() // customerId -> messages[]
const customerSessions = new Map() // customerId -> sessionId

// Error handling
process.on('uncaughtException', (error) => {
  console.error('Uncaught Exception:', error)
  process.exit(1)
})

process.on('unhandledRejection', (reason, promise) => {
  console.error('Unhandled Rejection at:', promise, 'reason:', reason)
  process.exit(1)
})

// Graceful shutdown monitoring
process.on('SIGTERM', () => {
  console.log(`[${new Date().toISOString()}] SIGTERM received - starting graceful shutdown`)
  console.log(`[${new Date().toISOString()}] Active sessions: ${sessions.size}`)
  console.log(`[${new Date().toISOString()}] Connected clients: ${io.engine.clientsCount}`)
  
  // Give time for cleanup
  setTimeout(() => {
    console.log(`[${new Date().toISOString()}] Graceful shutdown complete`)
    process.exit(0)
  }, 5000)
})

process.on('SIGINT', () => {
  console.log(`[${new Date().toISOString()}] SIGINT received - starting graceful shutdown`)
  process.exit(0)
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
            console.log(`[${new Date().toISOString()}] Removed old device entry for ${deviceType} reconnection`)
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

      console.log(`[${new Date().toISOString()}] Authenticated device ${deviceType} joined session ${sessionId} for customer ${customerId}`)

      // Deliver buffered messages on reconnection
      if (messageBuffer.has(customerId)) {
        const bufferedMessages = messageBuffer.get(customerId)
        if (bufferedMessages.length > 0) {
          socket.emit('buffered-messages', bufferedMessages)
          console.log(`[${new Date().toISOString()}] Delivered ${bufferedMessages.length} buffered messages to customer ${customerId}`)
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
        console.log(`[${new Date().toISOString()}] Notified peers in session ${sessionId} about ${deviceType} connection`)
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
      console.error(`[${new Date().toISOString()}] Error in join-authenticated-session:`, error)
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
        
        // Don't delete persistent sessions when empty - keep them for reconnection
        if (session.devices.size === 0 && !session.persistent) {
          sessions.delete(sessionId)
          console.log(`[${new Date().toISOString()}] Session ${sessionId} cleaned up (no devices left)`)
        } else if (session.devices.size === 0 && session.persistent) {
          console.log(`[${new Date().toISOString()}] Persistent session ${sessionId} kept alive for reconnection`)
        }
        break
      }
    }
  })

  socket.on('error', (error) => {
    console.error(`[${new Date().toISOString()}] Socket error for ${socket.id}:`, error)
  })
})

// Cleanup expired sessions and old buffered messages
setInterval(() => {
  const now = Date.now()
  
  // Clean up expired sessions
  for (const [sessionId, session] of sessions.entries()) {
    if (now > session.expiresAt) {
      sessions.delete(sessionId)
      console.log(`[${new Date().toISOString()}] Expired session ${sessionId} cleaned up`)
    }
  }
  
  // Clean up old buffered messages (older than 48 hours)
  const messageAgeLimit = 48 * 60 * 60 * 1000 // 48 hours
  let totalCleaned = 0
  
  for (const [customerId, messages] of messageBuffer.entries()) {
    const before = messages.length
    const filtered = messages.filter(msg => (now - msg.timestamp) < messageAgeLimit)
    messageBuffer.set(customerId, filtered)
    const cleaned = before - filtered.length
    totalCleaned += cleaned
    
    // Remove empty buffers
    if (filtered.length === 0) {
      messageBuffer.delete(customerId)
    }
  }
  
  if (totalCleaned > 0) {
    console.log(`[${new Date().toISOString()}] Cleaned ${totalCleaned} old buffered messages`)
  }
}, 60000) // Check every minute

const PORT = process.env.PORT || 3001
server.listen(PORT, () => {
  console.log(`[${new Date().toISOString()}] 🚀 GRSC WebSocket server running on port ${PORT}`)
  console.log(`[${new Date().toISOString()}] Environment: ${process.env.NODE_ENV || 'development'}`)
  console.log(`[${new Date().toISOString()}] CORS Origin: ${process.env.CORS_ORIGIN || 'Not set'}`)
})