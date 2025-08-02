# Production Deployment Guide

## Overview
This guide covers the complete deployment process for the mobile-desktop pairing application with QR code scanning functionality.

## Architecture Components

### Frontend Application
- **React 18** with TypeScript
- **Vite** build system
- **Tailwind CSS** for styling
- **Socket.IO Client** for real-time communication

### Backend Services
- **WebSocket Server** (Socket.IO)
- **Supabase** for database and real-time features
- **CDN** for static asset delivery

### Infrastructure Requirements
- **Web Server**: Nginx or Apache
- **SSL Certificate**: Required for camera access
- **WebSocket Support**: Reverse proxy configuration
- **Domain**: HTTPS required for production

## Environment Configuration

### Environment Variables
```bash
# Frontend (.env)
VITE_SUPABASE_URL=https://your-project.supabase.co
VITE_SUPABASE_ANON_KEY=your-anon-key
VITE_WS_URL=wss://your-websocket-server.com

# Backend
DATABASE_URL=postgresql://...
SUPABASE_SERVICE_ROLE_KEY=your-service-role-key
CORS_ORIGIN=https://your-frontend-domain.com
PORT=3001
```

### Build Configuration
```json
// package.json
{
  "scripts": {
    "build": "vite build",
    "preview": "vite preview",
    "build:staging": "vite build --mode staging",
    "build:production": "vite build --mode production"
  }
}
```

## WebSocket Server Setup

### Server Implementation
```javascript
// server.js
const express = require('express')
const { createServer } = require('http')
const { Server } = require('socket.io')
const cors = require('cors')

const app = express()
const server = createServer(app)

const io = new Server(server, {
  cors: {
    origin: process.env.CORS_ORIGIN,
    methods: ["GET", "POST"]
  },
  transports: ['websocket', 'polling']
})

// Session management
const sessions = new Map()

io.on('connection', (socket) => {
  console.log('Client connected:', socket.id)

  socket.on('join-session', ({ sessionId, deviceType }, callback) => {
    try {
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

      callback({ success: true })
    } catch (error) {
      callback({ success: false, error: error.message })
    }
  })

  socket.on('message', (message) => {
    socket.to(message.sessionId).emit('message', message)
  })

  socket.on('disconnect', () => {
    // Cleanup session data
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

// Cleanup expired sessions
setInterval(() => {
  const now = Date.now()
  for (const [sessionId, session] of sessions.entries()) {
    if (now > session.expiresAt) {
      sessions.delete(sessionId)
    }
  }
}, 60000) // Check every minute

const PORT = process.env.PORT || 3001
server.listen(PORT, () => {
  console.log(`WebSocket server running on port ${PORT}`)
})
```

### Docker Configuration
```dockerfile
# Dockerfile
FROM node:18-alpine

WORKDIR /app

# Copy package files
COPY package*.json ./
RUN npm ci --only=production

# Copy source code
COPY . .

# Build application
RUN npm run build

EXPOSE 3001

CMD ["node", "server.js"]
```

### Docker Compose
```yaml
# docker-compose.yml
version: '3.8'

services:
  frontend:
    build: .
    ports:
      - "3000:3000"
    environment:
      - VITE_SUPABASE_URL=${VITE_SUPABASE_URL}
      - VITE_SUPABASE_ANON_KEY=${VITE_SUPABASE_ANON_KEY}
      - VITE_WS_URL=${VITE_WS_URL}
    depends_on:
      - websocket-server

  websocket-server:
    build: ./server
    ports:
      - "3001:3001"
    environment:
      - CORS_ORIGIN=${CORS_ORIGIN}
      - PORT=3001
    restart: unless-stopped

  nginx:
    image: nginx:alpine
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf
      - ./ssl:/etc/nginx/ssl
    depends_on:
      - frontend
      - websocket-server
```

## Nginx Configuration

### SSL and WebSocket Proxy
```nginx
# nginx.conf
events {
    worker_connections 1024;
}

http {
    upstream frontend {
        server frontend:3000;
    }

    upstream websocket {
        server websocket-server:3001;
    }

    server {
        listen 80;
        server_name your-domain.com;
        return 301 https://$server_name$request_uri;
    }

    server {
        listen 443 ssl http2;
        server_name your-domain.com;

        ssl_certificate /etc/nginx/ssl/cert.pem;
        ssl_certificate_key /etc/nginx/ssl/key.pem;
        ssl_protocols TLSv1.2 TLSv1.3;
        ssl_ciphers HIGH:!aNULL:!MD5;

        # Frontend
        location / {
            proxy_pass http://frontend;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
        }

        # WebSocket
        location /socket.io/ {
            proxy_pass http://websocket;
            proxy_http_version 1.1;
            proxy_set_header Upgrade $http_upgrade;
            proxy_set_header Connection "upgrade";
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
        }
    }
}
```

## Database Setup (Supabase)

### Required Tables
The application uses the existing loyalty program schema:
- `customers`
- `loyalty_memberships`
- `orders`
- `order_items`
- `products`

### Row Level Security
```sql
-- Enable RLS on all tables
ALTER TABLE customers ENABLE ROW LEVEL SECURITY;
ALTER TABLE loyalty_memberships ENABLE ROW LEVEL SECURITY;

-- Create policies for authenticated access
CREATE POLICY "Allow authenticated users to read customers"
ON customers FOR SELECT
TO authenticated
USING (true);

CREATE POLICY "Allow authenticated users to read memberships"
ON loyalty_memberships FOR SELECT
TO authenticated
USING (true);
```

### Indexes for Performance
```sql
-- Optimize QR code lookups
CREATE INDEX IF NOT EXISTS idx_loyalty_memberships_qr_code 
ON loyalty_memberships(unique_qr_code_id);

-- Optimize customer searches
CREATE INDEX IF NOT EXISTS idx_customers_phone_search 
ON customers USING gin(to_tsvector('english', phone_number));

CREATE INDEX IF NOT EXISTS idx_customers_name_search 
ON customers USING gin(to_tsvector('english', first_name));
```

## Deployment Steps

### 1. Pre-deployment Checklist
- [ ] Environment variables configured
- [ ] SSL certificates obtained
- [ ] Database migrations applied
- [ ] WebSocket server tested
- [ ] Build process verified
- [ ] Security headers configured

### 2. Build and Deploy
```bash
# Build frontend
npm run build:production

# Build Docker images
docker-compose build

# Deploy to production
docker-compose up -d

# Verify deployment
curl -k https://your-domain.com/health
```

### 3. Post-deployment Verification
```bash
# Check services
docker-compose ps

# Check logs
docker-compose logs -f

# Test WebSocket connection
wscat -c wss://your-domain.com/socket.io/?EIO=4&transport=websocket

# Test QR code generation
curl https://your-domain.com/api/health
```

## Monitoring and Logging

### Application Monitoring
```javascript
// Add to WebSocket server
const winston = require('winston')

const logger = winston.createLogger({
  level: 'info',
  format: winston.format.json(),
  transports: [
    new winston.transports.File({ filename: 'error.log', level: 'error' }),
    new winston.transports.File({ filename: 'combined.log' })
  ]
})

// Log connections and errors
io.on('connection', (socket) => {
  logger.info('Client connected', { socketId: socket.id })
  
  socket.on('error', (error) => {
    logger.error('Socket error', { socketId: socket.id, error })
  })
})
```

### Health Check Endpoints
```javascript
// Add to Express server
app.get('/health', (req, res) => {
  res.json({
    status: 'healthy',
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    connections: io.engine.clientsCount
  })
})
```

## Security Considerations

### HTTPS Requirements
- SSL certificate for camera access
- Secure WebSocket connections (WSS)
- HSTS headers enabled

### Content Security Policy
```nginx
add_header Content-Security-Policy "
  default-src 'self';
  script-src 'self' 'unsafe-inline';
  style-src 'self' 'unsafe-inline';
  img-src 'self' data: https:;
  connect-src 'self' wss: https:;
  media-src 'self';
" always;
```

### Rate Limiting
```javascript
const rateLimit = require('express-rate-limit')

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100 // limit each IP to 100 requests per windowMs
})

app.use('/api/', limiter)
```

## Backup and Recovery

### Database Backups
- Automated daily backups via Supabase
- Point-in-time recovery available
- Cross-region replication for critical data

### Application Backups
- Docker image versioning
- Configuration file backups
- SSL certificate backups

## Scaling Considerations

### Horizontal Scaling
- Load balancer for multiple frontend instances
- Redis for WebSocket session sharing
- Database read replicas for high traffic

### Performance Optimization
- CDN for static assets
- Image optimization for QR codes
- WebSocket connection pooling
- Database query optimization

## Troubleshooting

### Common Issues
1. **Camera not working**: Check HTTPS and permissions
2. **WebSocket connection fails**: Verify proxy configuration
3. **QR codes not scanning**: Check camera permissions and lighting
4. **Database timeouts**: Optimize queries and add indexes

### Debug Commands
```bash
# Check WebSocket connections
netstat -an | grep :3001

# Monitor logs
tail -f /var/log/nginx/error.log
docker-compose logs -f websocket-server

# Test database connection
psql $DATABASE_URL -c "SELECT 1"
```