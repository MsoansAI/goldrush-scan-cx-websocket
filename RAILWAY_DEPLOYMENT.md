# Railway Deployment Guide for GRSC WebSocket Server

## Overview
This guide covers deploying the GRSC WebSocket server to Railway for production use.

## Prerequisites
- Git repository with the WebSocket server code
- Railway account (sign up at https://railway.app)
- Frontend application URL for CORS configuration

## Project Structure
```
.
├── server.js              # Main WebSocket server
├── package.json           # Dependencies and scripts
├── jest.config.js         # Test configuration
├── .gitignore            # Git ignore rules
├── tests/                # Test files
│   ├── server.test.js    # Main server tests
│   └── setup.js          # Test setup
└── RAILWAY_DEPLOYMENT.md # This file
```

## Railway Deployment Steps

### 1. Connect Your Repository
1. Go to [Railway](https://railway.app) and sign in
2. Click "New Project"
3. Select "Deploy from GitHub repo"
4. Connect your GitHub account if not already connected
5. Select this repository
6. Choose the branch to deploy (usually `main`)

### 2. Configure Build Settings
Railway should auto-detect your Node.js project. If needed:
- **Build Command**: `npm install`
- **Start Command**: `npm start`
- **Root Directory**: Leave empty (server files are in root)

### 3. Set Environment Variables
In your Railway service settings, add these environment variables:

**Required Variables:**
```bash
# CORS Origin - Your frontend URL
CORS_ORIGIN=https://your-frontend-domain.vercel.app

# Production environment
NODE_ENV=production
```

**Optional Variables:**
```bash
# Custom port (Railway provides PORT automatically)
# PORT=3001
```

### 4. Deploy
1. Railway will automatically start building and deploying
2. Monitor the deployment logs in the Railway dashboard
3. Once deployed, you'll get a public URL like: `https://your-service-name.up.railway.app`

### 5. Update Frontend Configuration
Update your frontend's WebSocket URL environment variable:
```bash
# In your Vercel frontend project
VITE_WS_URL=https://your-service-name.up.railway.app
```

## Testing Your Deployment

### Health Check
Test the health endpoint:
```bash
curl https://your-service-name.up.railway.app/health
```

Expected response:
```json
{
  "status": "healthy",
  "timestamp": "2024-01-15T10:30:00.000Z",
  "uptime": 123.456,
  "connections": 0,
  "sessions": 0,
  "environment": "production"
}
```

### WebSocket Connection
Test WebSocket connection using wscat:
```bash
# Install wscat if you don't have it
npm install -g wscat

# Test connection
wscat -c wss://your-service-name.up.railway.app/socket.io/?EIO=4&transport=websocket
```

### Full Integration Test
1. Open your frontend application
2. Click "Pair Mobile Device" on desktop
3. Scan QR code with mobile device
4. Verify connection is established

## Environment Variables Reference

| Variable | Description | Required | Example |
|----------|-------------|----------|---------|
| `CORS_ORIGIN` | Frontend domain for CORS | Yes | `https://your-app.vercel.app` |
| `NODE_ENV` | Environment mode | Yes | `production` |
| `PORT` | Server port | No | Auto-provided by Railway |

## Monitoring and Logs

### Railway Dashboard
- View real-time logs in Railway dashboard
- Monitor CPU and memory usage
- Set up custom metrics if needed

### Application Health
- Use `/health` endpoint for uptime monitoring
- Monitor WebSocket connection counts
- Track session management metrics

## Troubleshooting

### Common Issues

**1. CORS Errors**
- Verify `CORS_ORIGIN` matches your frontend URL exactly
- Check for trailing slashes or protocol mismatches

**2. WebSocket Connection Fails**
- Ensure your frontend is using `wss://` (secure WebSocket)
- Verify the Railway service URL is correct
- Check Railway logs for connection errors

**3. Build Failures**
- Verify `package.json` has all required dependencies
- Check Node.js version compatibility
- Review Railway build logs for specific errors

**4. Runtime Errors**
- Check Railway service logs
- Verify environment variables are set
- Test health endpoint response

### Debug Commands
```bash
# Check service status
curl https://your-service-name.up.railway.app/

# Test health endpoint
curl https://your-service-name.up.railway.app/health

# View Railway logs (in Railway dashboard)
# Go to your service > Deployments > Click on latest deployment > View logs
```

## Security Considerations

1. **CORS Configuration**
   - Only allow your frontend domain
   - Never use wildcard (`*`) in production

2. **Environment Variables**
   - Store sensitive data in Railway environment variables
   - Never commit secrets to Git

3. **Rate Limiting**
   - Consider adding rate limiting for production
   - Monitor for unusual connection patterns

## Performance Optimization

1. **Connection Limits**
   - Railway provides generous connection limits
   - Monitor usage in Railway dashboard

2. **Memory Management**
   - Session cleanup runs every minute
   - Monitor memory usage for session leaks

3. **Scaling**
   - Railway auto-scales based on usage
   - Consider upgrading plan for high traffic

## Local Development

To run locally and test against Railway:
```bash
# Install dependencies
npm install

# Set environment variables
export CORS_ORIGIN=http://localhost:5173
export NODE_ENV=development

# Run server
npm start

# Run tests
npm test
```

## Support
- Railway Documentation: https://docs.railway.app
- Railway Discord: https://discord.gg/railway
- Railway Status: https://status.railway.app