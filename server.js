// server.js
const express = require('express')
const { createServer } = require('http')
const { Server } = require('socket.io')
const cors = require('cors')
const crypto = require('crypto')
const axios = require('axios')
const cron = require('node-cron')
const { createClient } = require('@supabase/supabase-js')
require('dotenv').config()

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

// ============================================================================
// GOHIGHLEVEL OAUTH FLOW ENDPOINTS
// ============================================================================

// OAuth Initiate Endpoint - Phase 1
app.get('/api/ghl-oauth/initiate', (req, res) => {
  try {
    const { GHL_CLIENT_ID, GHL_REDIRECT_URI, GHL_SCOPES } = process.env

    if (!GHL_CLIENT_ID || !GHL_REDIRECT_URI || !GHL_SCOPES) {
      console.error(`[${new Date().toISOString()}] Missing OAuth environment variables`)
      return res.status(500).json({
        success: false,
        error: 'OAuth configuration incomplete'
      })
    }

    // Construct GoHighLevel Authorization URL
    const authUrl = new URL('https://oauth.integrately.com/oauth/authorize')
    authUrl.searchParams.append('client_id', GHL_CLIENT_ID)
    authUrl.searchParams.append('redirect_uri', GHL_REDIRECT_URI)
    authUrl.searchParams.append('scope', GHL_SCOPES)
    authUrl.searchParams.append('response_type', 'code')
    
    // Optional: Add state parameter for CSRF protection
    const state = crypto.randomBytes(32).toString('hex')
    authUrl.searchParams.append('state', state)
    
    console.log(`[${new Date().toISOString()}] Initiating GHL OAuth flow, redirecting to: ${authUrl.toString()}`)
    
    // Redirect to GoHighLevel authorization server
    res.redirect(authUrl.toString())
    
  } catch (error) {
    console.error(`[${new Date().toISOString()}] OAuth initiate error:`, error.message)
    res.status(500).json({
      success: false,
      error: 'Failed to initiate OAuth flow'
    })
  }
})

// OAuth Callback Endpoint - Phase 1
app.get('/api/ghl-oauth/callback', async (req, res) => {
  try {
    const { code, state, error } = req.query
    const { GHL_CLIENT_ID, GHL_CLIENT_SECRET, GHL_REDIRECT_URI, FRONTEND_URL } = process.env

    // Handle OAuth errors
    if (error) {
      console.error(`[${new Date().toISOString()}] OAuth callback error from GHL:`, error)
      return res.redirect(`${FRONTEND_URL}/ghl-oauth-status?status=error&message=${encodeURIComponent(error)}`)
    }

    if (!code) {
      console.error(`[${new Date().toISOString()}] No authorization code received`)
      return res.redirect(`${FRONTEND_URL}/ghl-oauth-status?status=error&message=No authorization code received`)
    }

    if (!GHL_CLIENT_ID || !GHL_CLIENT_SECRET || !GHL_REDIRECT_URI) {
      console.error(`[${new Date().toISOString()}] Missing OAuth client credentials`)
      return res.redirect(`${FRONTEND_URL}/ghl-oauth-status?status=error&message=OAuth configuration incomplete`)
    }

    console.log(`[${new Date().toISOString()}] Processing OAuth callback with code: ${code.substring(0, 10)}...`)

    // Step 1: Exchange code for agency tokens
    const tokenResponse = await axios.post('https://oauth.integrately.com/oauth/token', {
      grant_type: 'authorization_code',
      code: code,
      client_id: GHL_CLIENT_ID,
      client_secret: GHL_CLIENT_SECRET,
      redirect_uri: GHL_REDIRECT_URI
    }, {
      headers: {
        'Content-Type': 'application/json'
      }
    })

    const { access_token: agencyToken, refresh_token: agencyRefreshToken, expires_in } = tokenResponse.data
    
    if (!agencyToken) {
      throw new Error('No access token received from GHL')
    }

    console.log(`[${new Date().toISOString()}] Successfully obtained agency tokens`)

    // Step 2: Get location where app is installed
    const locationResponse = await axios.get('https://rest.gohighlevel.com/v1/oauth/location', {
      headers: {
        'Authorization': `Bearer ${agencyToken}`,
        'Accept': 'application/json'
      }
    })

    const { locationId: ghlLocationId, agencyId: ghlAgencyId } = locationResponse.data
    
    if (!ghlLocationId || !ghlAgencyId) {
      throw new Error('Unable to determine installation location')
    }

    console.log(`[${new Date().toISOString()}] App installed at location: ${ghlLocationId}, agency: ${ghlAgencyId}`)

    // Step 3: Get location-specific access token
    const locationTokenResponse = await axios.post('https://rest.gohighlevel.com/v1/oauth/locationToken', {
      locationId: ghlLocationId
    }, {
      headers: {
        'Authorization': `Bearer ${agencyToken}`,
        'Content-Type': 'application/json'
      }
    })

    const { 
      access_token: locationToken, 
      refresh_token: locationRefreshToken,
      expires_in: locationExpiresIn 
    } = locationTokenResponse.data

    if (!locationToken) {
      throw new Error('No location access token received')
    }

    console.log(`[${new Date().toISOString()}] Successfully obtained location tokens`)

    // Step 4: Store installation in database
    const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_ROLE_KEY, {
      auth: {
        autoRefreshToken: false,
        persistSession: false
      }
    })

    // Calculate token expiry times
    const agencyExpiresAt = new Date(Date.now() + (expires_in * 1000))
    const locationExpiresAt = new Date(Date.now() + (locationExpiresIn * 1000))

    // Get location details (optional)
    let locationName = null
    let locationAddress = null
    try {
      const locationDetailsResponse = await axios.get(`https://rest.gohighlevel.com/v1/locations/${ghlLocationId}`, {
        headers: {
          'Authorization': `Bearer ${locationToken}`,
          'Accept': 'application/json'
        }
      })
      locationName = locationDetailsResponse.data.name
      locationAddress = locationDetailsResponse.data.address
    } catch (detailsError) {
      console.warn(`[${new Date().toISOString()}] Could not fetch location details:`, detailsError.message)
    }

    // Store installation using our secure function
    const { data: installationData, error: storageError } = await supabase.rpc('store_ghl_installation', {
      p_ghl_agency_id: ghlAgencyId,
      p_ghl_location_id: ghlLocationId,
      p_agency_access_token: agencyToken,
      p_agency_refresh_token: agencyRefreshToken,
      p_agency_token_expires_at: agencyExpiresAt.toISOString(),
      p_location_access_token: locationToken,
      p_location_refresh_token: locationRefreshToken,
      p_location_token_expires_at: locationExpiresAt.toISOString(),
      p_installed_by_user_id: null, // Will be populated when user context is available
      p_location_name: locationName,
      p_location_address: locationAddress
    })

    if (storageError) {
      throw new Error(`Database storage failed: ${storageError.message}`)
    }

    console.log(`[${new Date().toISOString()}] Successfully stored GHL installation with ID: ${installationData}`)

    // Step 5: Redirect to frontend success page
    const successUrl = `${FRONTEND_URL}/ghl-oauth-status?status=success&locationId=${ghlLocationId}&locationName=${encodeURIComponent(locationName || 'Unknown Location')}`
    res.redirect(successUrl)

  } catch (error) {
    console.error(`[${new Date().toISOString()}] OAuth callback error:`, error.message)
    
    // Extract meaningful error message
    let errorMessage = 'OAuth flow failed'
    if (error.response?.data?.error_description) {
      errorMessage = error.response.data.error_description
    } else if (error.response?.data?.message) {
      errorMessage = error.response.data.message
    } else if (error.message) {
      errorMessage = error.message
    }

    const errorUrl = `${process.env.FRONTEND_URL}/ghl-oauth-status?status=error&message=${encodeURIComponent(errorMessage)}`
    res.redirect(errorUrl)
  }
})


// GoHighLevel Authentication Endpoint (for encrypted payloads)
app.post('/api/auth/ghl', async (req, res) => {
  try {
    // Environment variables validation
    const { GHL_SHARED_SECRET, SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY } = process.env
    
    if (!GHL_SHARED_SECRET || !SUPABASE_URL || !SUPABASE_SERVICE_ROLE_KEY) {
      console.error(`[${new Date().toISOString()}] Missing environment variables for GHL auth`)
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

    // Decrypt the GoHighLevel payload
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
      console.error(`[${new Date().toISOString()}] Decryption failed:`, decryptError.message)
      return res.status(400).json({
        success: false,
        error: 'Failed to decrypt payload: Invalid encryption format or shared secret'
      })
    }

    // Parse JSON separately to catch JSON parsing errors
    try {
      decryptedData = JSON.parse(decryptedString)
    } catch (parseError) {
      console.error(`[${new Date().toISOString()}] JSON parsing failed:`, parseError.message)
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
      console.error(`[${new Date().toISOString()}] JSON parsing failed:`, parseError.message)
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

    // Initialize Supabase Admin client
    let supabase
    try {
      supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, {
        auth: {
          autoRefreshToken: false,
          persistSession: false
        }
      })
    } catch (supabaseError) {
      console.error(`[${new Date().toISOString()}] Supabase initialization failed:`, supabaseError.message)
      return res.status(500).json({
        success: false,
        error: 'Authentication service unavailable'
      })
    }

    let authResult
    let isNewUser = false

    try {
      // Check if user exists in Supabase auth.users by email
      const { data: existingUsers, error: getUserError } = await supabase.auth.admin.listUsers()
      
      if (getUserError) {
        throw getUserError
      }

      const existingUser = existingUsers.users.find(user => user.email === email)

      if (existingUser) {
        // User exists - generate new tokens for existing user
        console.log(`[${new Date().toISOString()}] Signing in existing GHL user: ${email}`)
        
        // Generate fresh tokens for existing user using admin API
        const { data: tokenData, error: tokenError } = await supabase.auth.admin.generateLink({
          type: 'magiclink',
          email: email,
          options: {
            redirectTo: process.env.REDIRECT_URL || 'http://localhost:3000'
          }
        })

        if (tokenError) {
          throw tokenError
        }

        // Extract tokens from the response
        const accessToken = tokenData.properties?.access_token
        const refreshToken = tokenData.properties?.refresh_token

        if (!accessToken || !refreshToken) {
          throw new Error('Failed to generate valid tokens')
        }

        authResult = {
          user: {
            id: existingUser.id,
            email: existingUser.email,
            ghl_user_id: userId,
            role: role
          },
          tokens: {
            access_token: accessToken,
            refresh_token: refreshToken,
            expires_in: 3600 // 1 hour
          }
        }
      } else {
        // User doesn't exist - create new user
        console.log(`[${new Date().toISOString()}] Creating new GHL user: ${email}`)
        isNewUser = true

        const { data: newUserData, error: createError } = await supabase.auth.admin.createUser({
          email: email,
          email_confirm: true,
          user_metadata: {
            ghl_user_id: userId,
            role: role,
            first_name: firstName,
            last_name: lastName,
            source: 'gohighlevel'
          }
        })

        if (createError) {
          throw createError
        }

        // Generate tokens for new user
        const { data: tokenData, error: tokenError } = await supabase.auth.admin.generateLink({
          type: 'magiclink',
          email: email,
          options: {
            redirectTo: process.env.REDIRECT_URL || 'http://localhost:3000'
          }
        })

        if (tokenError) {
          throw tokenError
        }

        const accessToken = tokenData.properties?.access_token
        const refreshToken = tokenData.properties?.refresh_token

        if (!accessToken || !refreshToken) {
          throw new Error('Failed to generate valid tokens')
        }

        authResult = {
          user: {
            id: newUserData.user.id,
            email: newUserData.user.email,
            ghl_user_id: userId,
            role: role
          },
          tokens: {
            access_token: accessToken,
            refresh_token: refreshToken,
            expires_in: 3600 // 1 hour
          }
        }

        // Create entry in internal_users table for GoHighLevel staff
        try {
          const { error: insertError } = await supabase
            .from('internal_users')
            .insert([
              {
                id: newUserData.user.id,
                email: email,
                ghl_user_id: userId,
                role: role,
                first_name: firstName,
                last_name: lastName,
                created_at: new Date().toISOString(),
                is_active: true
              }
            ])

          if (insertError) {
            console.warn(`[${new Date().toISOString()}] Failed to insert into internal_users table:`, insertError.message)
            // Don't fail the request if insert fails
          } else {
            console.log(`[${new Date().toISOString()}] Created internal_users record for ${email}`)
          }
        } catch (tableError) {
          console.warn(`[${new Date().toISOString()}] internal_users table operation failed:`, tableError.message)
          // Continue anyway
        }
      }

      console.log(`[${new Date().toISOString()}] GHL authentication successful for user: ${email}`)

      // Return success response
      res.json({
        success: true,
        user: authResult.user,
        tokens: authResult.tokens,
        isNewUser: isNewUser
      })

    } catch (authError) {
      console.error(`[${new Date().toISOString()}] Supabase auth error:`, authError.message)
      return res.status(500).json({
        success: false,
        error: 'Authentication service unavailable'
      })
    }

  } catch (error) {
    console.error(`[${new Date().toISOString()}] GHL auth endpoint error:`, error.message)
    res.status(500).json({
      success: false,
      error: 'Internal server error'
    })
  }
})

// ============================================================================
// PHASE 2: TOKEN REFRESH MECHANISM
// ============================================================================

// Function to refresh GHL tokens
async function refreshGHLTokens(installationId, currentLocationRefreshToken) {
  try {
    const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_ROLE_KEY, {
      auth: {
        autoRefreshToken: false,
        persistSession: false
      }
    })

    // Get current installation details
    const { data: installation, error: getError } = await supabase
      .from('ghl_installations')
      .select('*')
      .eq('id', installationId)
      .single()

    if (getError || !installation) {
      throw new Error(`Installation not found: ${getError?.message}`)
    }

    console.log(`[${new Date().toISOString()}] Refreshing tokens for location: ${installation.ghl_location_id}`)

    // Refresh location token
    const refreshResponse = await axios.post('https://rest.gohighlevel.com/v1/oauth/locationToken/refresh', {
      refresh_token: currentLocationRefreshToken
    }, {
      headers: {
        'Content-Type': 'application/json'
      }
    })

    const { access_token: newLocationToken, refresh_token: newLocationRefreshToken, expires_in } = refreshResponse.data

    if (!newLocationToken) {
      throw new Error('No new access token received during refresh')
    }

    // Update tokens in database
    const newExpiresAt = new Date(Date.now() + (expires_in * 1000))
    
    const { error: updateError } = await supabase.rpc('store_ghl_installation', {
      p_ghl_agency_id: installation.ghl_agency_id,
      p_ghl_location_id: installation.ghl_location_id,
      p_agency_access_token: installation.agency_access_token, // Keep existing
      p_agency_refresh_token: installation.agency_refresh_token, // Keep existing  
      p_agency_token_expires_at: installation.agency_token_expires_at, // Keep existing
      p_location_access_token: newLocationToken,
      p_location_refresh_token: newLocationRefreshToken,
      p_location_token_expires_at: newExpiresAt.toISOString(),
      p_installed_by_user_id: installation.installed_by_user_id,
      p_location_name: installation.location_name,
      p_location_address: installation.location_address
    })

    if (updateError) {
      throw new Error(`Failed to update tokens: ${updateError.message}`)
    }

    console.log(`[${new Date().toISOString()}] Successfully refreshed tokens for location: ${installation.ghl_location_id}`)
    return newLocationToken

  } catch (error) {
    console.error(`[${new Date().toISOString()}] Token refresh failed:`, error.message)
    throw error
  }
}

// Schedule token refresh check every hour
cron.schedule('0 * * * *', async () => {
  try {
    console.log(`[${new Date().toISOString()}] Running scheduled token refresh check`)
    
    const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_ROLE_KEY, {
      auth: {
        autoRefreshToken: false,
        persistSession: false
      }
    })

    // Find installations with tokens expiring in the next 2 hours
    const expiryThreshold = new Date(Date.now() + (2 * 60 * 60 * 1000)) // 2 hours from now

    const { data: installations, error } = await supabase
      .from('ghl_installations')
      .select('id, ghl_location_id, location_refresh_token, location_token_expires_at')
      .eq('installation_status', 'active')
      .lt('location_token_expires_at', expiryThreshold.toISOString())

    if (error) {
      console.error(`[${new Date().toISOString()}] Failed to fetch installations for refresh:`, error.message)
      return
    }

    if (!installations || installations.length === 0) {
      console.log(`[${new Date().toISOString()}] No tokens need refreshing`)
      return
    }

    console.log(`[${new Date().toISOString()}] Found ${installations.length} installations needing token refresh`)

    // Refresh tokens for each installation
    for (const installation of installations) {
      try {
        // Decrypt the refresh token
        const { data: tokenData } = await supabase.rpc('get_ghl_location_token', {
          p_ghl_location_id: installation.ghl_location_id
        })

        if (tokenData && tokenData.length > 0) {
          await refreshGHLTokens(installation.id, tokenData[0].location_refresh_token)
        }
      } catch (refreshError) {
        console.error(`[${new Date().toISOString()}] Failed to refresh token for installation ${installation.id}:`, refreshError.message)
        
        // Mark installation as error if refresh fails
        await supabase
          .from('ghl_installations')
          .update({ installation_status: 'error', updated_at: new Date().toISOString() })
          .eq('id', installation.id)
      }
    }

  } catch (error) {
    console.error(`[${new Date().toISOString()}] Scheduled token refresh error:`, error.message)
  }
})

// ============================================================================
// PHASE 3: INTEGRATION & API PROXY
// ============================================================================

// List GHL Installations/Locations
app.get('/api/ghl-locations', async (req, res) => {
  try {
    const authHeader = req.headers.authorization
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({
        success: false,
        error: 'Authentication required'
      })
    }

    const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_ROLE_KEY, {
      auth: {
        autoRefreshToken: false,
        persistSession: false
      }
    })

    // Get user from token
    const token = authHeader.split(' ')[1]
    const { data: user, error: userError } = await supabase.auth.getUser(token)
    
    if (userError || !user) {
      return res.status(401).json({
        success: false,
        error: 'Invalid authentication token'
      })
    }

    console.log(`[${new Date().toISOString()}] Fetching GHL locations for user: ${user.user.email}`)

    // Check if user is admin (can see all) or staff (can see based on permissions)
    const { data: internalUser } = await supabase
      .from('internal_users')
      .select('role')
      .eq('id', user.user.id)
      .single()

    let query = supabase
      .from('ghl_installations')
      .select(`
        id,
        ghl_agency_id,
        ghl_location_id,
        location_name,
        location_address,
        installation_status,
        created_at,
        updated_at
      `)
      .eq('installation_status', 'active')

    // If not admin, filter based on user permissions (future enhancement)
    if (internalUser?.role !== 'admin') {
      // For now, allow all staff to see all locations
      // In future, this could be filtered based on store assignments
    }

    const { data: installations, error: locationsError } = await query

    if (locationsError) {
      throw new Error(`Failed to fetch locations: ${locationsError.message}`)
    }

    console.log(`[${new Date().toISOString()}] Found ${installations?.length || 0} GHL locations`)

    res.json({
      success: true,
      locations: installations || []
    })

  } catch (error) {
    console.error(`[${new Date().toISOString()}] GHL locations fetch error:`, error.message)
    res.status(500).json({
      success: false,
      error: 'Failed to fetch GHL locations'
    })
  }
})

// GHL API Proxy - Generic endpoint for proxying GHL API calls
app.post('/api/ghl-proxy', async (req, res) => {
  try {
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

    const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_ROLE_KEY, {
      auth: {
        autoRefreshToken: false,
        persistSession: false
      }
    })

    // Authenticate user
    const token = authHeader.split(' ')[1]
    const { data: user, error: userError } = await supabase.auth.getUser(token)
    
    if (userError || !user) {
      return res.status(401).json({
        success: false,
        error: 'Invalid authentication token'
      })
    }

    console.log(`[${new Date().toISOString()}] GHL API proxy request - User: ${user.user.email}, Location: ${ghl_location_id}, Endpoint: ${endpoint}`)

    // Get location token
    const { data: tokenData, error: tokenError } = await supabase.rpc('get_ghl_location_token', {
      p_ghl_location_id: ghl_location_id
    })

    if (tokenError || !tokenData || tokenData.length === 0) {
      return res.status(404).json({
        success: false,
        error: 'GHL location not found or not accessible'
      })
    }

    let locationToken = tokenData[0].location_access_token
    const tokenExpiresAt = new Date(tokenData[0].token_expires_at)
    const installationId = tokenData[0].installation_id

    // Check if token needs refresh
    if (tokenExpiresAt <= new Date()) {
      console.log(`[${new Date().toISOString()}] Token expired, refreshing for location: ${ghl_location_id}`)
      try {
        locationToken = await refreshGHLTokens(installationId, tokenData[0].location_refresh_token)
      } catch (refreshError) {
        return res.status(500).json({
          success: false,
          error: 'Failed to refresh GHL token'
        })
      }
    }

    // Make API request to GoHighLevel
    const ghlUrl = `https://rest.gohighlevel.com/v1${endpoint}`
    const axiosConfig = {
      method: method.toUpperCase(),
      url: ghlUrl,
      headers: {
        'Authorization': `Bearer ${locationToken}`,
        'Accept': 'application/json'
      }
    }

    if (requestData && ['POST', 'PUT', 'PATCH'].includes(method.toUpperCase())) {
      axiosConfig.data = requestData
      axiosConfig.headers['Content-Type'] = 'application/json'
    }

    const ghlResponse = await axios(axiosConfig)

    console.log(`[${new Date().toISOString()}] GHL API proxy successful - Status: ${ghlResponse.status}`)

    res.json({
      success: true,
      data: ghlResponse.data,
      status: ghlResponse.status
    })

  } catch (error) {
    console.error(`[${new Date().toISOString()}] GHL API proxy error:`, error.message)
    
    // Handle GHL API specific errors
    let errorMessage = 'GHL API request failed'
    let statusCode = 500
    
    if (error.response) {
      statusCode = error.response.status
      errorMessage = error.response.data?.message || error.response.data?.error || errorMessage
    }

    res.status(statusCode).json({
      success: false,
      error: errorMessage
    })
  }
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