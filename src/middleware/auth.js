// src/middleware/auth.js
const { getUserClient } = require('../lib/supabase')

async function requireAuth(req, res, next) {
  try {
    const authHeader = req.headers.authorization
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ success: false, error: 'Authentication required' })
    }
    const token = authHeader.split(' ')[1]
    const supabase = getUserClient(token)
    const { data, error } = await supabase.auth.getUser(token)
    if (error || !data?.user) {
      return res.status(401).json({ success: false, error: 'Invalid authentication token' })
    }
    req.user = data.user
    req.supabase = supabase
    return next()
  } catch (e) {
    return res.status(500).json({ success: false, error: 'Auth validation failed' })
  }
}

module.exports = { requireAuth }

