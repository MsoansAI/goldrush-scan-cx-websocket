// src/lib/supabase.js
const { createClient } = require('@supabase/supabase-js')

let cachedAdminClient = null

function getSupabaseUrl() {
  const url = process.env.SUPABASE_URL
  if (!url) {
    throw new Error('Missing SUPABASE_URL')
  }
  return url
}

function getAdminClient() {
  if (cachedAdminClient) return cachedAdminClient
  const serviceKey = process.env.SUPABASE_SERVICE_ROLE_KEY
  if (!serviceKey) {
    throw new Error('Missing SUPABASE_SERVICE_ROLE_KEY')
  }
  cachedAdminClient = createClient(getSupabaseUrl(), serviceKey, {
    auth: { autoRefreshToken: false, persistSession: false }
  })
  return cachedAdminClient
}

function getUserClient(userJwt) {
  const anonKey = process.env.SUPABASE_ANON_KEY || process.env.VITE_SUPABASE_ANON_KEY
  const apiKey = anonKey || process.env.SUPABASE_SERVICE_ROLE_KEY
  if (!apiKey) {
    throw new Error('Missing SUPABASE_ANON_KEY (or VITE_SUPABASE_ANON_KEY)')
  }
  if (!anonKey) {
    // Fallback is dangerous; log loudly
    console.warn('[security] Using service role key for user client due to missing anon key. Provide SUPABASE_ANON_KEY to enforce RLS.')
  }
  const client = createClient(getSupabaseUrl(), apiKey, {
    auth: { autoRefreshToken: false, persistSession: false }
  })
  return client
}

module.exports = { getAdminClient, getUserClient }

