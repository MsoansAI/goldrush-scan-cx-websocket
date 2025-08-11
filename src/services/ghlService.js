// src/services/ghlService.js
const axios = require('axios')
const { getAdminClient } = require('../lib/supabase')

async function storeInstallation({
  ghlAgencyId,
  ghlLocationId,
  agencyAccessToken,
  agencyRefreshToken,
  agencyExpiresAt,
  locationAccessToken,
  locationRefreshToken,
  locationExpiresAt,
  installedByUserId,
  locationName,
  locationAddress
}) {
  const supabase = getAdminClient()
  return await supabase.rpc('store_ghl_installation', {
    p_ghl_agency_id: ghlAgencyId,
    p_ghl_location_id: ghlLocationId,
    p_agency_access_token: agencyAccessToken,
    p_agency_refresh_token: agencyRefreshToken,
    p_agency_token_expires_at: agencyExpiresAt,
    p_location_access_token: locationAccessToken,
    p_location_refresh_token: locationRefreshToken,
    p_location_token_expires_at: locationExpiresAt,
    p_installed_by_user_id: installedByUserId,
    p_location_name: locationName,
    p_location_address: locationAddress
  })
}

async function getLocationToken(locationId) {
  const supabase = getAdminClient()
  return await supabase.rpc('get_ghl_location_token', { p_ghl_location_id: locationId })
}

async function refreshLocationToken(installation, currentRefreshToken) {
  const resp = await axios.post('https://rest.gohighlevel.com/v1/oauth/locationToken/refresh', {
    refresh_token: currentRefreshToken
  }, { headers: { 'Content-Type': 'application/json' } })

  const { access_token, refresh_token, expires_in } = resp.data
  const newExpiresAt = new Date(Date.now() + (expires_in * 1000)).toISOString()
  const { error } = await storeInstallation({
    ghlAgencyId: installation.ghl_agency_id,
    ghlLocationId: installation.ghl_location_id,
    agencyAccessToken: installation.agency_access_token,
    agencyRefreshToken: installation.agency_refresh_token,
    agencyExpiresAt: installation.agency_token_expires_at,
    locationAccessToken: access_token,
    locationRefreshToken: refresh_token,
    locationExpiresAt: newExpiresAt,
    installedByUserId: installation.installed_by_user_id,
    locationName: installation.location_name,
    locationAddress: installation.location_address
  })
  if (error) throw new Error(`Failed to update tokens: ${error.message}`)
  return access_token
}

module.exports = { storeInstallation, getLocationToken, refreshLocationToken }

