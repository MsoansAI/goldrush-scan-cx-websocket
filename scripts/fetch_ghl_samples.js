const fs = require('fs')
const path = require('path')
const axios = require('axios')

async function main() {
  const GHL_LOCATION_API_KEY = process.env.GHL_LOCATION_API_KEY || 'pit-1efa627c-f947-4b8b-98e9-e58cfa931ce1'
  const GHL_LOCATION_ID = process.env.GHL_LOCATION_ID || 'sbZmSdZiZECyTSZgIYo9'
  const baseUrl = 'https://services.leadconnectorhq.com'
  const headers = {
    Authorization: `Bearer ${GHL_LOCATION_API_KEY}`,
    Accept: 'application/json',
    'Content-Type': 'application/json',
    Version: '2021-07-28'
  }

  try {
    const contactsRes = await axios.get(`${baseUrl}/contacts/`, { headers, params: { locationId: GHL_LOCATION_ID, limit: 10 } })
    let customFields = []
    try {
      const cfRes = await axios.get(`${baseUrl}/locations/${GHL_LOCATION_ID}/customFields`, { headers })
      customFields = cfRes.data || []
    } catch (e) {
      customFields = []
    }

    const out = {
      fetched_at: new Date().toISOString(),
      contacts: contactsRes.data?.contacts || contactsRes.data?.items || contactsRes.data || [],
      customFields
    }

    const outPath = path.join(__dirname, '..', 'docs', 'ghl_samples.json')
    fs.writeFileSync(outPath, JSON.stringify(out, null, 2))
    console.log(`Saved sample to ${outPath}`)
  } catch (err) {
    console.error('Failed to fetch GHL samples:', err?.response?.data || err.message)
    process.exit(1)
  }
}

main()

