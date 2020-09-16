const { initRustAPI, initVcxWithConfig, provisionAgent } = require('@absaoss/node-vcx-wrapper')
const ffi = require('ffi-napi')
const os = require('os')
const isPortReachable = require('is-port-reachable')
const url = require('url')
const extension = { darwin: '.dylib', linux: '.so', win32: '.dll' }
const libPath = { darwin: '/usr/local/lib/', linux: '/usr/lib/', win32: 'c:\\windows\\system32\\' }

module.exports.allowedProtocolTypes = ['1.0', '2.0', '3.0', '4.0']

module.exports.protocolTypes = {
  v1: '1.0',
  v2: '2.0',
  v3: '3.0',
  v4: '4.0'
}

function getLibraryPath (libraryName) {
  const platform = os.platform()
  const postfix = extension[platform.toLowerCase()] || extension.linux
  const libDir = libPath[platform.toLowerCase()] || libPath.linux
  return `${libDir}${libraryName}${postfix}`
}

async function loadPostgresPlugin (provisionConfig) {
  const myffi = ffi.Library(getLibraryPath('libindystrgpostgres'), { postgresstorage_init: ['void', []] })
  await myffi.postgresstorage_init()
}

async function initLibNullPay () {
  const myffi = ffi.Library(getLibraryPath('libnullpay'), { nullpay_init: ['void', []] })
  await myffi.nullpay_init()
}

async function initRustApiAndLogger (logLevel) {
  const rustApi = initRustAPI()
  await rustApi.vcx_set_default_logger(logLevel)
}

async function initVcxWithProvisionedAgentConfig (config) {
  await initVcxWithConfig(JSON.stringify(config))
}

async function initRustapi (logLevel = 'vcx=error') {
  await initLibNullPay()
  await initRustApiAndLogger(logLevel)
}

async function provisionAgentInAgency (agentName, protocolType, agencyUrl, seed, webhookUrl, usePostgresWallet, logger) {
  if (!agentName) {
    throw Error('agentName not specified')
  }
  if (!protocolType) {
    throw Error('protocolType not specified')
  }
  if (!agencyUrl) {
    throw Error('agencyUrl not specified')
  }
  if (!seed) {
    throw Error('seed not specified')
  }
  if (!webhookUrl) {
    throw Error('webhookUrl not specified')
  }
  const provisionConfig = {
    agency_url: agencyUrl,
    agency_did: 'VsKV7grR1BUE29mG2Fm2kX',
    agency_verkey: 'Hezce2UWMZ3wUhVkh2LfKSs8nDzWwzs2Win7EzNN3YaR',
    wallet_name: agentName,
    wallet_key: '123',
    payment_method: 'null',
    enterprise_seed: seed,
    protocol_type: protocolType
  }
  if (usePostgresWallet) {
    logger.info('Will use PostreSQL wallet. Initializing plugin.')
    await loadPostgresPlugin(provisionConfig)
    provisionConfig.wallet_type = 'postgres_storage'
    provisionConfig.storage_config = '{"url":"localhost:5432"}'
    provisionConfig.storage_credentials = '{"account":"postgres","password":"mysecretpassword","admin_account":"postgres","admin_password":"mysecretpassword"}'
    logger.info(`Running with PostreSQL wallet enabled! Config = ${provisionConfig.storage_config}`)
  } else {
    logger.info('Running with builtin wallet.')
  }

  if (await isPortReachable(url.parse(webhookUrl).port, { host: url.parse(webhookUrl).hostname })) { // eslint-disable-line
    provisionConfig.webhook_url = webhookUrl
    logger.info(`Running with webhook notifications enabled! Webhook url = ${webhookUrl}`)
  } else {
    logger.info('Webhook url will not be used')
  }

  logger.info(`Using following config to create agent provision: ${JSON.stringify(provisionConfig, null, 2)}`)
  const agentProvision = JSON.parse(await provisionAgent(JSON.stringify(provisionConfig)))
  agentProvision.institution_name = agentName
  agentProvision.institution_logo_url = 'https://example.org'
  agentProvision.genesis_path = `${__dirname}/docker.txn`
  logger.info(`Agent provision created: ${JSON.stringify(agentProvision, null, 2)}`)
  return agentProvision
}

module.exports.loadPostgresPlugin = loadPostgresPlugin
module.exports.initLibNullPay = initLibNullPay
module.exports.initRustApiAndLogger = initRustApiAndLogger
module.exports.initVcxWithProvisionedAgentConfig = initVcxWithProvisionedAgentConfig
module.exports.provisionAgentInAgency = provisionAgentInAgency
module.exports.initRustapi = initRustapi
