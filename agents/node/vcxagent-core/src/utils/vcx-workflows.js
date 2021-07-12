const {
  initRustAPI, initVcxWithConfig, provisionCloudAgent,
  createWallet, openMainWallet, closeMainWallet,
  configureIssuerWallet
} = require('@hyperledger/node-vcx-wrapper')
const ffi = require('ffi-napi')
const os = require('os')

const extension = { darwin: '.dylib', linux: '.so', win32: '.dll' }
const libPath = { darwin: '/usr/local/lib/', linux: '/usr/lib/', win32: 'c:\\windows\\system32\\' }

function getLibraryPath (libraryName) {
  const platform = os.platform()
  const postfix = extension[platform.toLowerCase()] || extension.linux
  const libDir = libPath[platform.toLowerCase()] || libPath.linux
  return `${libDir}${libraryName}${postfix}`
}

async function loadPostgresPlugin () {
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

async function provisionAgentInAgency (agentName, genesisPath, agencyUrl, seed, usePostgresWallet, logger) {
  logger.info('Provisioning cloud agent')
  if (!agentName) {
    throw Error('agentName not specified')
  }
  if (!genesisPath) {
    throw Error('genesisPath not specified')
  }
  if (!agencyUrl) {
    throw Error('agencyUrl not specified')
  }
  if (!seed) {
    throw Error('seed not specified')
  }

  const walletConfig = {
    wallet_name: agentName,
    wallet_key: '8dvfYSt5d1taSd6yJdpjq4emkwsPDDLYxkNFysFD2cZY',
    wallet_key_derivation: 'RAW'
  }

  if (usePostgresWallet) {
    logger.info('Will use PostreSQL wallet. Initializing plugin.')
    await loadPostgresPlugin()
    walletConfig.wallet_type = 'postgres_storage'
    walletConfig.storage_config = '{"url":"localhost:5432"}'
    walletConfig.storage_credentials = '{"account":"postgres","password":"mysecretpassword","admin_account":"postgres","admin_password":"mysecretpassword"}'
    logger.info(`Running with PostreSQL wallet enabled! Config = ${walletConfig.storage_config}`)
  } else {
    logger.info('Running with builtin wallet.')
  }

  let agencyConfig = {
    agency_endpoint: agencyUrl,
    agency_did: 'VsKV7grR1BUE29mG2Fm2kX',
    agency_verkey: 'Hezce2UWMZ3wUhVkh2LfKSs8nDzWwzs2Win7EzNN3YaR'
  }

  logger.debug(`Creating wallet with config: ${JSON.stringify(walletConfig, null, 2)}`)
  await createWallet(walletConfig)
  logger.debug(`Opening wallet with config: ${JSON.stringify(walletConfig, null, 2)}`)
  await openMainWallet(walletConfig)
  logger.debug(`Configuring issuer's wallet with seed: ${seed}`)
  const issuerConfig = JSON.parse(await configureIssuerWallet(seed))
  issuerConfig.institution_name = agentName
  logger.debug(`Configured issuer wallet with config: ${JSON.stringify(issuerConfig, null, 2)}`)
  logger.debug(`Provisioning agent with config: ${JSON.stringify(agencyConfig, null, 2)}`)
  agencyConfig = JSON.parse(await provisionCloudAgent(agencyConfig))
  logger.debug(`Provisioned agent with config: ${JSON.stringify(agencyConfig, null, 2)}`)
  await closeMainWallet()

  return { agencyConfig, issuerConfig, walletConfig }
}

module.exports.loadPostgresPlugin = loadPostgresPlugin
module.exports.initLibNullPay = initLibNullPay
module.exports.initRustApiAndLogger = initRustApiAndLogger
module.exports.initVcxWithProvisionedAgentConfig = initVcxWithProvisionedAgentConfig
module.exports.provisionAgentInAgency = provisionAgentInAgency
module.exports.initRustapi = initRustapi
