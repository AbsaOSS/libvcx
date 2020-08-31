const { initRustAPI, initVcxWithConfig, provisionAgent } = require('../dist/src')
const ffi = require('ffi-napi')
const os = require('os')
const sleepPromise = require('sleep-promise')
const axios = require('axios')

const extension = { darwin: '.dylib', linux: '.so', win32: '.dll' }
const libPath = { darwin: '/usr/local/lib/', linux: '/usr/lib/', win32: 'c:\\windows\\system32\\' }

module.exports.allowedProtocolTypes = ['1.0', '2.0', '3.0', '4.0']

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

async function provisionAgentInAgency (config) {
  return JSON.parse(await provisionAgent(JSON.stringify(config)))
}

async function initVcxWithProvisionedAgentConfig (config) {
  await initVcxWithConfig(JSON.stringify(config))
}

function getRandomInt (min, max) {
  min = Math.ceil(min)
  max = Math.floor(max)
  return Math.floor(Math.random() * (max - min)) + min
}

async function waitUntilAgencyIsReady (agencyEndpoint, logger) {
  let agencyReady = false
  while (!agencyReady) {
    try {
      await axios.get(`${agencyEndpoint}/agency`)
      agencyReady = true
    } catch (e) {
      logger.warn(`Agency ${agencyEndpoint} should return 200OK on HTTP GET ${agencyEndpoint}/agency, but returns error: ${e}. Sleeping.`)
      await sleepPromise(1000)
    }
  }
}

async function pollFunction (fn, actionDescription, logger, attemptsThreshold = 10, timeout = 2000) {
  let { result, isFinished } = await fn()
  let attempts = 1
  while (!isFinished) {
    if (attempts > attemptsThreshold) {
      const error = `Tried to poll ${attempts} times and result was not received.`
      return [error, null]
    }
    logger.info(`Trying to do: ${actionDescription} Attempt ${attempts}/${attemptsThreshold}. Will try again after ${timeout}ms.`)
    await sleepPromise(timeout);
    ({ result, isFinished } = await fn())
    attempts += 1
  }
  return [null, result]
}

module.exports.loadPostgresPlugin = loadPostgresPlugin
module.exports.initLibNullPay = initLibNullPay
module.exports.initRustApiAndLogger = initRustApiAndLogger
module.exports.provisionAgentInAgency = provisionAgentInAgency
module.exports.initVcxWithProvisionedAgentConfig = initVcxWithProvisionedAgentConfig
module.exports.getRandomInt = getRandomInt
module.exports.waitUntilAgencyIsReady = waitUntilAgencyIsReady
module.exports.pollFunction = pollFunction
