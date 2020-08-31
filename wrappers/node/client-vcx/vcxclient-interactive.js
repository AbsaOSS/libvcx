const { provisionAgent, initRustapi } = require('./vcx-workflows')
const readlineSync = require('readline-sync')
const { createVcxClient } = require('./vcxclient')
const logger = require('../common/logger')('VCX Client')
const { waitUntilAgencyIsReady } = require('./common')
const { createStorageService } = require('./storage-service')

async function createInteractiveClient (agentName, seed, acceptTaa, protocolType, rustlog) {
  logger.debug('Initializing rust api')
  await initRustapi(rustlog)
  logger.debug('Rust api initialized')

  logger.info(`Creating interactive client ${agentName} seed=${seed} protocolType=${protocolType}`)

  const webhookUrl = `http://localhost:7209/notifications/${agentName}`
  const usePostgresWallet = false
  const agencyUrl = 'http://localhost:8080'

  logger.info(`Created interactive client for agent ${agentName}.`)
  const storageService = await createStorageService(agentName)

  await waitUntilAgencyIsReady(agencyUrl, logger)

  if (!await storageService.agentProvisionExists()) {
    const agentProvision = await provisionAgent(agentName, protocolType, agencyUrl, seed, webhookUrl, usePostgresWallet, logger)
    await storageService.saveAgentProvision(agentProvision)
  }
  const vcxClient = await createVcxClient(storageService, logger)

  if (acceptTaa) {
    await vcxClient.acceptTaa()
  }

  const commands = {
    0: 'ACCEPT_TAA',
    1: 'CREATE_SCHEMA',
    2: 'CREATE_CRED_DEF',
    10: 'CONNECTION_CREATE',
    11: 'CONNECTION_ACCEPT',
    12: 'CONNECTION_FINISH',
    13: 'CONNECTION_INFO',
    14: 'CONNECTIONS_INFO',
    20: 'GET_CREDENTIAL_OFFERS'
  }

  while (true) {
    const cmd = readlineSync.question(`Select action: ${JSON.stringify(commands, null, 2)}\n`)
    if (cmd) {
      if (cmd === '0') {
        logger.info('Going to accept taa.\n')
        await vcxClient.acceptTaa()
        logger.info('Taa accepted.\n')
      } else if (cmd === '1') {
        logger.info(`Cmd was ${cmd}, going to create schema\n`)
        const schema = await vcxClient.createSchema()
        logger.info(`Schema created ${JSON.stringify(await schema.serialize())}`)
      } else if (cmd === '2') {
        const schemaId = readlineSync.question('Enter schemaId:\n')
        const name = readlineSync.question('Enter credDef name:\n')
        logger.info(`Cmd was ${cmd}, going to create cred def`)
        const credentialDef = await vcxClient.createCredentialDefinition(schemaId, name)
        logger.info(`Credential definition ${JSON.stringify(await credentialDef.serialize())}`)
      } else if (cmd === '10') {
        const connectionName = readlineSync.question('Enter connection name:\n')
        const invitationString = await vcxClient.connectionCreate(connectionName)
        logger.info(`Connection ${connectionName} created. Invitation String ${invitationString}`)
        await vcxClient.connectionAutoupdate(connectionName)
      } else if (cmd === '11') {
        const connectionName = readlineSync.question('Enter connection name:\n')
        const invitationString = readlineSync.question('Enter invitation:\n')
        await vcxClient.connectionAccept(connectionName, invitationString)
        await vcxClient.connectionAutoupdate(connectionName)
      } else if (cmd === '12') {
        const connectionName = readlineSync.question('Enter connection name:\n')
        await vcxClient.connectionAutoupdate(connectionName)
      } else if (cmd === '13') {
        const connectionName = readlineSync.question('Enter connection name:\n')
        await vcxClient.connectionPrintInfo(connectionName)
      } else if (cmd === '14') {
        logger.info('Listing connections:')
        await vcxClient.connectionsList()
      } else if (cmd === '20') {
        const connectionName = readlineSync.question('Enter connection name:\n')
        await vcxClient.getCredentialOffers(connectionName)
      } else {
        logger.error(`Unknown command ${cmd}`)
      }
    }
  }
}

async function runInteractive (options) {
  logger.debug(`Going to build interactive client using options ${JSON.stringify(options)}`)
  const agentName = options.name || readlineSync.question('Enter agent\'s name:\n')
  await createInteractiveClient(agentName, options.seed, options.acceptTaa, options.protocolType, options.RUST_LOG)
}

module.exports.runInteractive = runInteractive
