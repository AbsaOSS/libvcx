const {
  IssuerStateType,
  IssuerCredential
} = require('@hyperledger/node-vcx-wrapper')
const { pollFunction } = require('../common')

module.exports.createServiceCredIssuer = function createServiceCredIssuer ({ logger, loadConnection, loadCredDef, saveIssuerCredential, loadIssuerCredential, listIssuerCredentialIds, issuerDid }) {
  async function sendOffer (issuerCredId, connectionId, credDefId, schemaAttrs) {
    const connection = await loadConnection(connectionId)
    const credDef = await loadCredDef(credDefId)
    logger.debug('Building issuer credential')
    const issuerCred = await IssuerCredential.create({
      attr: schemaAttrs,
      sourceId: 'alice_degree',
      credDefHandle: credDef.handle,
      credentialName: 'cred',
      price: '0',
      issuerDid
    })
    logger.info(`Per issuer credential ${issuerCredId}, sending cred offer to connection ${connectionId}`)
    await issuerCred.sendOffer(connection)
    await saveIssuerCredential(issuerCredId, issuerCred)
  }

  async function sendCredential (issuerCredId, connectionId) {
    const connection = await loadConnection(connectionId)
    const issuerCred = await loadIssuerCredential(issuerCredId)
    logger.info(`Sending credential ${issuerCredId} to ${connectionId}`)
    await issuerCred.sendCredential(connection)
    const state = await issuerCred.getState()
    await saveIssuerCredential(issuerCredId, issuerCred)
    return state
  }

  async function sendOfferAndWaitForCredRequest (issuerCredId, connectionId, credDefId, schemaAttrs) {
    await sendOffer(issuerCredId, connectionId, credDefId, schemaAttrs)
    const issuerCred = await loadIssuerCredential(issuerCredId)
    const connection = await loadConnection(connectionId)
    logger.debug('Going to wait until credential request is received.')
    await _progressIssuerCredentialToState(issuerCred, connection, IssuerStateType.RequestReceived, 10, 2000)
    await saveIssuerCredential(issuerCredId, issuerCred)
  }

  async function sendCredentialAndProgress (issuerCredId, connectionId) {
    await sendCredential(issuerCredId, connectionId)
    const connection = await loadConnection(connectionId)
    const issuerCred = await loadIssuerCredential(issuerCredId)
    logger.info('Going to wait until counterparty accepts the credential.')
    await _progressIssuerCredentialToState(issuerCred, connection, IssuerStateType.Finished, 10, 2000)
    await saveIssuerCredential(issuerCredId, issuerCred)
  }

  async function sendOfferAndCredential (issuerCredId, connectionId, credDefId, schemaAttrs) {
    await sendOfferAndWaitForCredRequest(issuerCredId, connectionId, credDefId, schemaAttrs)
    await sendCredentialAndProgress(issuerCredId, connectionId)
  }

  async function revokeCredential (issuerCredId) {
    const issuerCred = await loadIssuerCredential(issuerCredId)
    logger.info(`Revoking credential ${issuerCredId}`)
    await issuerCred.revokeCredential()
  }

  async function getRevRegId (issuerCredId) {
    const issuerCred = await loadIssuerCredential(issuerCredId)
    logger.info(`Getting rev reg id for credential ${issuerCredId}`)
    return issuerCred.getRevRegId()
  }

  async function _progressIssuerCredentialToState (issuerCredential, connection, credentialStateTarget, attemptsThreshold, timeoutMs) {
    async function progressToAcceptedState () {
      if (await issuerCredential.updateStateV2(connection) !== credentialStateTarget) {
        return { result: undefined, isFinished: false }
      } else {
        return { result: null, isFinished: true }
      }
    }

    const [error, offers] = await pollFunction(progressToAcceptedState, `Progress IssuerCredentialSM to state ${credentialStateTarget}`, logger, attemptsThreshold, timeoutMs)
    if (error) {
      throw Error(`Couldn't find suitable message to progress issuerCredential to state ${credentialStateTarget}. ${error}`)
    }
    return offers
  }

  async function credentialUpdate (issuerCredId, connectionId) {
    const connection = await loadConnection(connectionId)
    const issuerCred = await loadIssuerCredential(issuerCredId)
    const state = await issuerCred.updateStateV2(connection)
    await saveIssuerCredential(issuerCredId, issuerCred)
    return state
  }

  async function getState (issuerCredentialId) {
    const issuerCredential = await loadIssuerCredential(issuerCredentialId)
    return issuerCredential.getState()
  }

  async function listIds () {
    return listIssuerCredentialIds()
  }

  async function printInfo (issuerCredentialIds) {
    for (const id of issuerCredentialIds) {
      const state = await getState(id)
      logger.info(`IssuerCredential ${id} state=${state}`)
    }
  }

  async function getVcxCredentialIssuer (issuerCredentialId) {
    logger.warn('Usage of getVcxCredentialIssuer is not recommended. You should use vcxagent-core API rather than work with vcx object directly.')
    return loadIssuerCredential(issuerCredentialId)
  }

  return {
    sendOffer,
    sendOfferAndWaitForCredRequest,
    sendCredential,
    sendCredentialAndProgress,
    sendOfferAndCredential,
    revokeCredential,
    credentialUpdate,
    getVcxCredentialIssuer,

    listIds,
    printInfo,
    getState,
    getRevRegId
  }
}
