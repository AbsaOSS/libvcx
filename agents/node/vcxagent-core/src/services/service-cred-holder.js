const {filterOffersByCredentialName} = require('../utils/credentials')
const { filterOffersByAttr } = require('../utils/credentials')
const { filterOffersBySchema } = require('../utils/credentials')
const {
  HolderStateType,
  Credential
} = require('@hyperledger/node-vcx-wrapper')
const { pollFunction } = require('../common')

module.exports.createServiceCredHolder = function createServiceCredHolder ({ logger, loadConnection, saveHolderCredential, loadHolderCredential, listHolderCredentialIds }) {
  async function _getOffers (connection, filter, attemptsThreshold, timeoutMs) {
    async function findSomeCredOffer () {
      let offers = await Credential.getOffers(connection)
      logger.info(`Offers: ${offers}`)
      if (filter && filter.schemaIdRegex) {
        offers = filterOffersBySchema(offers, filter.schemaIdRegex)
      }
      if (filter && filter.attrRegex) {
        offers = filterOffersByAttr(offers, filter.attrRegex)
      }
      if (offers.length === 0) {
        return { result: undefined, isFinished: false }
      } else {
        return { result: offers, isFinished: true }
      }
    }

    const [error, offers] = await pollFunction(findSomeCredOffer, 'Get credential offer', logger, attemptsThreshold, timeoutMs)
    if (error) {
      throw Error(`Couldn't get credential offers. ${error}`)
    }
    return offers
  }

  async function _progressCredentialToState (credential, connection, credentialStateTarget, attemptsThreshold = 10, timeoutMs = 2000) {
    async function progressToAcceptedState () {
      if (await credential.updateStateV2(connection) !== credentialStateTarget) {
        return { result: undefined, isFinished: false }
      } else {
        return { result: null, isFinished: true }
      }
    }

    const [error] = await pollFunction(progressToAcceptedState, `Progress CredentialSM to state ${credentialStateTarget}`, logger, attemptsThreshold, timeoutMs)
    if (error) {
      throw Error(`Couldn't progress credential to Accepted state. ${error}`)
    }
  }

  async function waitForCredential (connectionId, holderCredentialId, attemptsThreshold = 10, timeoutMs = 2000) {
    const connection = await loadConnection(connectionId)
    const credential = await loadHolderCredential(holderCredentialId)
    await _progressCredentialToState(credential, connection, HolderStateType.Finished, attemptsThreshold, timeoutMs)
    logger.info('Credential has been received.')
    await saveHolderCredential(holderCredentialId, credential)
    return getCredentialData(holderCredentialId)
  }

  async function getCredentialData (holderCredentialId) {
    const credential = await loadHolderCredential(holderCredentialId)
    const serCred = await credential.serialize()
    return JSON.parse(
      Buffer.from(serCred.data.holder_sm.state.Finished.credential['credentials~attach'][0].data.base64, 'base64')
        .toString('utf8')
    )
  }

  async function createCredentialFromOfferAndSendRequest (connectionId, holderCredentialId, credentialOffer) {
    const connection = await loadConnection(connectionId)
    const credential = await Credential.create({ sourceId: 'credential', offer: credentialOffer })
    await saveHolderCredential(holderCredentialId, credential)
    logger.info('Sending credential request')
    await credential.sendRequest({ connection, payment: 0 })
    await saveHolderCredential(holderCredentialId, credential)
    return credential
  }

  async function waitForCredentialOffer (connectionId, credOfferFilter = null, attemptsThreshold = 10, timeoutMs = 2000) {
    logger.info('Going to try fetch credential offer and receive credential.')
    const connection = await loadConnection(connectionId)
    const offers = await _getOffers(connection, credOfferFilter, attemptsThreshold, timeoutMs)
    logger.info(`Found ${offers.length} credential offers.`)
    const pickedOffer = JSON.stringify(offers[0])
    logger.debug(`Picked credential offer = ${pickedOffer}`)
    return pickedOffer
  }

  async function waitForCredentialOfferAndAccept (connectionId, holderCredentialId, credOfferFilter = null, attemptsThreshold = 10, timeoutMs = 2000) {
    const pickedOffer = await waitForCredentialOffer(connectionId, credOfferFilter, attemptsThreshold, timeoutMs)
    return createCredentialFromOfferAndSendRequest(connectionId, holderCredentialId, pickedOffer)
  }

  async function waitForCredentialOfferAndAcceptAndProgress (connectionId, holderCredentialId, credOfferFilter = null, attemptsThreshold = 10, timeoutMs = 2000) {
    logger.info('Going to try fetch credential offer and receive credential.')
    await waitForCredentialOfferAndAccept(connectionId, holderCredentialId, credOfferFilter, attemptsThreshold, timeoutMs)
    return waitForCredential(connectionId, holderCredentialId, attemptsThreshold, timeoutMs)
  }

  async function credentialUpdate (holderCredentialId, connectionId) {
    const connection = await loadConnection(connectionId)
    const cred = await loadHolderCredential(holderCredentialId)
    const state = await cred.updateStateV2(connection)
    await saveHolderCredential(holderCredentialId, cred)
    return state
  }

  async function getTailsLocation (holderCredentialId) {
    logger.info(`Getting tails location for credential ${holderCredentialId}`)
    const cred = await loadHolderCredential(holderCredentialId)
    const tailsLocation = await cred.getTailsLocation()
    logger.debug(`Holder's tails location: ${tailsLocation}`)
    return tailsLocation
  }

  async function getRevRegId (holderCredentialId) {
    logger.info(`Getting rev reg id for credential ${holderCredentialId}`)
    const cred = await loadHolderCredential(holderCredentialId)
    const revRegId = await cred.getRevRegId()
    logger.debug(`Holder's rev reg id: ${revRegId}`)
    return revRegId
  }

  async function getTailsHash (holderCredentialId) {
    logger.info(`Getting to get tails hash for credential ${holderCredentialId}`)
    const cred = await loadHolderCredential(holderCredentialId)
    const tailsHash = await cred.getTailsHash()
    logger.debug(`Holder's tails hash: ${tailsHash}`)
    return tailsHash
  }

  async function getState (credHolderId) {
    const credential = await loadHolderCredential(credHolderId)
    return await credential.getState()
  }

  async function listIds () {
    return listHolderCredentialIds()
  }

  async function printInfo (credHolderIds) {
    for (const id of credHolderIds) {
      const state = await getState(id)
      logger.info(`Credential ${id} state=${state}`)
    }
  }

  async function getVcxCredential (credHolderId) {
    logger.warn('Usage of getVcxCredential is not recommended. You should use vcxagent-core API rather than work with vcx object directly.')
    return loadHolderCredential(credHolderId)
  }

  return {
    waitForCredentialOffer,
    createCredentialFromOfferAndSendRequest,
    waitForCredential,
    getCredentialData,
    waitForCredentialOfferAndAccept,
    waitForCredentialOfferAndAcceptAndProgress,
    credentialUpdate,
    getTailsLocation,
    getRevRegId,
    getTailsHash,
    getVcxCredential,

    listIds,
    printInfo,
    getState
  }
}
