const { pollFunction } = require('../common')
const { holderSelectCredentialsForProof } = require('../utils/proofs')
const {
  DisclosedProof,
  ProverStateType
} = require('@hyperledger/node-vcx-wrapper')

module.exports.createServiceProver = function createServiceProver ({ logger, loadConnection, saveDisclosedProof, loadDisclosedProof, listDislosedProofIds }) {
  async function _progressProofToState (proof, connection, targetStates, attemptsThreshold, timeoutMs) {
    async function progressToAcceptedState () {
      if (!Array.isArray(targetStates)) {
        throw Error('Argument targetStates should be array.')
      }
      const state = await proof.updateStateV2(connection)
      if (targetStates.includes(state)) {
        return { result: null, isFinished: true }
      } else {
        return { result: undefined, isFinished: false }
      }
    }

    const [error] = await pollFunction(progressToAcceptedState, `Progress ProofSM to one of states ${JSON.stringify(targetStates)}`, logger, attemptsThreshold, timeoutMs)
    if (error) {
      throw Error(`Couldn't progress credential to Accepted state. ${error}`)
    }
  }

  async function _getProofRequests (connection, attemptsThreshold, timeoutMs) {
    async function findSomeRequests () {
      const requests = await DisclosedProof.getRequests(connection)
      if (requests.length === 0) {
        return { result: undefined, isFinished: false }
      } else {
        return { result: requests, isFinished: true }
      }
    }

    const [error, proofRequests] = await pollFunction(findSomeRequests, 'Get proof request', logger, attemptsThreshold, timeoutMs)
    if (error) {
      throw Error(`Couldn't find any proof request. ${error}`)
    }
    return proofRequests
  }

  async function waitForProofRequests (connectionId, attemptsThreshold = 10, timeoutMs = 2000) {
    const connection = await loadConnection(connectionId)
    const proofRequests = await _getProofRequests(connection, attemptsThreshold, timeoutMs)
    logger.info(`Found ${proofRequests.length} credential offers.`)
    return proofRequests
  }

  async function getProofRequests (connectionId) {
    const connection = await loadConnection(connectionId)
    return DisclosedProof.getRequests(connection)
  }

  async function buildDisclosedProof (disclosedProofId, proofRequest) {
    const request = typeof proofRequest === 'string' ? proofRequest : JSON.stringify(proofRequest)
    const disclosedProof = await DisclosedProof.create({ sourceId: 'proof', request })
    await saveDisclosedProof(disclosedProofId, disclosedProof)
  }

  async function selectCredentials (disclosedProofId, mapRevRegIdToTailsFilePath) {
    const disclosedProof = await loadDisclosedProof(disclosedProofId)
    return holderSelectCredentialsForProof(disclosedProof, logger, mapRevRegIdToTailsFilePath)
  }

  async function generateProof (disclosedProofId, selectedCreds, selfAttestedAttrs) {
    const disclosedProof = await loadDisclosedProof(disclosedProofId)
    await disclosedProof.generateProof({ selectedCreds, selfAttestedAttrs })
    await saveDisclosedProof(disclosedProofId, disclosedProof)
  }

  async function sendDisclosedProof (disclosedProofId, connectionId) {
    const disclosedProof = await loadDisclosedProof(disclosedProofId)
    const connection = await loadConnection(connectionId)
    await disclosedProof.sendProof(connection)
    const state = await disclosedProof.getState()
    await saveDisclosedProof(disclosedProofId, disclosedProof)
    return state
  }

  async function sendDisclosedProofAndProgress (disclosedProofId, connectionId) {
    await sendDisclosedProof(disclosedProofId, connectionId)
    const disclosedProof = await loadDisclosedProof(disclosedProofId)
    const connection = await loadConnection(connectionId)
    await _progressProofToState(disclosedProof, connection, [ProverStateType.PresentationPreparationFailed, ProverStateType.PresentationSent])
    const state = await disclosedProof.getState()
    await saveDisclosedProof(disclosedProofId, disclosedProof)
    return state
  }

  async function disclosedProofUpdate (disclosedProofId, connectionId) {
    const disclosedProof = await loadDisclosedProof(disclosedProofId)
    const connection = await loadConnection(connectionId)
    const state = await disclosedProof.updateStateV2(connection)
    await saveDisclosedProof(disclosedProofId, disclosedProof)
    return state
  }

  async function getState (disclosedProofId) {
    const disclosedProof = await loadDisclosedProof(disclosedProofId)
    return await disclosedProof.getState()
  }

  async function listIds () {
    return listDislosedProofIds()
  }

  async function printInfo (disclosedProofIds) {
    for (const id of disclosedProofIds) {
      const state = await getState(id)
      logger.info(`DisclosedProof ${id} state=${state}`)
    }
  }

  async function getVcxDisclosedProof (disclosedProofId) {
    logger.warn('Usage of getVcxDisclosedProof is not recommended. You should use vcxagent-core API rather than work with vcx object directly.')
    return loadDisclosedProof(disclosedProofId)
  }

  return {
    generateProof,
    selectCredentials,
    getProofRequests,
    waitForProofRequests,
    sendDisclosedProof,
    sendDisclosedProofAndProgress,
    buildDisclosedProof,
    disclosedProofUpdate,

    listIds,
    printInfo,
    getState
  }
}
