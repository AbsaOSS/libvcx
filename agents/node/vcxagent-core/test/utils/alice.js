/* eslint-env jest */
const { createVcxAgent } = require('../../src/index')
const { ConnectionStateType, ProverStateType } = require('@hyperledger/node-vcx-wrapper')

module.exports.createAlice = async function createAlice () {
  const agentName = `alice-${Math.floor(new Date() / 1000)}`
  const connectionId = 'connection-alice-to-faber'
  const holderCredentialId = 'credential-of-alice'
  const disclosedProofId = 'proof-from-alice'
  const logger = require('../../demo/logger')('Alice')

  const aliceAgentConfig = {
    agentName,
    agencyUrl: 'http://localhost:8080',
    seed: '000000000000000000000000Alice000',
    webhookUrl: `http://localhost:7209/notifications/${agentName}`,
    usePostgresWallet: false,
    logger
  }
  const vcxAgent = await createVcxAgent(aliceAgentConfig)

  async function acceptInvite (invite) {
    logger.info('Alice establishing connection with Faber')

    await vcxAgent.agentInitVcx()

    await vcxAgent.serviceConnections.inviteeConnectionAcceptFromInvitation(connectionId, invite)
    const connection = await vcxAgent.serviceConnections.getVcxConnection(connectionId)
    expect(await connection.getState()).toBe(ConnectionStateType.Requested)

    await vcxAgent.agentShutdownVcx()
  }

  async function updateConnection (expectedNextState) {
    logger.info(`Alice is going to update connection, expecting new state of ${expectedNextState}`)
    await vcxAgent.agentInitVcx()

    expect(await vcxAgent.serviceConnections.connectionUpdate(connectionId)).toBe(expectedNextState)

    await vcxAgent.agentShutdownVcx()
  }

  async function acceptCredentialOffer () {
    await vcxAgent.agentInitVcx()

    logger.info('Alice accepting creadential offer')
    await vcxAgent.serviceCredHolder.waitForCredentialOfferAndAccept(connectionId, holderCredentialId)

    await vcxAgent.agentShutdownVcx()
  }

  async function sendHolderProof (proofRequest, _mapRevRegId) {
    await vcxAgent.agentInitVcx()
    const mapRevRegId = _mapRevRegId || ((_revRegId) => { throw Error('Tails file should not be needed') })
    await vcxAgent.serviceProver.buildDisclosedProof(disclosedProofId, proofRequest)
    const { selectedCreds } = await vcxAgent.serviceProver.selectCredentials(disclosedProofId, mapRevRegId)
    const selfAttestedAttrs = { attribute_3: 'Smith' }
    await vcxAgent.serviceProver.generateProof(disclosedProofId, selectedCreds, selfAttestedAttrs)
    expect(await vcxAgent.serviceProver.sendDisclosedProof(disclosedProofId, connectionId)).toBe(ProverStateType.PresentationSent)

    await vcxAgent.agentShutdownVcx()
  }

  async function updateStateHolderProofV2 (expectedNextState) {
    logger.info(`Holder updating state of disclosed proof, expecting it to be in state ${expectedNextState}`)
    await vcxAgent.agentInitVcx()

    expect(await vcxAgent.serviceProver.disclosedProofUpdate(disclosedProofId, connectionId)).toBe(expectedNextState)

    await vcxAgent.agentShutdownVcx()
  }

  async function updateStateCredentialV2 (expectedState) {
    logger.info('Holder updating state of credential with connection')
    await vcxAgent.agentInitVcx()

    expect(await vcxAgent.serviceCredHolder.credentialUpdate(holderCredentialId, connectionId)).toBe(expectedState)

    await vcxAgent.agentShutdownVcx()
  }

  async function signData (dataBase64) {
    logger.info('Alice is going to sign data')
    await vcxAgent.agentInitVcx()

    const signatureBase64 = await vcxAgent.serviceConnections.signData(connectionId, dataBase64)

    await vcxAgent.agentShutdownVcx()

    logger.debug(`Alice signed data. Data=${dataBase64} signature=${signatureBase64}`)
    return signatureBase64
  }

  async function sendMessage (message) {
    logger.info('Alice is going to send message')
    await vcxAgent.agentInitVcx()
    await vcxAgent.serviceConnections.sendMessage(connectionId, message)
    await vcxAgent.agentShutdownVcx()
  }

  async function getTailsLocation () {
    logger.info('Alice is going to get tails location')
    await vcxAgent.agentInitVcx()
    const tailsLocation = await vcxAgent.serviceCredHolder.getTailsLocation(holderCredentialId)
    logger.debug(`Alice obtained tails location ${tailsLocation}`)
    await vcxAgent.agentShutdownVcx()
    return tailsLocation
  }

  async function getTailsHash () {
    logger.info('Alice getting tails hash')
    await vcxAgent.agentInitVcx()
    const tailsHash = await vcxAgent.serviceCredHolder.getTailsHash(holderCredentialId)
    logger.debug(`Alice obtained tails hash ${tailsHash}`)
    await vcxAgent.agentShutdownVcx()
    return tailsHash
  }

  async function downloadReceivedMessagesV2 () {
    logger.info('Alice is going to download messages using getMessagesV2')
    await vcxAgent.agentInitVcx()
    const agencyMessages = await vcxAgent.serviceConnections.getMessagesV2(connectionId, ["MS-103"])
    await vcxAgent.agentShutdownVcx()
    return agencyMessages
  }

  async function sendPing() {
    logger.info(`Alice is going to send ping`)
    await vcxAgent.agentInitVcx()
    const res = await vcxAgent.serviceConnections.sendPing(connectionId)
    logger.info(`Operation result = ${JSON.stringify(res)}`)
    await vcxAgent.agentShutdownVcx()
  }

  async function discoverTheirFeatures() {
    logger.info(`Alice is going to request Faber's Aries features.`)
    await vcxAgent.agentInitVcx()
    const res = await vcxAgent.serviceConnections.discoverTheirFeatures(connectionId)
    logger.info(`Operation result = ${JSON.stringify(res)}`)
    await vcxAgent.agentShutdownVcx()
  }

  return {
    sendMessage,
    signData,
    acceptInvite,
    updateConnection,
    acceptCredentialOffer,
    updateStateCredentialV2,
    sendHolderProof,
    updateStateHolderProofV2,
    getTailsLocation,
    getTailsHash,
    downloadReceivedMessagesV2,
    sendPing,
    discoverTheirFeatures
  }
}
