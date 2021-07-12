/* eslint-env jest */
const { buildRevocationDetails } = require('../../src')
const { createVcxAgent, getSampleSchemaData } = require('../../src')
const { ConnectionStateType, IssuerStateType, VerifierStateType } = require('@hyperledger/node-vcx-wrapper')
const { getAliceSchemaAttrs, getFaberCredDefName, getFaberProofData } = require('./data')

module.exports.createFaber = async function createFaber () {
  const agentName = `faber-${Math.floor(new Date() / 1000)}`
  const connectionId = 'connection-faber-to-alice'
  const issuerCredId = 'credential-for-alice'
  let credDefId
  const proofId = 'proof-from-alice'
  const logger = require('../../demo/logger')('Faber')

  const faberAgentConfig = {
    agentName,
    agencyUrl: 'http://localhost:8080',
    seed: '000000000000000000000000Trustee1',
    webhookUrl: `http://localhost:7209/notifications/${agentName}`,
    usePostgresWallet: false,
    logger
  }

  const vcxAgent = await createVcxAgent(faberAgentConfig)

  async function createInvite () {
    logger.info('Faber is going to generate invite')
    await vcxAgent.agentInitVcx()

    const invite = await vcxAgent.serviceConnections.inviterConnectionCreate(connectionId, undefined)
    logger.info(`Faber generated invite:\n${invite}`)
    const connection = await vcxAgent.serviceConnections.getVcxConnection(connectionId)
    expect(await connection.getState()).toBe(ConnectionStateType.Invited)

    await vcxAgent.agentShutdownVcx()

    return invite
  }

  async function sendConnectionResponse () {
    logger.info('Faber is going to generate invite')
    await vcxAgent.agentInitVcx()

    expect(await vcxAgent.serviceConnections.connectionUpdate(connectionId)).toBe(ConnectionStateType.Responded)

    await vcxAgent.agentShutdownVcx()
  }

  async function updateConnection (expectedNextState) {
    logger.info(`Faber is going to update connection, expecting new state of ${expectedNextState}`)
    await vcxAgent.agentInitVcx()

    expect(await vcxAgent.serviceConnections.connectionUpdate(connectionId)).toBe(expectedNextState)

    await vcxAgent.agentShutdownVcx()
  }

  async function sendCredentialOffer (_revocationDetails) {
    await vcxAgent.agentInitVcx()

    logger.info('Faber writing schema on ledger')
    const schemaId = await vcxAgent.serviceLedgerSchema.createSchema(getSampleSchemaData())

    logger.info('Faber writing credential definition on ledger')
    const revocationDetails = _revocationDetails || buildRevocationDetails({ supportRevocation: false })
    await vcxAgent.serviceLedgerCredDef.createCredentialDefinition(
      schemaId,
      getFaberCredDefName(),
      revocationDetails
    )

    logger.info('Faber sending credential to Alice')
    const schemaAttrs = getAliceSchemaAttrs()
    credDefId = getFaberCredDefName()
    await vcxAgent.serviceCredIssuer.sendOffer(issuerCredId, connectionId, credDefId, schemaAttrs)

    await vcxAgent.agentShutdownVcx()
  }

  async function updateStateCredentialV2 (expectedState) {
    await vcxAgent.agentInitVcx()

    logger.info('Issuer updating state of credential with connection')
    expect(await vcxAgent.serviceCredIssuer.credentialUpdate(issuerCredId, connectionId)).toBe(expectedState)

    await vcxAgent.agentShutdownVcx()
  }

  async function sendCredential () {
    await vcxAgent.agentInitVcx()

    logger.info('Issuer sending credential')
    expect(await vcxAgent.serviceCredIssuer.sendCredential(issuerCredId, connectionId)).toBe(IssuerStateType.Finished)
    logger.info('Credential sent')

    await vcxAgent.agentShutdownVcx()
  }

  async function requestProofFromAlice () {
    logger.info('Faber going to request proof from Alice')
    await vcxAgent.agentInitVcx()
    const issuerDid = vcxAgent.getInstitutionDid()
    const proofData = getFaberProofData(issuerDid, proofId)
    logger.info(`Faber is creating proof ${proofId}`)
    await vcxAgent.serviceVerifier.createProof(proofId, proofData)
    logger.info(`Faber is sending proof request to connection ${connectionId}`)
    const { state, proofRequestMessage } = await vcxAgent.serviceVerifier.sendProofRequest(connectionId, proofId)
    expect(state).toBe(VerifierStateType.PresentationRequestSent)
    await vcxAgent.agentShutdownVcx()
    return proofRequestMessage
  }

  async function updateStateVerifierProofV2 (expectedNextState) {
    logger.info(`Verifier updating state of proof, expecting it to be in state ${expectedNextState}`)
    await vcxAgent.agentInitVcx()

    expect(await vcxAgent.serviceVerifier.proofUpdate(proofId, connectionId)).toBe(expectedNextState)

    await vcxAgent.agentShutdownVcx()
  }

  async function verifySignature (dataBase64, signatureBase64) {
    logger.debug(`Faber is going to verift signed data. Data=${dataBase64} signature=${signatureBase64}`)
    await vcxAgent.agentInitVcx()

    const isValid = await vcxAgent.serviceConnections.verifySignature(connectionId, dataBase64, signatureBase64)

    await vcxAgent.agentShutdownVcx()
    return isValid
  }

  async function downloadReceivedMessages () {
    logger.info('Faber is going to download messages using getMessages')
    await vcxAgent.agentInitVcx()
    const agencyMessages = await vcxAgent.serviceConnections.getMessages(connectionId, ["MS-103"])
    await vcxAgent.agentShutdownVcx()
    return agencyMessages
  }

  async function updateMessageStatus (uids) {
    await vcxAgent.agentInitVcx()
    await vcxAgent.serviceConnections.updateMessagesStatus(connectionId, uids)
    await vcxAgent.agentShutdownVcx()
  }

  async function updateAllReceivedMessages () {
    await vcxAgent.agentInitVcx()
    await vcxAgent.serviceConnections.updateAllReceivedMessages(connectionId)
    await vcxAgent.agentShutdownVcx()
  }

  async function downloadReceivedMessagesV2 () {
    logger.info('Faber is going to download messages using getMessagesV2')
    await vcxAgent.agentInitVcx()
    const agencyMessages = await vcxAgent.serviceConnections.getMessagesV2(connectionId, ["MS-103"])
    await vcxAgent.agentShutdownVcx()
    return agencyMessages
  }

  async function getCredentialRevRegId () {
    logger.info(`Faber is going to obtain rev reg id for cred id ${issuerCredId}`)
    await vcxAgent.agentInitVcx()
    const revRegId = await vcxAgent.serviceCredIssuer.getRevRegId(issuerCredId)
    logger.debug(`Faber obtained rev reg id ${revRegId}`)
    await vcxAgent.agentShutdownVcx()
    return revRegId
  }

  async function getTailsFile () {
    logger.info(`Faber is going to obtain tails file for cred id ${issuerCredId}`)
    await vcxAgent.agentInitVcx()
    const tailsFile = await vcxAgent.serviceLedgerCredDef.getTailsFile(issuerCredId)
    await vcxAgent.agentShutdownVcx()
    logger.debug(`Faber obtained tails file ${tailsFile}`)
    return tailsFile
  }

  async function getTailsHash () {
    logger.info(`Faber is going to obtain tails hash for cred def id ${credDefId}`)
    await vcxAgent.agentInitVcx()
    const tailsHash = await vcxAgent.serviceLedgerCredDef.getTailsHash(credDefId)
    logger.info(`Faber obtained tails hash ${tailsHash}`)
    await vcxAgent.agentShutdownVcx()
    return tailsHash
  }

  return {
    downloadReceivedMessages,
    downloadReceivedMessagesV2,
    verifySignature,
    createInvite,
    updateConnection,
    sendConnectionResponse,
    sendCredentialOffer,
    updateStateCredentialV2,
    sendCredential,
    requestProofFromAlice,
    updateStateVerifierProofV2,
    getCredentialRevRegId,
    getTailsFile,
    getTailsHash,
    updateMessageStatus,
    updateAllReceivedMessages
  }
}
