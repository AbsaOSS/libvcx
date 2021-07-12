const { getMessagesForConnection } = require('../utils/messages')
const {
  updateMessages,
  Connection,
  ConnectionStateType
} = require('@hyperledger/node-vcx-wrapper')
const { pollFunction } = require('../common')

module.exports.createServiceConnections = function createServiceConnections ({ logger, saveConnection, loadConnection, listConnectionIds }) {
  async function inviterConnectionCreate (connectionId, cbInvitation) {
    logger.info(`InviterConnectionSM creating connection ${connectionId}`)
    const connection = await Connection.create({ id: connectionId })
    logger.debug(`InviterConnectionSM after created connection:\n${JSON.stringify(await connection.serialize())}`)
    await connection.connect('{}')
    logger.debug(`InviterConnectionSM after invitation was generated:\n${JSON.stringify(await connection.serialize())}`)
    const invite = await connection.inviteDetails()
    if (cbInvitation) {
      cbInvitation(invite)
    }
    await saveConnection(connectionId, connection)
    logger.info(`InviterConnectionSM has established connection ${connectionId}`)
    return invite
  }

  async function inviterConnectionCreateAndAccept (conenctionId, cbInvitation) {
    const invite = await inviterConnectionCreate(conenctionId, cbInvitation)
    const connection = await loadConnection(conenctionId)
    await _progressConnectionToAcceptedState(connection, 20, 2000)

    await saveConnection(conenctionId, connection)
    return invite
  }

  async function inviteeConnectionAcceptFromInvitation (connectionId, invite) {
    logger.info(`InviteeConnectionSM creating connection ${connectionId} from connection invitation.`)
    const connection = await Connection.createWithInvite({ id: connectionId, invite })
    logger.debug(`InviteeConnectionSM after created from invitation:\n${JSON.stringify(await connection.serialize())}`)
    await connection.connect({ data: '{}' })
    logger.debug('InviteeConnectionSM created connection agent')
    await saveConnection(connectionId, connection)
  }

  async function inviteeConnectionAcceptFromInvitationAndProgress (connectionId, invite) {
    await inviteeConnectionAcceptFromInvitation(connectionId, invite)
    const connection = await loadConnection(connectionId)
    await _progressConnectionToAcceptedState(connection, 20, 2000)
    logger.info(`InviteeConnectionSM has established connection ${connectionId}`)
    await saveConnection(connectionId, connection)
  }

  async function _progressConnectionToAcceptedState (connection, attemptsThreshold, timeoutMs) {
    async function progressToAcceptedState () {
      if (await connection.updateState() !== ConnectionStateType.Finished) {
        return { result: undefined, isFinished: false }
      } else {
        return { result: null, isFinished: true }
      }
    }

    const [error] = await pollFunction(progressToAcceptedState, 'Progress connection', logger, attemptsThreshold, timeoutMs)
    if (error) {
      throw Error(`Couldn't progress connection to Accepted state. ${error}`)
    }
  }

  async function connectionUpdate (connectionId) {
    const connection = await loadConnection(connectionId)
    const state = await connection.updateState()
    await saveConnection(connectionId, connection)
    return state
  }

  async function connectionAutoupdate (connectionId, updateAttemptsThreshold = 10, timeoutMs = 2000) {
    const connection = await loadConnection(connectionId)
    await _progressConnectionToAcceptedState(connection, updateAttemptsThreshold, timeoutMs)
    logger.info('Success! Connection was progressed to Accepted state.')
    await saveConnection(connectionId, connection)
  }

  async function signData (connectionId, dataBase64) {
    const connection = await loadConnection(connectionId)
    var challengeBuffer = Buffer.from(dataBase64, 'base64')
    let signatureBuffer
    try {
      signatureBuffer = await connection.signData(challengeBuffer)
    } catch (err) {
      throw Error(`Error occurred while connection was signing data '${dataBase64}'. Err Message = ${err.message} Stack = ${err.stack}`)
    }
    if (!signatureBuffer) {
      throw Error(`Error occurred while connection was signing data '${dataBase64}' The resulting signature was empty.`)
    }
    return signatureBuffer.toString('base64')
  }

  async function verifySignature (connectionId, dataBase64, signatureBase64) {
    const connection = await loadConnection(connectionId)
    const data = Buffer.from(dataBase64, 'base64')
    const signature = Buffer.from(signatureBase64, 'base64')
    return connection.verifySignature({ data, signature })
  }

  async function getConnectionPwDid (connectionId) {
    const connection = await loadConnection(connectionId)
    const serConnection = await connection.serialize()
    return serConnection.data.pw_did
  }

  async function sendMessage (connectionId, payload) {
    const connection = await loadConnection(connectionId)
    await connection.sendMessage({ msg: payload, msg_title: 'msg_title', msg_type: 'msg_type', ref_msg_id: 'ref_msg_id' })
  }

  async function getMessages (connectionId, filterStatuses = [], filterUids = []) {
    const connection = await loadConnection(connectionId)
    return getMessagesForConnection([connection], filterStatuses, filterUids)
  }

  async function getState (connectionId) {
    const connection = await loadConnection(connectionId)
    return await connection.getState()
  }

  async function listIds () {
    return listConnectionIds()
  }

  async function printInfo (connectionIds) {
    for (const id of connectionIds) {
      const state = await getState(id)
      logger.info(`Connection ${id} state=${state}`)
    }
  }

  async function getVcxConnection (connectionId) {
    logger.warn('Usage of getVcxConnection is not recommended. You should use vcxagent-core API rather than work with vcx object directly.')
    return loadConnection(connectionId)
  }

  async function getMessagesV2 (connectionId, filterStatuses = [], filterUids = []) {
    const connection = await getVcxConnection(connectionId)
    return getMessagesForConnection([connection], filterStatuses, filterUids)
  }

  async function updateMessagesStatus (connectionId, uids) {
    const pwDid = await getConnectionPwDid(connectionId)
    const updateInstructions = [{ pairwiseDID: pwDid, uids }]
    await updateMessages({ msgJson: JSON.stringify(updateInstructions) })
  }

  async function updateAllReceivedMessages(connectionId) {
    const receivedMessages = await getMessagesV2(connectionId, ["MS-103"], [])
    await updateMessagesStatus(connectionId, receivedMessages.map(m => m.uid))
  }

  async function sendPing(connectionId) {
    const connection = await getVcxConnection(connectionId)
    await connection.sendPing()
  }

  async function discoverTheirFeatures(connectionId) {
    const connection = await getVcxConnection(connectionId)
    await connection.sendDiscoveryFeatures()
  }


  return {
    // inviter
    inviterConnectionCreate,
    inviterConnectionCreateAndAccept,

    // invitee
    inviteeConnectionAcceptFromInvitation,
    inviteeConnectionAcceptFromInvitationAndProgress,

    // universal
    connectionAutoupdate,
    connectionUpdate,
    getConnectionPwDid,

    signData,
    verifySignature,
    sendMessage,
    getMessages,

    getMessagesV2,
    updateMessagesStatus,
    updateAllReceivedMessages,

    sendPing,
    discoverTheirFeatures,

    getState,
    listIds,
    printInfo,
    getVcxConnection
  }
}
