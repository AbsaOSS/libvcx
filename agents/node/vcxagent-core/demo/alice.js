const readlineSync = require('readline-sync')
const sleepPromise = require('sleep-promise')
const { initRustapi } = require('../src/index')
const { createVcxAgent } = require('../src/index')
const { testTailsUrl } = require('../src/common')
const logger = require('./logger')('Alice')
const { runScript } = require('./script-common')
const uuid = require('uuid')
const axios = require('axios')
const isPortReachable = require('is-port-reachable')
const url = require('url')
const { extractProofRequestAttachement } = require('../src/utils/proofs')
const assert = require('assert')

const mapRevRegIdToTailsFile = (_revRegId) => '/tmp/tails'

async function getInvitationString (fetchInviteUrl) {
  let invitationString
  if (fetchInviteUrl) {
    const fetchInviteAttemptThreshold = 30
    const fetchInviteTimeout = 1000
    let fetchInviteAttemps = 0
    while (!invitationString) {
      if (await isPortReachable(url.parse(fetchInviteUrl).port, { host: url.parse(fetchInviteUrl).hostname })) { // eslint-disable-line
        ({ data: { invitationString } } = await axios.get(fetchInviteUrl))
        logger.info(`Invitation ${invitationString} was loaded from ${fetchInviteUrl}.`)
      } else {
        logger.info(`Invitation fetch url ${fetchInviteUrl} not yet available. ${fetchInviteAttemps}/${fetchInviteAttemptThreshold}`)
        await sleepPromise(fetchInviteTimeout)
      }
      fetchInviteAttemps++
      if (fetchInviteAttemps > fetchInviteAttemptThreshold) {
        throw Error(`Could not reach ${fetchInviteUrl} to fetch connection invitation.`)
      }
    }
  } else {
    invitationString = readlineSync.question('Enter connection invitation:\n')
  }
  return invitationString
}

async function runAlice (options) {
  logger.info('Starting.')

  await initRustapi(process.env.VCX_LOG_LEVEL || 'vcx=error,agency_client=error')
  const agentName = `alice-${uuid.v4()}`
  const connectionId = 'alice-to-faber'
  const holderCredentialId = 'alice-credential'
  const disclosedProofId = 'alice-proof'
  const vcxAgent = await createVcxAgent({
    agentName,
    agencyUrl: 'http://localhost:8080',
    seed: '000000000000000000000000Trustee1',
    usePostgresWallet: false,
    logger
  })
  await vcxAgent.agentInitVcx()
  await vcxAgent.updateWebhookUrl(`http://localhost:7209/notifications/${agentName}`)

  const invitationString = await getInvitationString(options['autofetch-invitation-url'])
  await vcxAgent.serviceConnections.inviteeConnectionAcceptFromInvitationAndProgress(connectionId, invitationString)
  logger.info('Connection to alice was Accepted!')

  await vcxAgent.serviceCredHolder.waitForCredentialOfferAndAcceptAndProgress(connectionId, holderCredentialId)
  const revRegId = await vcxAgent.serviceCredHolder.getRevRegId(holderCredentialId)
  await _validateTestTailsLocation(holderCredentialId, revRegId, vcxAgent)

  const proofRequests = await vcxAgent.serviceProver.waitForProofRequests(connectionId)
  if (proofRequests.length === 0) {
    throw Error('No proof request found.')
  }
  const proofRequest = proofRequests[0]

  await vcxAgent.serviceProver.buildDisclosedProof(disclosedProofId, proofRequest)
  const requestInfo = extractProofRequestAttachement(proofRequest)
  logger.debug(`Proof request presentation attachment ${JSON.stringify(requestInfo, null, 2)}`)

  const { selectedCreds } = await vcxAgent.serviceProver.selectCredentials(disclosedProofId, mapRevRegIdToTailsFile)
  const selfAttestedAttrs = { attribute_3: 'Smith' }
  await vcxAgent.serviceProver.generateProof(disclosedProofId, selectedCreds, selfAttestedAttrs)
  await vcxAgent.serviceProver.sendDisclosedProofAndProgress(disclosedProofId, connectionId)
  logger.info('Faber received the proof')

  const msgs = await vcxAgent.serviceConnections.getMessages(connectionId)
  _validateMsgs(msgs)

  const msgs2 = await vcxAgent.serviceConnections.getMessagesV2(connectionId)
  _validateMsgs(msgs2)

  await vcxAgent.agentShutdownVcx()
  process.exit(0)
}

function _validateMsgs (msgs) {
  logger.debug(`Validating messages:\n${JSON.stringify(msgs, null, 2)}`)
  assert(msgs.length === 4)
  assert(msgs[0].uid)
  assert(msgs[0].statusCode)
  assert(msgs[0].decryptedMsg)
  const payload = JSON.parse(msgs[0].decryptedMsg)
  assert(payload['@id'])
  assert(payload['@type'])
}

async function _validateTestTailsLocation (holderCredentialId, revRegId, vcxAgent) {
  logger.debug(`Going to check that holder's tails location is ${testTailsUrl}`)
  const tailsLocation = await vcxAgent.serviceCredHolder.getTailsLocation(holderCredentialId)
  assert(tailsLocation === testTailsUrl)
}

const optionDefinitions = [
  {
    name: 'help',
    alias: 'h',
    type: Boolean,
    description: 'Display this usage guide.'
  },
  {
    name: 'postgresql',
    type: Boolean,
    description: 'If specified, postresql wallet will be used.',
    defaultValue: false
  },
  {
    name: 'autofetch-invitation-url',
    type: String,
    description: 'If specified, the script will try to download invitation from specified url.'
  }
]

const usage = [
  {
    header: 'Options',
    optionList: optionDefinitions
  },
  {
    content: 'Project home: {underline https://github.com/AbsaOSS/libvcx}'
  }
]

function areOptionsValid (_options) {
  return true
}

runScript(optionDefinitions, usage, areOptionsValid, runAlice)
