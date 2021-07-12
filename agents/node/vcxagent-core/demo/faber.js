const { VerifierStateType, ProofState, Proof } = require('@hyperledger/node-vcx-wrapper')
const sleepPromise = require('sleep-promise')
const { runScript } = require('./script-common')
const { testTailsUrl } = require('../src/common')
const logger = require('./logger')('Faber')
const assert = require('assert')
const uuid = require('uuid')
const express = require('express')
const bodyParser = require('body-parser')
const { getFaberProofDataWithNonRevocation } = require('../test/utils/data')
const { createVcxAgent, initRustapi, getSampleSchemaData, buildRevocationDetails } = require('../src/index')
const { getAliceSchemaAttrs, getFaberCredDefName } = require('../test/utils/data')
require('@hyperledger/node-vcx-wrapper')

const tailsFile = '/tmp/tails'

async function runFaber (options) {
  logger.info(`Starting. Revocation enabled=${options.revocation}`)
  await initRustapi(process.env.VCX_LOG_LEVEL || 'vcx=error,agency_client=error')
  let faberServer
  let exitcode = 0
  let vcxAgent
  const credDefId = getFaberCredDefName()
  const proofId = 'proof-from-alice'
  const connectionId = 'faber-to-alice'
  const issuerCredId = 'cred-for-alice'
  try {
    const agentName = `faber-${uuid.v4()}`
    vcxAgent = await createVcxAgent({
      agentName,
      agencyUrl: 'http://localhost:8080',
      seed: '000000000000000000000000Trustee1',
      usePostgresWallet: false,
      logger
    })
    await vcxAgent.agentInitVcx()
    await vcxAgent.updateWebhookUrl(`http://localhost:7209/notifications/${agentName}`)

    if (process.env.ACCEPT_TAA) {
      await vcxAgent.acceptTaa()
    }

    const schemaId = await vcxAgent.serviceLedgerSchema.createSchema(getSampleSchemaData())
    await vcxAgent.serviceLedgerCredDef.createCredentialDefinition(schemaId, getFaberCredDefName(), buildRevocationDetails({ supportRevocation: true, tailsFile, tailsUrl: testTailsUrl, maxCreds: 5 }))

    await vcxAgent.serviceConnections.inviterConnectionCreateAndAccept(connectionId, (invitationString) => {
      logger.info('\n\n**invite details**')
      logger.info("**You'll ge queried to paste this data to alice side of the demo. This is invitation to connect.**")
      logger.info("**It's assumed this is obtained by Alice from Faber by some existing secure channel.**")
      logger.info('**Could be on website via HTTPS, QR code scanned at Faber institution, ...**')
      logger.info('\n******************\n\n')
      logger.info(invitationString)
      logger.info('\n\n******************\n\n')

      if (options['expose-invitation-port']) {
        const port = options['expose-invitation-port']
        try {
          const appCallbacks = express()
          appCallbacks.use(bodyParser.json())
          appCallbacks.get('/',
            async function (req, res) {
              res.status(200).send({ invitationString })
            }
          )
          faberServer = appCallbacks.listen(port)
          logger.info(`The invitation is also available on port ${port}`)
        } catch (e) {
          logger.error(`Error trying to expose connection invitation on port ${port}`)
        }
      }
    })

    logger.info('Faber is going to send credential offer')
    const schemaAttrs = getAliceSchemaAttrs()
    await vcxAgent.serviceCredIssuer.sendOfferAndCredential(issuerCredId, connectionId, credDefId, schemaAttrs)
    if (options.revocation) {
      await vcxAgent.serviceCredIssuer.revokeCredential(issuerCredId)
    }

    logger.info('#19 Create a Proof object')
    const vcxProof = await Proof.create(getFaberProofDataWithNonRevocation(vcxAgent.getInstitutionDid(), proofId))

    const connectionToAlice = await vcxAgent.serviceConnections.getVcxConnection(connectionId)
    logger.info('#20 Request proof of degree from alice')
    await vcxProof.requestProof(connectionToAlice)

    logger.info('#21 Poll agency and wait for alice to provide proof')
    let proofProtocolState = await vcxProof.updateStateV2(connectionToAlice)
    logger.debug(`vcxProof = ${JSON.stringify(vcxProof)}`)
    logger.debug(`proofState = ${proofProtocolState}`)
    while (![VerifierStateType.Finished, VerifierStateType.Failed].includes(proofProtocolState)) {
      await sleepPromise(2000)
      proofProtocolState = await vcxProof.updateStateV2(connectionToAlice)
      logger.info(`proofState=${proofProtocolState}`)
      if (proofProtocolState === VerifierStateType.Failed) {
        logger.error(`Faber proof protocol state is ${3} which an error has ocurred.`)
        logger.error(`Serialized proof state = ${JSON.stringify(await vcxProof.serialize())}`)
        process.exit(-1)
      }
    }

    logger.info('#27 Process the proof provided by alice.')
    const { proofState, proof } = await vcxProof.getProof()
    assert(proofState)
    assert(proof)
    logger.info(`Proof protocol state = ${JSON.stringify(proofProtocolState)}`)
    logger.info(`Proof verification state =${proofState}`)
    logger.debug(`Proof presentation = ${JSON.stringify(proof, null, 2)}`)
    logger.debug(`Serialized Proof state machine ${JSON.stringify(await vcxProof.serialize())}`)

    if (proofState === ProofState.Verified) {
      if (options.revocation) {
        throw Error('Proof was verified, but was expected to be invalid, because revocation was enabled.')
      } else {
        logger.info('Proof was verified.')
      }
    } else if (proofState === ProofState.Invalid) {
      if (options.revocation) {
        logger.info('Proof was determined as invalid, which was expected because the used credential was revoked.')
      } else {
        throw Error('Proof was invalid, but was expected to be verified. Revocation was not enabled.')
      }
      await sleepPromise(1000)
    } else {
      logger.error(`Unexpected proof state '${proofState}'.`)
      process.exit(-1)
    }

    const msgs = await vcxAgent.serviceConnections.getMessagesV2(connectionId)
    logger.debug(`Faber received messages: ${JSON.stringify(msgs, null, 2)}`)
    assert(msgs.length === 3)
  } catch (err) {
    exitcode = -1
    logger.error(`Faber encountered error ${err.message} ${err.stack}`)
  } finally {
    if (faberServer) {
      await faberServer.close()
    }
    logger.info(`Exiting process with code ${exitcode}`)
    await vcxAgent.agentShutdownVcx()
    process.exit(exitcode)
  }
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
    name: 'revocation',
    type: Boolean,
    description: 'If specified, the issued credential will be revoked',
    defaultValue: false
  },
  {
    name: 'expose-invitation-port',
    type: Number,
    description: 'If specified, invitation will be exposed on this port via HTTP'
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
runScript(optionDefinitions, usage, areOptionsValid, runFaber)
