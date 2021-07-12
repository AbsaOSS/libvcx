/* eslint-env jest */
require('jest')
const express = require('express')
const axios = require('axios')
const { buildRevocationDetails } = require('../src')
const { createPairedAliceAndFaber } = require('./utils/utils')
const { initRustapi } = require('../src/index')
const { IssuerStateType, HolderStateType, VerifierStateType, ProverStateType } = require('@hyperledger/node-vcx-wrapper')
const uuid = require('uuid')
const sleep = require('sleep-promise')
const fs = require('fs')
const mkdirp = require('mkdirp')

beforeAll(async () => {
  jest.setTimeout(1000 * 60 * 4)
  await initRustapi(process.env.VCX_LOG_LEVEL || 'vcx=error')
})

describe('test tails distribution', () => {
  it('Faber uploads tails and Alice downloads using tails location info from ledger', async () => {
    let server
    try {
      const { alice, faber } = await createPairedAliceAndFaber()

      const port = 5468
      const tailsUrlId = uuid.v4()
      const tailsUrl = `http://127.0.0.1:${port}/${tailsUrlId}`
      await faber.sendCredentialOffer(buildRevocationDetails({ supportRevocation: true, tailsFile: `${__dirname}/tmp/faber/tails`, tailsUrl, maxCreds: 5 }))
      await alice.acceptCredentialOffer()
      await faber.updateStateCredentialV2(IssuerStateType.RequestReceived)
      await faber.sendCredential()
      await alice.updateStateCredentialV2(HolderStateType.Finished)

      const faberTailsHash = await faber.getTailsHash()
      const app = express()
      app.use(`/${tailsUrlId}`, express.static(`${__dirname}/tmp/faber/tails/${faberTailsHash}`))
      server = app.listen(port)

      const aliceTailsLocation = await alice.getTailsLocation()
      const aliceTailsHash = await alice.getTailsHash()
      const aliceTailsFileDir = `${__dirname}/tmp/alice/tails`
      const aliceTailsFilePath = aliceTailsFileDir + `/${aliceTailsHash}`
      await mkdirp(aliceTailsFileDir)
      axios.default.get(`${aliceTailsLocation}`, { responseType: 'stream' }).then(res => {
        res.data.pipe(fs.createWriteStream(aliceTailsFilePath))
      })

      const request = await faber.requestProofFromAlice()
      await alice.sendHolderProof(JSON.parse(request), revRegId => aliceTailsFileDir)
      await faber.updateStateVerifierProofV2(VerifierStateType.Finished)
      await alice.updateStateHolderProofV2(ProverStateType.Finished)
    } catch (err) {
      console.error(`err = ${err.message} stack = ${err.stack}`)
      if (server) {
        await server.close()
      }
      await sleep(2000)
      throw Error(err)
    }
  })
})
