/* eslint-env jest */
require('jest')
const { createPairedAliceAndFaber } = require('./utils/utils')
const { initRustapi } = require('../src/index')
const sleep = require('sleep-promise')

beforeAll(async () => {
  jest.setTimeout(1000 * 60 * 4)
  await initRustapi(process.env.VCX_LOG_LEVEL || 'vcx=error')
})

describe('send ping, get ping', () => {
  it('Faber should send credential to Alice', async () => {
    try {
      const { alice, faber } = await createPairedAliceAndFaber()
      await alice.discoverTheirFeatures()

      const faberMessages1 = await faber.downloadReceivedMessagesV2()
      expect(faberMessages1.length).toBe(1)
      expect(JSON.parse(faberMessages1[0].decryptedMsg)["@type"].match(/discover-features\/1.0\/query/))
      await faber.updateConnection(4) //
      const faberMessages2 = await faber.downloadReceivedMessagesV2()
      expect(faberMessages2.length).toBe(0)

      const aliceMessages1 = await alice.downloadReceivedMessagesV2()
      expect(aliceMessages1.length).toBe(1)
      expect(JSON.parse(aliceMessages1[0].decryptedMsg)["@type"].match(/discover-features\/1.0\/disclose/))
      const disclosedProtocols = JSON.parse(aliceMessages1[0].decryptedMsg)["protocols"].map(r => r.pid)
      expect(disclosedProtocols).toContain("did:sov:BzCbsNYhMrjHiqZDTUASHg;spec/connections/1.0")
      expect(disclosedProtocols).toContain("did:sov:BzCbsNYhMrjHiqZDTUASHg;spec/issue-credential/1.0")
      expect(disclosedProtocols).toContain("did:sov:BzCbsNYhMrjHiqZDTUASHg;spec/report-problem/1.0")
      expect(disclosedProtocols).toContain("did:sov:BzCbsNYhMrjHiqZDTUASHg;spec/present-proof/1.0")
      expect(disclosedProtocols).toContain("did:sov:BzCbsNYhMrjHiqZDTUASHg;spec/trust_ping/1.0")
      expect(disclosedProtocols).toContain("did:sov:BzCbsNYhMrjHiqZDTUASHg;spec/discover-features/1.0")
      expect(disclosedProtocols).toContain( "did:sov:BzCbsNYhMrjHiqZDTUASHg;spec/basicmessage/1.0")

      await alice.updateConnection(4)
      const aliceMessages2 = await alice.downloadReceivedMessagesV2()
      expect(aliceMessages2.length).toBe(0)
    } catch (err) {
      console.error(`err = ${err.message} stack = ${err.stack}`)
      await sleep(2000)
      throw Error(err)
    }
  })
})
