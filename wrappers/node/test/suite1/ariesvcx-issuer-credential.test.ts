import '../module-resolver-helper';

import { assert } from 'chai';
import {
  createConnectionInviterRequested,
  dataIssuerCredentialCreate,
  issuerCredentialCreate,
} from 'helpers/entities';
import { initVcxTestMode, shouldThrow } from 'helpers/utils';
import { Connection, IssuerCredential, IssuerStateType, VCXCode } from 'src';

describe('IssuerCredential:', () => {
  before(() => initVcxTestMode());

  describe('create:', () => {
    it('success', async () => {
      await issuerCredentialCreate();
    });

    it('throws: missing sourceId', async () => {
      const { sourceId, ...data } = await dataIssuerCredentialCreate();
      const error = await shouldThrow(() => IssuerCredential.create(data as any));
      assert.equal(error.vcxCode, VCXCode.INVALID_OPTION);
    });

    it('throws: invalid credDefHandle', async () => {
      const { credDefHandle, ...data } = await dataIssuerCredentialCreate();
      const error = await shouldThrow(() => IssuerCredential.create(data as any));
      assert.equal(error.vcxCode, VCXCode.INVALID_CREDENTIAL_DEF_HANDLE);
    });

    it('throws: missing credDefId', async () => {
      const { credDefHandle, ...data } = await dataIssuerCredentialCreate();
      const error = await shouldThrow(() => IssuerCredential.create(data as any));
      assert.equal(error.vcxCode, VCXCode.INVALID_CREDENTIAL_DEF_HANDLE);
    });

    it('throws: missing attr', async () => {
      const { attr, ...data } = await dataIssuerCredentialCreate();
      const error = await shouldThrow(() => IssuerCredential.create(data as any));
      assert.equal(error.vcxCode, VCXCode.INVALID_OPTION);
    });

    it('throws: missing credentialName', async () => {
      const { credentialName, ...data } = await dataIssuerCredentialCreate();
      const error = await shouldThrow(() => IssuerCredential.create(data as any));
      assert.equal(error.vcxCode, VCXCode.INVALID_OPTION);
    });

    it('throws: missing price', async () => {
      const { price, ...data } = await dataIssuerCredentialCreate();
      const error = await shouldThrow(() => IssuerCredential.create(data as any));
      assert.equal(error.vcxCode, VCXCode.INVALID_OPTION);
    });

    it('throws: invalid attr', async () => {
      const { attr, ...data } = await dataIssuerCredentialCreate();
      const error = await shouldThrow(() =>
        IssuerCredential.create({ attr: null as any, ...data }),
      );
      assert.equal(error.vcxCode, VCXCode.INVALID_OPTION);
    });
  });

  describe('serialize:', () => {
    it('success', async () => {
      const issuerCredential = await issuerCredentialCreate();
      const serialized = await issuerCredential.serialize();
      assert.ok(serialized);
      assert.property(serialized, 'version');
      assert.property(serialized, 'data');
      const { data, version } = serialized;
      assert.ok(data);
      assert.ok(version);
    });

    it('throws: not initialized', async () => {
      const issuerCredential = new IssuerCredential(null as any, {} as any);
      const error = await shouldThrow(() => issuerCredential.serialize());
      assert.equal(error.vcxCode, VCXCode.INVALID_ISSUER_CREDENTIAL_HANDLE);
    });
  });

  describe('deserialize:', () => {
    it('success', async () => {
      const issuerCredential1 = await issuerCredentialCreate();
      const data1 = await issuerCredential1.serialize();
      const issuerCredential2 = await IssuerCredential.deserialize(data1);
      const data2 = await issuerCredential2.serialize();
      assert.deepEqual(data1, data2);
    });

    it('throws: incorrect data', async () => {
      const error = await shouldThrow(async () =>
        IssuerCredential.deserialize({ source_id: 'Invalid' } as any),
      );
      assert.equal(error.vcxCode, VCXCode.UNKNOWN_ERROR);
    });

    it('throws: incomplete data', async () => {
      const error = await shouldThrow(async () =>
        IssuerCredential.deserialize({
          version: '2.0',
          data: {
            issuer_sm: {
              state: {
                SomeUnknown: {},
              },
              source_id: 'alice_degree',
            },
          },
        } as any),
      );
      assert.equal(error.vcxCode, VCXCode.INVALID_JSON);
    });
  });

  describe('updateState:', () => {
    it(`returns state offer sent`, async () => {
      const issuerCredential = await issuerCredentialCreate();
      const connection = await createConnectionInviterRequested();
      await issuerCredential.sendOffer(connection);
      assert.equal(await issuerCredential.getState(), IssuerStateType.OfferSent);
    });
  });

  describe('sendOffer:', () => {
    it('success', async () => {
      const connection = await createConnectionInviterRequested();
      const issuerCredential = await issuerCredentialCreate();
      await issuerCredential.sendOffer(connection);
      assert.equal(await issuerCredential.getState(), IssuerStateType.OfferSent);
    });

    it('throws: not initialized', async () => {
      const connection = await createConnectionInviterRequested();
      const issuerCredential = new IssuerCredential(null as any, {} as any);
      const error = await shouldThrow(() => issuerCredential.sendOffer(connection));
      assert.equal(error.vcxCode, VCXCode.INVALID_ISSUER_CREDENTIAL_HANDLE);
    });

    it('throws: connection not initialized', async () => {
      const connection = new (Connection as any)();
      const issuerCredential = await issuerCredentialCreate();
      const error = await shouldThrow(() => issuerCredential.sendOffer(connection));
      assert.equal(error.vcxCode, VCXCode.INVALID_CONNECTION_HANDLE);
    });

    // "vcx_issuer_get_credential_offer_msg" not implemented for Aries
    it.skip('can generate the offer message', async () => {
      await createConnectionInviterRequested();
      const issuerCredential = await issuerCredentialCreate();
      const message = await issuerCredential.getCredentialOfferMsg();
      assert(message.length > 0);
    });
  });

  describe('sendCredential:', () => {
    it('throws: not initialized', async () => {
      const connection = await createConnectionInviterRequested();
      const issuerCredential = new IssuerCredential(null as any, {} as any);
      const error = await shouldThrow(() => issuerCredential.sendCredential(connection));
      assert.equal(error.vcxCode, VCXCode.INVALID_ISSUER_CREDENTIAL_HANDLE);
    });

    // todo: recorder this test/behaviour in 4.0, issuerCredential is not throwing, only prints warning
    it.skip('throws: no offer', async () => {
      const connection = await createConnectionInviterRequested();
      const issuerCredential = await issuerCredentialCreate();
      const error = await shouldThrow(() => issuerCredential.sendCredential(connection));
      assert.equal(error.vcxCode, VCXCode.NOT_READY);
    });

    // todo: recorder this test/behaviour in 4.0, issuerCredential is not throwing, only prints warning
    it.skip('throws: no request', async () => {
      const connection = await createConnectionInviterRequested();
      const issuerCredential = await issuerCredentialCreate();
      await issuerCredential.sendOffer(connection);
      const error = await shouldThrow(() => issuerCredential.sendCredential(connection));
      assert.equal(error.vcxCode, VCXCode.NOT_READY);
    });
  });

  // describe('revoke:', () => {
  //   it('throws: invalid revocation details', async () => {
  //     const issuerCredential = await issuerCredentialCreate()
  //     const error = await shouldThrow(() => issuerCredential.revokeCredential())
  //     assert.equal(error.vcxCode, VCXCode.INVALID_REVOCATION_DETAILS)
  //   })
  //
  //   it('success', async () => {
  //     const issuerCredential1 = await issuerCredentialCreate()
  //     const data = await issuerCredential1.serialize()
  //     data.data.cred_rev_id = '123'
  //     data.data.rev_reg_id = '456'
  //     data.data.tails_file = 'file'
  //     const issuerCredential2 = await IssuerCredential.deserialize(data)
  //     await issuerCredential2.revokeCredential()
  //   })
  // })
});
