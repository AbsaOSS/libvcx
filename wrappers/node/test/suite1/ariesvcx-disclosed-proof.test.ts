import '../module-resolver-helper';

import { assert } from 'chai';
import {
  connectionCreateInviterNull,
  createConnectionInviterRequested,
  dataDisclosedProofCreateWithMsgId,
  dataDisclosedProofCreateWithRequest,
  disclosedProofCreateWithMsgId,
  disclosedProofCreateWithRequest,
} from 'helpers/entities'
import { initVcxTestMode, shouldThrow } from 'helpers/utils';
import { mapValues } from 'lodash';
import { DisclosedProof, ProverStateType, VCXCode } from 'src';

describe('DisclosedProof', () => {
  before(() => initVcxTestMode());

  describe('create:', () => {
    it('success1', async () => {
      await disclosedProofCreateWithRequest();
    });

    it('throws: missing sourceId', async () => {
      const { connection, request } = await dataDisclosedProofCreateWithRequest();
      const error = await shouldThrow(() => DisclosedProof.create({ connection, request } as any));
      assert.equal(error.vcxCode, VCXCode.INVALID_OPTION);
    });

    it('throws: missing request', async () => {
      const { connection, sourceId } = await dataDisclosedProofCreateWithRequest();
      const error = await shouldThrow(() => DisclosedProof.create({ connection, sourceId } as any));
      assert.equal(error.vcxCode, VCXCode.INVALID_OPTION);
    });

    // Enable when we start utilizing connection prop
    it.skip('throws: missing connection', async () => {
      const { request, sourceId } = await dataDisclosedProofCreateWithRequest();
      const error = await shouldThrow(() => DisclosedProof.create({ request, sourceId } as any));
      assert.equal(error.vcxCode, VCXCode.INVALID_OPTION);
    });

    it('throws: invalid request', async () => {
      const { connection, sourceId } = await dataDisclosedProofCreateWithRequest();
      const error = await shouldThrow(() =>
        DisclosedProof.create({ connection, request: 'invalid', sourceId }),
      );
      assert.equal(error.vcxCode, VCXCode.INVALID_JSON);
    });
  });

  describe('createWithMsgId:', () => {
    // todo: migrate to aries
    it.skip('success', async () => {
      await disclosedProofCreateWithMsgId();
    });

    it('throws: missing sourceId', async () => {
      const { connection, msgId } = await dataDisclosedProofCreateWithMsgId();
      const error = await shouldThrow(() =>
        DisclosedProof.createWithMsgId({ connection, msgId } as any),
      );
      assert.equal(error.vcxCode, VCXCode.INVALID_OPTION);
    });

    it('throws: missing request', async () => {
      const { connection, sourceId } = await dataDisclosedProofCreateWithMsgId();
      const error = await shouldThrow(() =>
        DisclosedProof.createWithMsgId({ connection, sourceId } as any),
      );
      assert.equal(error.vcxCode, VCXCode.INVALID_OPTION);
    });

    it('throws: missing connection', async () => {
      const { connection, ...data } = await dataDisclosedProofCreateWithMsgId();
      const error = await shouldThrow(() => DisclosedProof.createWithMsgId({ data } as any));
      assert.equal(error.vcxCode, VCXCode.UNKNOWN_ERROR);
    });

    it('throws: missing connection handle', async () => {
      const { connection, ...data } = await dataDisclosedProofCreateWithMsgId();
      const error = await shouldThrow(() =>
        DisclosedProof.createWithMsgId({ connection: {} as any, ...data }),
      );
      assert.equal(error.vcxCode, VCXCode.INVALID_CONNECTION_HANDLE);
    });
  });

  describe('serialize:', () => {
    it('success', async () => {
      const disclosedProof = await disclosedProofCreateWithRequest();
      const serialized = await disclosedProof.serialize();
      assert.ok(serialized);
      assert.property(serialized, 'version');
      assert.property(serialized, 'data');
    });

    it('throws: not initialized', async () => {
      const disclosedProof = new (DisclosedProof as any)();
      const error = await shouldThrow(() => disclosedProof.serialize());
      assert.equal(error.vcxCode, VCXCode.INVALID_DISCLOSED_PROOF_HANDLE);
    });
  });

  describe('deserialize:', () => {
    it('success', async () => {
      const disclosedProof1 = await disclosedProofCreateWithRequest();
      const data1 = await disclosedProof1.serialize();
      const disclosedProof2 = await DisclosedProof.deserialize(data1);
      const data2 = await disclosedProof2.serialize();
      assert.deepEqual(data1, data2);
    });

    it('throws: incorrect data', async () => {
      const error = await shouldThrow(async () =>
        DisclosedProof.deserialize({ data: { source_id: 'Invalid' } } as any),
      );
      assert.equal(error.vcxCode, VCXCode.INVALID_JSON);
    });
  });

  describe('updateState:', () => {
    it('Throws error when not initialized', async () => {
      let caught_error;
      const disclosedProof = new (DisclosedProof as any)();
      const connection = await createConnectionInviterRequested();
      try {
        await disclosedProof.updateStateV2(connection);
      } catch (err) {
        caught_error = err;
      }
      assert.isNotNull(caught_error);
    });

    it(`returns ${ProverStateType.Initial}: created`, async () => {
      const disclosedProof = await disclosedProofCreateWithRequest();
      const connection = await createConnectionInviterRequested();
      await disclosedProof.updateStateV2(connection);
      assert.equal(await disclosedProof.getState(), ProverStateType.Initial);
    });
  });

  describe('sendProof:', () => {
    it.skip('success', async () => {
      const data = await dataDisclosedProofCreateWithRequest();
      const disclosedProof = await disclosedProofCreateWithRequest(data);
      await disclosedProof.sendProof(data.connection);
      assert.equal(await disclosedProof.getState(), ProverStateType.PresentationSent);
    });
  });

  describe('getRequests:', async () => {
    it.skip('success', async () => {
      const connection = await createConnectionInviterRequested();
      const requests = await DisclosedProof.getRequests(connection);
      assert.ok(requests);
      assert.ok(requests.length);
      const request = requests[0];
      const disclosedProof = await disclosedProofCreateWithRequest({
        connection,
        request: JSON.stringify(request),
        sourceId: 'disclosedProofTestSourceId',
      });
      await disclosedProof.updateStateV2(connection);
      assert.equal(await disclosedProof.getState(), ProverStateType.Finished);
    });
  });

  describe('generateProof:', async () => {
    it.skip('success', async () => {
      const data = await dataDisclosedProofCreateWithRequest();
      const disclosedProof = await disclosedProofCreateWithRequest(data);
      const { attrs } = await disclosedProof.getCredentials();
      const valSelfAttested = 'testSelfAttestedVal';
      await disclosedProof.generateProof({
        selectedCreds: {},
        selfAttestedAttrs: mapValues(attrs, () => valSelfAttested),
      });
      await disclosedProof.sendProof(data.connection);
    });
  });

  describe('getProofRequestAttachment:', async () => {
    it('success', async () => {
      const data = await dataDisclosedProofCreateWithRequest();
      const disclosedProof = await disclosedProofCreateWithRequest(data);
      const attrs = await disclosedProof.getProofRequestAttachment();
      const expectedAttrs =
        '{"name":"proofForAlice","non_revoked":{"from":null,"to":1599834712270},"nonce":"1137618739380422483900458","requested_attributes":{"attribute_0":{"names":["name","last_name","sex"],"restrictions":{"$or":[{"issuer_did":"V4SGRU86Z58d6TV7PBUe6f"}]}},"attribute_1":{"name":"date","restrictions":{"issuer_did":"V4SGRU86Z58d6TV7PBUe6f"}},"attribute_2":{"name":"degree","restrictions":{"attr::degree::value":"maths"}},"attribute_3":{"name":"nickname"}},"requested_predicates":{"predicate_0":{"name":"age","p_type":">=","p_value":20,"restrictions":{"$or":[{"issuer_did":"V4SGRU86Z58d6TV7PBUe6f"}]}}},"ver":"1.0","version":"1.0"}';
      assert.equal(attrs, expectedAttrs);
    });
  });

  describe('rejectProof:', async () => {
    it('success', async () => {
      const data = await dataDisclosedProofCreateWithRequest();
      const disclosedProof = await disclosedProofCreateWithRequest(data);
      await disclosedProof.rejectProof(data.connection);
    });
  });

  describe('declinePresentationRequest:', () => {
    it('success', async () => {
      const data = await dataDisclosedProofCreateWithRequest();
      await disclosedProofCreateWithRequest(data);
    });
  });
});
