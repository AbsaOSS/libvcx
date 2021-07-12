import '../module-resolver-helper';

import { assert } from 'chai';
import { createConnectionInviterRequested, dataProofCreate, proofCreate } from 'helpers/entities';
import { initVcxTestMode, shouldThrow } from 'helpers/utils';
import {
  Connection,
  DisclosedProof,
  Proof,
  ProofState,
  VerifierStateType,
  VCXCode,
  VCXMock,
  VCXMockMessage,
} from 'src';

describe('Proof:', () => {
  before(() => initVcxTestMode());

  describe('create:', () => {
    it('success', async () => {
      await proofCreate();
    });

    it('throws: missing sourceId', async () => {
      const { sourceId, ...data } = dataProofCreate();
      const error = await shouldThrow(() => Proof.create(data as any));
      assert.equal(error.vcxCode, VCXCode.INVALID_OPTION);
    });

    it('throws: missing attrs', async () => {
      const { attrs, ...data } = dataProofCreate();
      const error = await shouldThrow(() => Proof.create({ ...data } as any));
      assert.equal(error.vcxCode, VCXCode.INVALID_OPTION);
    });

    // TODO: Enable once https://evernym.atlassian.net/browse/EN-666 is resolved
    it.skip('throws: empty attrs', async () => {
      const { attrs, ...data } = dataProofCreate();
      const error = await shouldThrow(() => Proof.create({ attrs: [], ...data }));
      assert.equal(error.vcxCode, VCXCode.INVALID_OPTION);
    });

    it('throws: missing name', async () => {
      const { name, ...data } = dataProofCreate();
      const error = await shouldThrow(() => Proof.create(data as any));
      assert.equal(error.vcxCode, VCXCode.INVALID_OPTION);
    });

    // TODO: Enable once https://evernym.atlassian.net/browse/EN-666 is resolved
    it.skip('throws: invalid attrs', async () => {
      const { attrs, ...data } = dataProofCreate();
      const error = await shouldThrow(() =>
        Proof.create({ attrs: [{ invalid: 'invalid' }] as any, ...data }),
      );
      assert.equal(error.vcxCode, VCXCode.INVALID_JSON);
    });
  });

  describe('serialize:', () => {
    it('success', async () => {
      const proof = await proofCreate();
      const { data } = await proof.serialize();
      assert.ok(data);
      // todo: IProofData is reflecting legacy structure, not vcxaries
      assert.equal((data as any).verifier_sm.source_id, proof.sourceId);
    });

    it('throws: not initialized', async () => {
      const proof = new Proof(null as any, {} as any);
      const error = await shouldThrow(() => proof.serialize());
      assert.equal(error.vcxCode, VCXCode.INVALID_PROOF_HANDLE);
    });
  });

  describe('deserialize:', () => {
    it('success', async () => {
      const proof1 = await proofCreate();
      const data1 = await proof1.serialize();
      const proof2 = await Proof.deserialize(data1);
      // todo: Does not hold in aries, the TS/JS representation after serialize->deserialize in incorrect because
      // IProofData structure is matching legacy structure
      // perhaps we could make JS layer thinner and instead of trying to keeping attributes like _requestedAttributes
      // in javascript representations, we could rather add method on libvcx proof vcx_proof_get_requested_attributes
      // which could encompass the logic of how to retrieve this data from internal proof representation.
      // The downside is some overhead associated with FFI.
      // assert.equal(proof2.verifier_sm.sourceId, proof1.verifier_sm.sourceId)
      const data2 = await proof2.serialize();
      assert.deepEqual(data1, data2);
    });

    it('throws: incorrect data', async () => {
      const error = await shouldThrow(async () =>
        Proof.deserialize({ source_id: 'Invalid' } as any),
      );
      assert.equal(error.vcxCode, VCXCode.UNKNOWN_ERROR);
    });

    it('throws: incomplete data', async () => {
      const error = await shouldThrow(async () =>
        Proof.deserialize({
          name: 'Invalid',
          requested_attrs: 'Invalid',
          source_id: 'Invalid',
        } as any),
      );
      assert.equal(error.vcxCode, VCXCode.UNKNOWN_ERROR);
    });
  });

  describe('updateState:', () => {
    it(`throws error when not initialized`, async () => {
      let caught_error;
      const proof = new Proof(null as any, {} as any);
      const connection = await createConnectionInviterRequested();
      try {
        await proof.updateStateV2(connection);
      } catch (err) {
        caught_error = err;
      }
      assert.isNotNull(caught_error);
    });
  });

  describe('requestProof:', () => {
    it('success', async () => {
      const connection = await createConnectionInviterRequested();
      const proof = await proofCreate();
      await proof.requestProof(connection);
      assert.equal(await proof.getState(), VerifierStateType.PresentationRequestSent);
    });

    it('successfully get request message', async () => {
      const proof = await proofCreate();
      const msg = await proof.getProofRequestMessage();
      assert(msg);
    });

    it('throws: not initialized', async () => {
      const connection = await createConnectionInviterRequested();
      const proof = new Proof(null as any, {} as any);
      const error = await shouldThrow(() => proof.requestProof(connection));
      assert.equal(error.vcxCode, VCXCode.INVALID_PROOF_HANDLE);
    });

    it('throws: connection not initialized', async () => {
      const connection = new (Connection as any)();
      const proof = await proofCreate();
      const error = await shouldThrow(() => proof.requestProof(connection));
      assert.equal(error.vcxCode, VCXCode.INVALID_CONNECTION_HANDLE);
    });
  });
});
