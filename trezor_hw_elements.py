import pytest
pytestmark = pytest.mark.liquid

from trezorlib import btc, elements, messages as proto
from trezorlib.client import get_default_client
from trezorlib.ckd_public import deserialize
from trezorlib.tools import parse_path

from core_rpc import *
from conftest import create_liquid_session, create_session, issue_asset, fund_user_with_asset, wait_tx_notification, wait_for_block

from greenaddress import Session, json, init
import wallycore as wally
import base64


h2b = wally.hex_to_bytes


class trezor_device(object):

    def __init__(self):
        self.client = get_default_client();
        print(self.get_features())

    def get_features(self):
        return self.client.features

    def as_xpub(self, path):
        n = btc.get_public_node(self.client, path)
        return n.xpub

    def __get_xpubs_from_path_array(self, paths):
        return [self.as_xpub(p) for p in paths]

    def get_xpubs(self, required_data):
        return json.dumps({'xpubs': self.__get_xpubs_from_path_array(required_data['paths'])})

    def sign_message(self, required_data):
        sig = btc.sign_message(self.client, "Bitcoin", required_data['path'], required_data['message'])
        # TODO: trezor appears to generate a recoverable sig
        sig_der = wally.ec_sig_to_der(sig['signature'][1:])
        return json.dumps({'signature': sig_der.hex(), 'signature_b64': base64.b64encode(sig['signature']).decode('ascii')})

    def get_receive_address(self, required_data):
        blinding_pubkey = elements.get_blinding_pubkey(self.client, h2b(required_data['address']['blinding_script_hash']))
        return json.dumps({'blinding_key': blinding_pubkey.hex()})

    def get_balance(self, required_data):
        nonces = [elements.get_rangeproof_nonce(self.client, ecdh_pubkey = h2b(script['pubkey']), script_pubkey = h2b(script['script']))
                    for script in required_data['blinded_scripts']]
        assert len(nonces)
        return json.dumps({'nonces' : [nonce.hex() for nonce in nonces]})

    def create_transaction(self, required_data):
        change_address = required_data['transaction'].get('change_address')
        if change_address:
            blinding_pubkey = elements.get_blinding_pubkey(self.client, h2b(change_address['btc']['blinding_script_hash']))
            return json.dumps({'blinding_keys': {'btc': blinding_pubkey.hex()}})
        else:
            return json.dumps({'blinding_keys': {}})

    def sign_tx(self, required_data):
        signing_inputs = required_data['signing_inputs']
        transaction_outputs = required_data['transaction_outputs']
        signing_transactions = required_data['signing_transactions']
        signing_address_types = required_data['signing_address_types']

        scripts = []
        for in_ in signing_inputs:
            service_xpub = deserialize(in_['service_xpub'])
            user_xpub = deserialize(self.as_xpub(in_['user_path'][:-1]))
            pointer = in_['pointer']
            redeem_script = proto.MultisigRedeemScriptType(nodes = [user_xpub, service_xpub],
                                                           address_n = [pointer],
                                                           signatures = [b'', b''],
                                                           m = 2,
                                                           csv = in_['subtype'])
            scripts.append(redeem_script)

        ins = []
        for i, txin in enumerate(signing_inputs):
            in_ = proto.TxInputType(
                    address_n = txin['user_path'],
                                    prev_hash = h2b(txin['txhash']),
                                    prev_index = txin['pt_idx'],
                                    script_type = proto.InputScriptType.SPENDP2SHWITNESS,
                                    multisig = scripts[i],
                                    amount = txin['satoshi'],
                                    sequence = txin['sequence'])
            in_.confidential = proto.TxConfidentialAsset(asset = h2b(txin['asset_id'])[::-1],
                                                         amount_blind = h2b(txin['vbf']),
                                                         asset_blind = h2b(txin['abf']))
            ins.append(in_)

        values = []
        in_vbfs = []
        in_abfs = []
        for txin in signing_inputs:
            in_vbfs.append(h2b(txin['vbf']))
            in_abfs.append(h2b(txin['abf']))
            values.append(txin['satoshi'])

        out_vbfs = []
        out_abfs = []
        for i, txout in enumerate(transaction_outputs):
            if txout['is_fee']:
                continue
            out_vbfs.append(b'\x11'*32)
            out_abfs.append(b'\x22'*32)
            values.append(txout['satoshi'])

        abfs = in_abfs + out_abfs
        vbfs = in_vbfs + out_vbfs[:-1]
        final_vbf = wally.asset_final_vbf(values, len(signing_inputs), b''.join(abfs), b''.join(vbfs))
        out_vbfs[-1] = final_vbf

        outs = []
        for i, txout in enumerate(transaction_outputs):
            if txout['is_fee']:
                out = proto.TxOutputType(address = '',
                                         amount = txout['satoshi'])
                out.confidential = proto.TxConfidentialAsset(asset = h2b(txout['asset_id'])[::-1])
            else:
                out = proto.TxOutputType(address = txout['address'],
                                         amount = txout['satoshi'],
                                         script_type = proto.OutputScriptType.PAYTOADDRESS)
                out.confidential = proto.TxConfidentialAsset(asset = h2b(txout['asset_id'])[::-1],
                                                             amount_blind = out_vbfs[i],
                                                             asset_blind = out_abfs[i],
                                                             nonce_privkey = h2b(txout['eph_keypair_sec']))
            outs.append(out)

        signatures, serialized_tx = btc.sign_tx(self.client,
                                       'Elements',
                                       ins,
                                       outs,
                                       prev_txes = None,
                                       details = proto.SignTx(version = 2, lock_time = required_data['transaction']['transaction_locktime']))

        asset_commitments = []
        value_commitments = []

        tx = wally.tx_from_bytes(serialized_tx, wally.WALLY_TX_FLAG_USE_WITNESS | wally.WALLY_TX_FLAG_USE_ELEMENTS)
        for i in range(wally.tx_get_num_outputs(tx)):
            asset_commitments.append(wally.tx_get_output_asset(tx, i))
            value_commitments.append(wally.tx_get_output_value(tx, i))

        out_abfs.append(b'\x00' * 32) # FIXME: GDK enforcing blinding factors for fee
        out_vbfs.append(b'\x00' * 32)

        return json.dumps({'signatures': [sig.hex() + '01' for sig in signatures],
                           'vbfs': [vbf.hex() for vbf in out_vbfs],
                           'abfs': [abf.hex() for abf in out_abfs],
                           'asset_commitments': [commitment.hex() for commitment in asset_commitments],
                           'value_commitments': [commitment.hex() for commitment in value_commitments]})

    def get_hw_info(self):
        return { 'device': { 'name': 'trezor',
                             'supports_low_r': False,
                             'supports_arbitrary_scripts': True,
                             'supports_liquid': 1 } }


def unreachable():
    assert False


MODEL_T = trezor_device()


def hw_resolver(required_data):
    return getattr(MODEL_T, required_data['action'])(required_data)


def create_and_send_transaction(session, details, select_method_fn = None, resolve_code_fn = None):
    tx = session.create_transaction(details).resolve(select_method_fn, resolve_code_fn)
    assert tx['error'] == '', tx['error']
    tx = session.sign_transaction(tx).resolve(select_method_fn, resolve_code_fn)
    tx = session.send_transaction(tx).resolve(select_method_fn, resolve_code_fn)
    txhash = tx['txhash']
    wait_tx_notification(session, txhash)
    return txhash


def test_trezor_liquid(session):
    hw_session = Session({'name': 'localtest-liquid', 'log_level': 'debug'})
    hw_session.register_user(MODEL_T.get_hw_info(), '').resolve(unreachable, hw_resolver)
    hw_session.login(MODEL_T.get_hw_info(), '', '').resolve(unreachable, hw_resolver)

    ad = hw_session.get_receive_address().resolve(unreachable, hw_resolver)
    details = {'subaccount': 0, 'addressees' : [{'satoshi': 10000, 'address': ad['address']}]}
    create_and_send_transaction(session, details)

    assert wait_for_block(session, generate(6))

    balance = hw_session.get_balance().resolve(unreachable, hw_resolver)

    ad = session.get_receive_address().resolve(None, None)
    details = {'subaccount': 0, 'addressees' : [{'satoshi': 1000, 'address': ad['address']}]}
    create_and_send_transaction(hw_session, details, unreachable, hw_resolver)


if __name__ == '__main__':
    test_trezor_liquid(create_liquid_session())
