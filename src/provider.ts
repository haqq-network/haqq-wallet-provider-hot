import {TransactionRequest} from '@ethersproject/abstract-provider';
import {hexConcat, joinSignature} from '@ethersproject/bytes';
import {keccak256} from '@ethersproject/keccak256';
import {SigningKey} from '@ethersproject/signing-key';
import {serialize, UnsignedTransaction} from '@ethersproject/transactions';
import {encrypt} from '@haqq/encryption-react-native';
import {
  compressPublicKey, hexStringToByteArray,
  Provider as ProviderBase,
  ProviderInterface
} from '@haqq/provider-base';
import {accountInfo, sign} from '@haqq/provider-web3-utils'
import EncryptedStorage from 'react-native-encrypted-storage';
import {getPrivateKey} from './get-private-key';
import {ProviderHotOptions} from './types';

export class Provider extends ProviderBase<ProviderHotOptions> implements ProviderInterface {
  static async initialize(privateKey: string, getPassword: () => Promise<string>): Promise<string> {
    const password = await getPassword();
    const privateData = await encrypt(password, {
      privateKey,
    });

    const {address} = await accountInfo(privateKey)

    await EncryptedStorage.setItem(
      `hot_${address}`,
      JSON.stringify(privateData)
    );

    return address
  }

  async getEthAddress(hdPath: string): Promise<string> {
    const {address} = await this.getPublicKeyAndAddressForHDPath(hdPath)
    return address
  }

  async getPublicKey(hdPath: string) {
    const {publicKey} = await this.getPublicKeyAndAddressForHDPath(hdPath)
    return publicKey
  }

  async getPublicKeyAndAddressForHDPath(_hdPath: string) {
    let resp = {publicKey: '', address: ''}
    try {
      const privateKey = await getPrivateKey(this._options.account, this._options.getPassword)
      const account = await accountInfo(privateKey);

      resp = {
        publicKey: compressPublicKey(account.publicKey),
        address: account.address
      }
      this.emit('getPublicKeyForHDPath', true);
    } catch (e) {
      if (e instanceof Error) {
        this.catchError(e, 'getPublicKeyForHDPath')
      }
    }
    return resp
  }

  async getSignedTx(_hdPath: string, transaction: TransactionRequest): Promise<string> {
    let resp = ''
    try {
      const privateKey = await getPrivateKey(this._options.account, this._options.getPassword);

      if (!privateKey) {
        throw new Error('private_key_not_found');
      }

      const signature = await sign(
        privateKey,
        serialize(transaction as UnsignedTransaction),
      );

      const sig = hexStringToByteArray(signature);

      resp = serialize(transaction as UnsignedTransaction, sig);

      this.emit('getSignedTx', true);
    } catch (e) {
      if (e instanceof Error) {
        this.catchError(e, 'getSignedTx')
      }
    }

    return resp
  }

  async signTypedData(_hdPath: string, domainHash: string, valueHash: string): Promise<string> {
    let response = ''
    try {
      const privateKey = await getPrivateKey(this._options.account, this._options.getPassword);

      if (!privateKey) {
        throw new Error('private_key_not_found');
      }

      const concatHash = hexConcat(['0x1901', domainHash, valueHash]);
      response = await sign(privateKey, concatHash);
      this.emit('signTypedData', true);
    } catch (e) {
      if (e instanceof Error) {
        this.catchError(e, 'signTypedData')
      }
    }

    return response
  }
}
