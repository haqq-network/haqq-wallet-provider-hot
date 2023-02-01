import {TransactionRequest} from '@ethersproject/abstract-provider';
import {hexConcat} from '@ethersproject/bytes';
import {serialize, UnsignedTransaction} from '@ethersproject/transactions';
import {encrypt} from '@haqq/encryption-react-native';
import {
  compressPublicKey,
  hexStringToByteArray,
  Provider as ProviderBase,
  ProviderInterface
} from '@haqq/provider-base';
import {ProviderBaseOptions} from '@haqq/provider-base/src/types';
import {accountInfo, sign} from '@haqq/provider-web3-utils'
import EncryptedStorage from 'react-native-encrypted-storage';
import {getPrivateKey} from './get-private-key';
import {ProviderHotOptions} from './types';

export class ProviderHotReactNative extends ProviderBase<ProviderHotOptions> implements ProviderInterface {
  static async initialize(privateKey: string, getPassword: () => Promise<string>, options: Omit<ProviderBaseOptions, 'getPassword'>): Promise<ProviderHotReactNative> {
    const password = await getPassword();
    const privateData = await encrypt(password, {
      privateKey,
    });

    const {address} = await accountInfo(privateKey)

    await EncryptedStorage.setItem(
      `hot_${address.toLowerCase()}`,
      privateData
    );

    return new ProviderHotReactNative({
      ...options,
      getPassword,
      account: address.toLowerCase()
    })
  }

  async updatePin(pin: string) {
    try {
      const decryptedData = await getPrivateKey(this._options.account, this._options.getPassword)
      const privateData = await encrypt(pin, decryptedData);

      await EncryptedStorage.setItem(
        `hot_${this.getIdentifier().toLowerCase()}`,
        privateData
      );
    } catch (e) {
      if (e instanceof Error) {
        this.catchError(e, 'updatePin')
      }
    }
  }

  async clean() {
    try {
      await EncryptedStorage.removeItem(
        `hot_${this.getIdentifier().toLowerCase()}`
      );
    } catch (e) {
      if (e instanceof Error) {
        this.catchError(e, 'clean')
      }
    }
  }

  getIdentifier() {
    return this._options.account
  }

  async getAccountInfo(_hdPath: string) {
    let resp = {publicKey: '', address: ''}
    try {
      const {privateKey} = await getPrivateKey(this._options.account, this._options.getPassword)
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

  async signTransaction(_hdPath: string, transaction: TransactionRequest): Promise<string> {
    let resp = ''
    try {
      const {privateKey} = await getPrivateKey(this._options.account, this._options.getPassword);

      if (!privateKey) {
        throw new Error('private_key_not_found');
      }

      const signature = await sign(
        privateKey,
        serialize(transaction as UnsignedTransaction),
      );

      const sig = hexStringToByteArray(signature);

      resp = serialize(transaction as UnsignedTransaction, sig);

      this.emit('signTransaction', true);
    } catch (e) {
      if (e instanceof Error) {
        this.catchError(e, 'signTransaction')
      }
    }

    return resp
  }

  async signPersonalMessage(hdPath: string, message: string): Promise<string> {
    let resp = ''
    try {
      const {privateKey} = await getPrivateKey(this._options.account, this._options.getPassword);

      if (!privateKey) {
        throw new Error('private_key_not_found');
      }

      const msg = `\x19Ethereum Signed Message:\n${message.length}${message}`;


      resp = await sign(
        privateKey,
        msg,
      );
      this.emit('signTransaction', true);
    } catch (e) {
      if (e instanceof Error) {
        this.catchError(e, 'signTransaction')
      }
    }

    return resp
  }

  async signTypedData(_hdPath: string, domainHash: string, valueHash: string): Promise<string> {
    let response = ''
    try {
      const {privateKey} = await getPrivateKey(this._options.account, this._options.getPassword);

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
