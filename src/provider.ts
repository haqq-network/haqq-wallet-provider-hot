import {hexConcat} from '@ethersproject/bytes';
import {serialize, UnsignedTransaction} from '@ethersproject/transactions';
import {encrypt} from '@haqq/encryption-react-native';
import {
  compressPublicKey,
  hexStringToByteArray,
  joinSignature,
  prepareHashedEip712Data,
  stringToUtf8Bytes,
  BytesLike,
  Provider as ProviderBase,
  ProviderInterface,
  TransactionRequest,
  TypedData,
  calcTypedDataSignatureV,
} from '@haqq/provider-base';
import {ProviderBaseOptions} from '@haqq/provider-base/src/types';
import {accountInfo, sign} from '@haqq/provider-web3-utils';
import {encryptShare} from '@haqq/shared-react-native';
import EncryptedStorage from 'react-native-encrypted-storage';
import {ITEM_KEY} from './constants';
import {getPrivateKey} from './get-private-key';
import {ProviderHotOptions} from './types';

export class ProviderHotReactNative
  extends ProviderBase<ProviderHotOptions>
  implements ProviderInterface
{
  static async initialize(
    privateKey: string,
    getPassword: () => Promise<string>,
    options: Omit<ProviderBaseOptions, 'getPassword'>,
  ): Promise<ProviderHotReactNative> {
    const password = await getPassword();

    const privateData = await encryptShare(
      {
        share: privateKey,
        shareIndex: '0',
        polynomialID: '0',
      },
      password,
    );

    const {address} = await accountInfo(privateKey);

    await EncryptedStorage.setItem(
      `${ITEM_KEY}_${address.toLowerCase()}`,
      JSON.stringify(privateData),
    );

    return new ProviderHotReactNative({
      ...options,
      getPassword,
      account: address.toLowerCase(),
    });
  }

  async updatePin(pin: string) {
    try {
      const decryptedData = await getPrivateKey(
        this._options.account,
        this._options.getPassword,
      );
      const privateData = await encrypt(pin, decryptedData);

      await EncryptedStorage.setItem(
        `${ITEM_KEY}_${this.getIdentifier().toLowerCase()}`,
        privateData,
      );
    } catch (e) {
      if (e instanceof Error) {
        this.catchError(e, 'updatePin');
      }
    }
  }

  async clean() {
    try {
      await EncryptedStorage.removeItem(
        `${ITEM_KEY}_${this.getIdentifier().toLowerCase()}`,
      );
    } catch (e) {
      if (e instanceof Error) {
        this.catchError(e, 'clean');
      }
    }
  }

  getIdentifier() {
    return this._options.account;
  }

  async getAccountInfo(_hdPath: string) {
    let resp = {publicKey: '', address: ''};
    try {
      const {share} = await getPrivateKey(
        this._options.account,
        this._options.getPassword,
      );
      const account = await accountInfo(share);

      resp = {
        publicKey: compressPublicKey(account.publicKey),
        address: account.address,
      };
      this.emit('getPublicKeyForHDPath', true);
    } catch (e) {
      if (e instanceof Error) {
        this.catchError(e, 'getPublicKeyForHDPath');
      }
    }
    return resp;
  }

  async signTransaction(
    _hdPath: string,
    transaction: TransactionRequest,
  ): Promise<string> {
    let resp = '';
    try {
      const {share} = await getPrivateKey(
        this._options.account,
        this._options.getPassword,
      );

      if (!share) {
        throw new Error('private_key_not_found');
      }

      const signature = await sign(
        share,
        serialize(transaction as UnsignedTransaction),
      );

      const sig = hexStringToByteArray(signature);

      resp = serialize(transaction as UnsignedTransaction, sig);

      this.emit('signTransaction', true);
    } catch (e) {
      if (e instanceof Error) {
        this.catchError(e, 'signTransaction');
      }
    }

    return resp;
  }

  async signPersonalMessage(
    hdPath: string,
    message: BytesLike | string,
  ): Promise<string> {
    let resp = '';
    try {
      const {share} = await getPrivateKey(
        this._options.account,
        this._options.getPassword,
      );

      if (!share) {
        throw new Error('private_key_not_found');
      }

      const m = Array.from(
        typeof message === 'string' ? stringToUtf8Bytes(message) : message,
      );

      const hash = Buffer.from(
        [
          25, 69, 116, 104, 101, 114, 101, 117, 109, 32, 83, 105, 103, 110, 101,
          100, 32, 77, 101, 115, 115, 97, 103, 101, 58, 10,
        ].concat(stringToUtf8Bytes(String(message.length)), m),
      ).toString('hex');
      const signature = await sign(share, hash);
      resp = '0x' + joinSignature(signature);
      this.emit('signTransaction', true);
    } catch (e) {
      if (e instanceof Error) {
        this.catchError(e, 'signTransaction');
      }
    }

    return resp;
  }

  async signTypedData(_hdPath: string, typedData: TypedData): Promise<string> {
    let response = '';
    try {
      const {share} = await getPrivateKey(
        this._options.account,
        this._options.getPassword,
      );

      if (!share) {
        throw new Error('private_key_not_found');
      }

      const {domainSeparatorHex, hashStructMessageHex} =
        prepareHashedEip712Data(typedData);
      const concatHash = hexConcat([
        '0x1901',
        domainSeparatorHex,
        hashStructMessageHex,
      ]);
      response = await sign(share, concatHash);
      this.emit('signTypedData', true);
    } catch (e) {
      if (e instanceof Error) {
        this.catchError(e, 'signTypedData');
      }
    }

    return calcTypedDataSignatureV(response);
  }
}
