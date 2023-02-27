import {decrypt} from '@haqq/encryption-react-native';
import EncryptedStorage from 'react-native-encrypted-storage';
import {ITEM_KEY} from './constants';

export async function getPrivateKey(id: string, getPassword: () => Promise<string>) {
  const password = await getPassword();
  const data = await EncryptedStorage.getItem(`${ITEM_KEY}_${id}`);

  if(!data) {
    throw new Error('encrypted_data_not_found')
  }

  const resp = await decrypt<{privateKey: string}>(password, data);

  if (!resp.privateKey) {
    throw new Error('private_key_not_found');
  }

  return resp
}
