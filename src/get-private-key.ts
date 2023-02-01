import {decrypt} from '@haqq/encryption-react-native';
import EncryptedStorage from 'react-native-encrypted-storage';

export async function getPrivateKey(id: string, getPassword: () => Promise<string>) {
  const password = await getPassword();
  const data = await EncryptedStorage.getItem(`hot_${id}`);

  if(!data) {
    throw new Error('encrypted_data_not_found')
  }

  const resp = await decrypt<{privateKey: string}>(password, data);

  if (!resp.privateKey) {
    throw new Error('private_key_not_found');
  }

  return resp
}
