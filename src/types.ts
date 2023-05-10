export type ProviderHotOptions = {
  account: string;
  getPassword: () => Promise<string>;
};
