export const scansAPI = {
  list: async () => {
    return [] as any[];
  },
  get: async (_id: string) => ({} as any),
  getFindings: async (_id: string) => ([] as any[]),
  create: async (_payload: any) => ({} as any),
  delete: async (_id: string) => ({} as any),
};
export default scansAPI;
