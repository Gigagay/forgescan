export const billingAPI = {
  getUsage: async () => ({}) as any,
  cancelSubscription: async () => ({} as any),
  createCheckout: async (_payload: any) => ({ id: 'stub' } as any),
  getCheckoutStatus: async (_id: string) => ({ status: 'complete' } as any),
};
export default billingAPI;
