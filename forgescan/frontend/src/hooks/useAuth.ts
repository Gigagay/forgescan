import React from 'react';

export const useAuth = () => {
  // Minimal stub for build purposes
  const [isAuthenticated] = React.useState(false);
  const [isLoading] = React.useState(false);
  const user: any = null;

  const login = async (_email: string, _password: string) => {
    // stub
    return Promise.resolve();
  };

  const logout = () => {};

  const signup = async (..._args: any[]) => Promise.resolve();

  return { isAuthenticated, isLoading, user, login, logout, signup };
};
export default useAuth;
