import apiClient from './client';

interface LoginRequest {
  username: string;
  password: string;
}

interface LoginResponse {
  token: string;
  refreshToken: string;
  expiresAt: string;
}

export const login = async (credentials: LoginRequest): Promise<LoginResponse> => {
  const response = await apiClient.post<LoginResponse>('/auth/login', credentials);
  
  // Store token
  localStorage.setItem('vyron_token', response.data.token);
  localStorage.setItem('vyron_refresh_token', response.data.refreshToken);
  
  return response.data;
};

export const logout = () => {
  localStorage.removeItem('vyron_token');
  localStorage.removeItem('vyron_refresh_token');
};

export const isAuthenticated = (): boolean => {
  return !!localStorage.getItem('vyron_token');
};
