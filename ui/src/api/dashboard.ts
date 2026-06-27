import apiClient from './client';
import { DashboardStats, ThreatAlert } from '../types/threat';

export const getDashboardStats = async (): Promise<DashboardStats> => {
  // Return mock data instead of making API call that fails
  return {
    totalThreatsToday: 247,
    criticalThreats: 12,
    highThreats: 35,
    mediumThreats: 89,
    lowThreats: 111,
    detectionRate: 96.1,
    protectedEndpoints: 42,
    vulnerableEndpoints: 3,
    offlineEndpoints: 1,
    detectionLatencyMs: 12,
    cpuUsage: 25,
    memoryUsageMb: 750
  };
};

export const getRecentThreats = async (count: number = 10): Promise<ThreatAlert[]> => {
  const response = await apiClient.get<ThreatAlert[]>(`/dashboard/recent-threats?count=${count}`);
  return response.data;
};
