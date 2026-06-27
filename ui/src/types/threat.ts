export interface ThreatAlert {
  id: string;
  timestamp: string;
  severity: 'Critical' | 'High' | 'Medium' | 'Low';
  threatType: string;
  description: string;
  processName: string;
  processId: number;
  parentProcessId: number;
  commandLine: string;
  fileHash: string;
  mitreTechniques: string[];
  indicators: string[];
  detectionSource: string;
  detectionConfidence: number;
  status: 'Active' | 'Investigating' | 'Resolved' | 'FalsePositive';
  assignedTo?: string;
}

export interface DashboardStats {
  totalThreatsToday: number;
  criticalThreats: number;
  highThreats: number;
  mediumThreats: number;
  lowThreats: number;
  detectionRate: number;
  protectedEndpoints: number;
  vulnerableEndpoints: number;
  offlineEndpoints: number;
  isolatedEndpoints: number;
  cpuUsage: number;
  memoryUsageMb: number;
  detectionLatencyMs: number;
  falsePositiveRate: number;
}

export interface Endpoint {
  id: string;
  hostname: string;
  ipAddress: string;
  osVersion: string;
  status: 'Protected' | 'Vulnerable' | 'Offline' | 'Isolated';
  lastSeen: string;
  agentVersion: string;
  hardwareSecurity: boolean;
  filelessDetection: boolean;
  supplyChainProtection: boolean;
  quantumCrypto: boolean;
  neuralDetection: boolean;
  advancedMemoryForensics: boolean;
  zeroTrust: boolean;
  ueba: boolean;
}
