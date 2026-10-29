export interface PESectionInfo {
  name: string;
  rva: number;
  virtualSize: number;
  rawSize: number;
  entropy: number;
  characteristics: string;
}

export interface BinaryAnalysisResult {
  binaryId: string;
  filename: string;
  yaraMatched: boolean;
  matchedRules: string[] | string;
  mlRiskScore: number;
  classification: string;
  machineType?: string;
  entryPoint?: number;
  imageBase?: number;
  subsystem?: string;
  sections?: PESectionInfo[];
  packed?: boolean;
}

export interface ReportAlert {
  severity: 'Critical' | 'High' | 'Medium' | 'Low' | string;
  message: string;
}

export interface NetworkConnection {
  dst: string;
  dport: number;
  protocol: string;
  uri?: string;
}

export interface DroppedFile {
  name: string;
  size: number;
  type: string;
}

export interface ReportAnalysisData {
  name?: string;
  sha256?: string;
  size?: number;
  entropy?: number;
  behaviors?: string[];
  apicalls?: string[];
  network?: NetworkConnection[];
  dropped?: DroppedFile[];
  mutexes?: string[];
  analysis?: {
    verdict?: string;
    confidence?: number;
    tags?: string[];
  };
  [key: string]: any;
}

export interface ReportAnalysisResult {
  filename: string;
  timestamp: string;
  fileSize: number;
  binaryId: string;
  sha256?: string;
  entropy?: number;
  alerts: ReportAlert[];
  mlScore?: {
    riskScore: number;
    classification: string;
  };
  trustScore: number;
  riskLevel: 'Critical' | 'High' | 'Medium' | 'Low' | string;
  analysis?: ReportAnalysisData;
}

export type UnifiedAnalysis =
  | { type: 'binary'; data: BinaryAnalysisResult }
  | { type: 'report'; data: ReportAnalysisResult };
