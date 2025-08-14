// ========================
// Base API Responses
// ========================
export interface ApiResponse<T = any> {
  success: boolean;
  message?: string;
  data?: T;
  error?: string;
}

// ========================
// Image Interfaces
// ========================
export interface ImageData {
  base64: string;
  type?: string;
}

export interface ImageProcessResult {
  success: boolean;
  image?: string;
  size?: number;
  type?: string;
  error?: string;
}

export interface ImageQualityValidation {
  valid: boolean;
  issues: string[];
}

// ========================
// User and Verification Data
// ========================
export interface UserData {
  firstName?: string;
  lastName?: string;
  email?: string;
  phone?: string;
  dateOfBirth?: string;
  address?: {
    street?: string;
    city?: string;
    state?: string;
    postalCode?: string;
    country?: string;
  };
  [key: string]: any;
  vendorData?: any;
}

export interface VerificationSession {
  id: string;
  status: string;
  created_at?: string;
  user_data?: UserData;
  [key: string]: any;
}

export interface ExtractedDocumentData {
  firstName?: string;
  lastName?: string;
  dateOfBirth?: string;
  documentNumber?: string;
  expiryDate?: string;
  issuingCountry?: string;
  documentType?: string;
  gender?: string;
  nationality?: string;
  [key: string]: any;
}

export interface VerificationResult {
  id?: string;
  processingStatus: 'done' | 'processing';
  overallResult: {
    status: 'approved' | 'declined' | 'error' | 'needs-review';
    confidence?: number;
    reason?: string;
    [key: string]: any;
  };
  extractedData?: ExtractedDocumentData;
  jwtSignData?: string;
  [key: string]: any;
}

// ========================
// JWT / Authentication
// ========================
export interface JWTVerificationResult {
  valid: boolean;
  data?: any;
  error?: string;
}

export interface SessionTokenPayload {
  userId?: string;
  email?: string;
  firstName?: string;
  lastName?: string;
  iat: number;
  exp: number;
  iss: string;
}

// ========================
// Bulk Verification
// ========================
export interface BulkVerificationRequest {
  images: ImageData[];
  userData: UserData;
}

export interface BulkVerificationItemResult {
  index: number;
  success: boolean;
  sessionId?: string;
  status?: string;
  error?: string;
}

export interface BulkVerificationResult {
  results: BulkVerificationItemResult[];
  total: number;
  successful: number;
  failed: number;
}

// ========================
// Webhooks
// ========================
export interface WebhookPayload {
  id: string;
  processingStatus: string;
  overallResult: {
    status: string;
    [key: string]: any;
  };
  extractedData?: ExtractedDocumentData;
  jwtSignData?: string;
  timestamp?: string;
  [key: string]: any;
}

export interface WebhookRequest {
  body: WebhookPayload;
  headers: {
    'x-checkin-signature'?: string;
    'signature'?: string;
    [key: string]: string | undefined;
  };
}

export type WebhookEventType =
  | 'verification.completed'
  | 'verification.approved'
  | 'verification.declined'
  | 'verification.needs_review'
  | 'verification.error'
  | 'verification.started'
  | 'verification.processing';

export interface WebhookEvent {
  type: WebhookEventType;
  id: string;
  created: number;
  data: WebhookPayload;
}

// ========================
// Service Config
// ========================
export interface ServiceConfig {
  baseUrl: string;
  apiKey: string;
  webhookSecret: string;
  timeout: number;
  retryAttempts: number;
  retryDelay: number;
}

// ========================
// Type Guards
// ========================
export const isVerificationResult = (obj: any): obj is VerificationResult => {
  return obj &&
    typeof obj === 'object' &&
    typeof obj.processingStatus === 'string' &&
    obj.overallResult &&
    typeof obj.overallResult.status === 'string';
};

export const isValidImageData = (obj: any): obj is ImageData => {
  return obj && typeof obj === 'object' && typeof obj.base64 === 'string' && obj.base64.length > 0;
};

export const isWebhookPayload = (obj: any): obj is WebhookPayload => {
  return obj &&
    typeof obj === 'object' &&
    typeof obj.id === 'string' &&
    typeof obj.processingStatus === 'string' &&
    obj.overallResult &&
    typeof obj.overallResult === 'object';
};
