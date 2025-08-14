import axios from 'axios';
import crypto from 'crypto';
import jwt from 'jsonwebtoken';
import { config } from '../config/config';
import { 
  VerificationSession, 
  VerificationResult, 
  UserData,
  JWTVerificationResult 
} from '../types/index.js';

export class VeriffService {
  private apiKey: string;
  private webhookSecret: string;
  private baseURL: string;

  constructor() {
    this.apiKey = config.VERIFF_API_KEY;
    this.webhookSecret = config.VERIFF_WEBHOOK_SECRET;
    this.baseURL = config.IS_PRODUCTION 
      ? 'https://stationapi.veriff.com/v1'
      : 'https://stationapi.veriff.com/v1'; // Veriff uses same URL for both

    if (!this.apiKey) throw new Error('VERIFF_API_KEY is required');
    if (!this.webhookSecret) throw new Error('VERIFF_WEBHOOK_SECRET is required');
  }

  /**
   * Create Veriff session according to their API docs
   */
  async createVerificationSession(userData: UserData): Promise<VerificationSession> {
    try {
      // Validate required fields
      if (!userData?.firstName || !userData?.lastName) {
        throw new Error('firstName and lastName are required');
      }

      const sessionPayload = {
        verification: {
          callback: config.VERIFF_CALLBACK_URL,
          person: {
            firstName: userData.firstName,
            lastName: userData.lastName,
            ...(userData.documentNumber && { idNumber: userData.documentNumber })
          },
          vendorData: userData.vendorData || `session-${Date.now()}-${Math.random().toString(36).substring(2)}`,
          lang: userData.lang || 'en',
          features: userData.features || ['selfid']
        }
      };

      console.log('Creating Veriff session with payload:', JSON.stringify(sessionPayload, null, 2));

      const response = await axios.post(
        `${this.baseURL}/sessions`,
        sessionPayload,
        {
          headers: {
            'X-AUTH-CLIENT': this.apiKey,
            'Content-Type': 'application/json'
          },
          timeout: 30000
        }
      );

      const verification = response.data?.verification;
      
      if (!verification) {
        throw new Error('Invalid response from Veriff API - missing verification object');
      }

      return {
        id: verification.id,
        status: verification.status,
        url: verification.url,
        host: verification.host,
        created_at: new Date().toISOString(),
        user_data: userData
      };
    } catch (error: any) {
      console.error('Veriff session creation error:', {
        message: error.message,
        response: error.response?.data,
        status: error.response?.status
      });
      throw new Error(`Failed to create Veriff session: ${error.response?.data?.message || error.message}`);
    }
  }

  /**
   * Get verification result from Veriff
   */
  async getVerificationResult(sessionId: string): Promise<VerificationResult> {
    try {
      if (!sessionId) {
        throw new Error('Session ID is required');
      }

      const response = await axios.get(
        `${this.baseURL}/sessions/${sessionId}`,
        {
          headers: {
            'X-AUTH-CLIENT': this.apiKey
          },
          timeout: 30000
        }
      );

      const verification = response.data?.verification;
      
      if (!verification) {
        throw new Error('Invalid response from Veriff API - missing verification object');
      }
      
      return {
        id: verification.id,
        processingStatus: verification.status === 'submitted' ? 'processing' : 'done',
        overallResult: {
          status: this.mapVeriffStatus(verification.status),
          confidence: verification.code ? this.getConfidenceFromCode(verification.code) : undefined,
          reason: verification.reason || undefined
        },
        extractedData: verification.person ? {
          firstName: verification.person.firstName,
          lastName: verification.person.lastName,
          dateOfBirth: verification.person.dateOfBirth,
          documentNumber: verification.person.idNumber,
          nationality: verification.person.nationality,
          documentType: verification.document?.type
        } : undefined,
        vendorData: verification.vendorData || undefined
      };

    } catch (error: any) {
      console.error('Veriff result fetch error:', {
        sessionId,
        message: error.message,
        response: error.response?.data,
        status: error.response?.status
      });
      throw new Error(`Failed to fetch Veriff result: ${error.response?.data?.message || error.message}`);
    }
  }

  /**
   * Verify Veriff webhook signature
   */
  verifyWebhookSignature(payload: string, signature: string): boolean {
    try {
      if (!payload || !signature) {
        console.error('Missing payload or signature for webhook verification');
        return false;
      }

      const expectedSignature = crypto
        .createHmac('sha256', this.webhookSecret)
        .update(payload)
        .digest('hex');
      
      return crypto.timingSafeEqual(
        Buffer.from(signature, 'hex'),
        Buffer.from(expectedSignature, 'hex')
      );
    } catch (error) {
      console.error('Webhook signature verification error:', error);
      return false;
    }
  }

  /**
   * Generate session token for frontend
   */
  generateSessionToken(userData: UserData): string {
    if (!userData) {
      throw new Error('User data is required for token generation');
    }

    const payload = {
      userId: userData.userId || Math.random().toString(36).substring(7),
      email: userData.email || undefined,
      firstName: userData.firstName || undefined,
      lastName: userData.lastName || undefined,
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + 3600, // 1 hour
      iss: 'veriff-backend'
    };

    return jwt.sign(payload, config.JWT_SECRET);
  }

  /**
   * Verify session token
   */
  verifySessionToken(token: string): JWTVerificationResult {
    try {
      if (!token) {
        return { valid: false, error: 'Token is required' };
      }

      const decoded = jwt.verify(token, config.JWT_SECRET);
      return { valid: true, data: decoded };
    } catch (error: any) {
      return { valid: false, error: error.message };
    }
  }

  /**
   * Health check for Veriff service configuration
   */
  async healthCheck(): Promise<{ healthy: boolean; message?: string; responseTime?: number }> {
    try {
      const startTime = Date.now();
      
      // Validate configuration instead of making API call
      const configStatus = this.getConfigStatus();
      
      if (!configStatus.configured) {
        return {
          healthy: false,
          message: `Missing configuration: ${configStatus.missing.join(', ')}`
        };
      }
      
      // Additional checks
      if (!config.JWT_SECRET) {
        return {
          healthy: false,
          message: 'JWT_SECRET is required for session tokens'
        };
      }

      const responseTime = Date.now() - startTime;
      return { 
        healthy: true, 
        responseTime,
        message: 'Veriff service configured and ready' 
      };
    } catch (error: any) {
      return { 
        healthy: false, 
        message: error.message 
      };
    }
  }

  /**
   * Get configuration status
   */
  getConfigStatus(): { configured: boolean; missing: string[] } {
    const missing: string[] = [];
    
    if (!this.apiKey) missing.push('VERIFF_API_KEY');
    if (!this.webhookSecret) missing.push('VERIFF_WEBHOOK_SECRET');
    if (!config.VERIFF_CALLBACK_URL) missing.push('VERIFF_CALLBACK_URL');

    return {
      configured: missing.length === 0,
      missing
    };
  }

  /**
   * Validate verification result structure
   */
  validateVerificationResult(payload: any): { valid: boolean; error?: string } {
    if (!payload || typeof payload !== 'object') {
      return { valid: false, error: 'Invalid payload structure' };
    }

    if (!payload.id || typeof payload.id !== 'string') {
      return { valid: false, error: 'Missing or invalid session ID' };
    }

    if (!payload.status) {
      return { valid: false, error: 'Missing verification status' };
    }

    return { valid: true };
  }

  // Helper methods
  private mapVeriffStatus(veriffStatus: string): 'approved' | 'declined' | 'error' | 'needs-review' {
    switch (veriffStatus) {
      case 'approved':
        return 'approved';
      case 'declined':
        return 'declined';
      case 'resubmission_requested':
      case 'expired':
        return 'needs-review';
      default:
        return 'error';
    }
  }

  private getConfidenceFromCode(code: number): number {
    // Map Veriff codes to confidence scores
    if (code >= 9001 && code <= 9103) return 0.95; // High confidence approvals
    if (code >= 9200 && code <= 9299) return 0.7;  // Medium confidence
    return 0.5; // Low confidence or declined
  }
}

export const verificationService = new VeriffService();