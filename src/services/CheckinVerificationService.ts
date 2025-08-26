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

// Add new interfaces for the customer API responses
interface CustomerDetails {
  _id: string;
  name: string;
  email: string;
  phone: string;
  kycStatus: string;
  country?: string;
}

interface ExistingSession {
  id: string;
  status: string;
  url: string;
  host: string;
  created_at: string;
  user_data: UserData;
}

export class VeriffService {
  private apiKey: string;
  private webhookSecret: string;
  private baseURL: string;
  private customerServiceURL: string;

  constructor() {
    this.apiKey = config.VERIFF_API_KEY;
    this.webhookSecret = config.VERIFF_WEBHOOK_SECRET;
    this.baseURL = config.IS_PRODUCTION 
      ? 'https://stationapi.veriff.com/v1'
      : 'https://stationapi.veriff.com/v1';
    this.customerServiceURL = 'https://webapi.doronpay.com';

    if (!this.apiKey) throw new Error('VERIFF_API_KEY is required');
    if (!this.webhookSecret) throw new Error('VERIFF_WEBHOOK_SECRET is required');
  }

  /**
   * Check if existing verification session exists for customer
   */
  private async checkExistingSession(customerId: string, token?: string): Promise<VerificationSession | null> {
    try {
      const headers: any = {};
      if (token) headers['Authorization'] = token;
      
      const response = await axios.get(
        `${this.customerServiceURL}/customers/${customerId}/verification/sessionId`,
        {
          timeout: 10000,
          headers,
          validateStatus: (status) => status < 500 // Don't throw on 404
        }
      );

      if (response.status === 200 && response.data?.success && response.data?.data) {
        console.log('Existing verification session found for customer:', customerId);
        const sessionData = response.data.data;
        
        // Ensure we have all required fields for VerificationSession
        return {
          id: sessionData.sessionId || sessionData.id,
          status: sessionData.status,
          url: sessionData.url,
          host: sessionData.host,
          created_at: sessionData.created_at || new Date().toISOString(),
          user_data: sessionData.user_data || {}
        } as VerificationSession;
      }

      return null;
    } catch (error: any) {
      console.log('No existing session found for customer:', customerId, error.message);
      return null;
    }
  }

  /**
   * Fetch customer details from customer service
   */
  private async fetchCustomerDetails(customerId: string, token?: string): Promise<CustomerDetails> {
    try {
      const headers: any = {};
      if (token) headers['Authorization'] = token;
      const response = await axios.get(
        `${this.customerServiceURL}/customers/get/${customerId}`,
        {
          timeout: 10000,
          headers
        }
      );

      if (!response.data?.success || !response.data?.data) {
        throw new Error('Invalid customer response format');
      }

      const customerData = response.data.data;
      
      return {
        _id: customerData._id,
        name: customerData.name,
        email: customerData.email,
        phone: customerData.phone,
        kycStatus: customerData.kycStatus,
        country: customerData.country
      };
    } catch (error: any) {
      console.error('Failed to fetch customer details:', {
        customerId,
        error: error.message,
        response: error.response?.data
      });
      throw new Error(`Failed to fetch customer details: ${error.response?.data?.message || error.message}`);
    }
  }

  /**
   * Save verification session to customer service
   */
  private async saveVerificationSession(customerId: string, session: VerificationSession, token?: string): Promise<void> {
    try {
      // Create the complete session data structure
      const sessionData = {
        sessionId: session.id,
        status: session.status,
        url: session.url,
        host: session.host,
        created_at: session.created_at,
        user_data: session.user_data,
        // Add additional fields that might be needed
        instructions: {
          message: "Redirect user to the provided URL to complete verification",
          url: session.url
        }
      };

      const payload = {
        customerId,
        sessionData
      };

      const headers: any = { 'Content-Type': 'application/json' };
      if (token) headers['Authorization'] = token;
      
      const response = await axios.post(
        `${this.customerServiceURL}/customers/verification/sessionId`,
        payload,
        {
          headers,
          timeout: 10000
        }
      );

      console.log('Verification session saved successfully for customer:', customerId);
      console.log('Save response:', response.data);
    } catch (error: any) {
      console.error('Failed to save verification session:', {
        customerId,
        sessionId: session.id,
        error: error.message,
        response: error.response?.data
      });
      // Don't throw here as the session was created successfully in Veriff
      // We just log the error for monitoring purposes
    }
  }

  /**
   * Parse customer name into first and last name
   */
  private parseCustomerName(fullName: string): { firstName: string; lastName: string } {
    const nameParts = fullName.trim().split(' ');
    const firstName = nameParts[0] || '';
    const lastName = nameParts.slice(1).join(' ') || '';
    
    return { firstName, lastName };
  }

  /**
   * Create Veriff session - Returns existing session if found, creates new only if none exists
   */
  async createVerificationSession(customerId: string, userData?: Partial<UserData>, token?: string): Promise<VerificationSession> {
    try {
      if (!customerId) {
        throw new Error('Customer ID is required');
      }

      // Check if existing session exists FIRST
      console.log('Checking for existing verification session for customer:', customerId);
      const existingSession = await this.checkExistingSession(customerId, token);
      
      if (existingSession && existingSession.id) {
        console.log('Found existing session with ID:', existingSession.id);
        console.log('Returning existing session - NOT creating new one');
        return existingSession;
      }

      console.log('No existing session found. Proceeding to create new verification session...');

      // Fetch customer details
      console.log('Fetching customer details for:', customerId);
      const customerDetails = await this.fetchCustomerDetails(customerId, token);
      
      // Parse customer name
      const { firstName, lastName } = this.parseCustomerName(customerDetails.name);
      
      if (!firstName || !lastName) {
        throw new Error(`Invalid customer name format: "${customerDetails.name}". Both firstName and lastName are required.`);
      }

      // Merge customer data with any provided userData
      const mergedUserData: UserData = {
        userId: customerId,
        firstName,
        lastName,
        email: customerDetails.email,
        phone: customerDetails.phone,
        country: customerDetails.country,
        // Override with any provided userData
        ...userData,
        // But always use customer details for critical fields
      };

      const vendorData = mergedUserData.vendorData || customerId;

      const sessionPayload = {
        verification: {
          callback: config.VERIFF_CALLBACK_URL,
          person: {
            firstName: mergedUserData.firstName,
            lastName: mergedUserData.lastName,
            ...(mergedUserData.documentNumber && { idNumber: mergedUserData.documentNumber })
          },
          vendorData: vendorData,
          lang: mergedUserData.lang || 'en',
          features: mergedUserData.features || ['selfid']
        }
      };

      console.log('Creating NEW Veriff session with payload:', JSON.stringify(sessionPayload, null, 2));
      console.log('VendorData being sent to Veriff:', vendorData);

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

      const newSession: VerificationSession = {
        id: verification.id,
        status: verification.status,
        url: verification.url,
        host: verification.host,
        created_at: new Date().toISOString(),
        user_data: mergedUserData
      };

      // Save the NEW session to customer service
      console.log('Saving NEW verification session to customer service...');
      await this.saveVerificationSession(customerId, newSession, token);

      console.log('NEW session created successfully with ID:', newSession.id);
      return newSession;

    } catch (error: any) {
      console.error('Veriff session creation error:', {
        customerId,
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
  async getVerificationResult(sessionId: string, token?: string): Promise<VerificationResult> {
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
   * Verify Veriff webhook signature - CORRECTED VERSION
   */
  verifyWebhookSignature(rawBody: Buffer | string, signature: string): boolean {
    try {
      if (!rawBody || !signature) {
        console.error('Missing rawBody or signature for webhook verification');
        return false;
      }

      // Remove 'sha256=' prefix if present and clean the signature
      const cleanSignature = signature.replace(/^sha256=/, '').trim();
      
      // Convert Buffer to string if needed
      const bodyString = Buffer.isBuffer(rawBody) ? rawBody.toString('utf8') : rawBody;
      
      console.log('=== WEBHOOK SIGNATURE VERIFICATION ===');
      console.log('Raw body length:', bodyString.length);
      console.log('Received signature:', cleanSignature);
      console.log('Webhook secret exists:', !!this.webhookSecret);

      // Create HMAC signature
      const expectedSignature = crypto
        .createHmac('sha256', this.webhookSecret)
        .update(bodyString)
        .digest('hex');

      console.log('Expected signature:', expectedSignature);
      
      // Compare signatures using constant-time comparison
      const isValid = crypto.timingSafeEqual(
        Buffer.from(cleanSignature, 'hex'),
        Buffer.from(expectedSignature, 'hex')
      );

      console.log('Signature validation result:', isValid);
      console.log('=====================================');
      
      return isValid;

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
      
      const configStatus = this.getConfigStatus();
      
      if (!configStatus.configured) {
        return {
          healthy: false,
          message: `Missing configuration: ${configStatus.missing.join(', ')}`
        };
      }
      
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

    if (!payload.verification?.id || typeof payload.verification.id !== 'string') {
      return { valid: false, error: 'Missing or invalid session ID' };
    }

    if (!payload.verification?.status) {
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
    if (code >= 9001 && code <= 9103) return 0.95;
    if (code >= 9200 && code <= 9299) return 0.7;
    return 0.5;
  }
}

export const verificationService = new VeriffService();