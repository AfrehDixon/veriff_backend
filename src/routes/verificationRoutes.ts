import { Router, Request, Response, NextFunction } from 'express';
import Joi from 'joi';
import { 
  asyncHandler, 
  createValidationError, 
  createAuthError,
  sendSuccessResponse
} from '../middleware/errorHandler';
import { config } from '../config/config';
import { verificationService } from '../services/CheckinVerificationService';

const router = Router();

// Validation Schemas - ALL FIELDS OPTIONAL
const userDataSchema = Joi.object({
  firstName: Joi.string().min(1).max(100).optional().default('Test'),
  lastName: Joi.string().min(1).max(100).optional().default('User'),
  email: Joi.string().email().optional(),
  documentNumber: Joi.string().optional(),
  vendorData: Joi.string().optional(),
  lang: Joi.string().valid('en', 'et', 'es', 'ru', 'de', 'fr', 'lv', 'lt').default('en'),
  features: Joi.array().items(Joi.string().valid('selfid', 'smart-id-session')).default(['selfid'])
});

const tokenSchema = Joi.object({
  token: Joi.string().optional() // Made optional for testing
});

const validateBody = (schema: Joi.ObjectSchema) => {
  return (req: Request, res: Response, next: NextFunction) => {
    // Ensure req.body exists
    if (!req.body) {
      req.body = {};
    }

    const { error, value } = schema.validate(req.body, { 
      allowUnknown: true, 
      stripUnknown: true 
    });
    
    if (error?.details && error.details.length > 0) {
      const errorDetail = error.details[0];
      if (errorDetail) {
        const fieldPath = errorDetail.path?.join('.') ?? 'unknown';
        const message = errorDetail.message ?? 'Validation error';
        return next(createValidationError(message, fieldPath));
      }
    }
    
    // Ensure value is set properly
    req.body = value || {};
    next();
  };
};

const verifyWebhookSignature = (req: Request, res: Response, next: NextFunction) => {
  try {
    const signature = req.headers['x-veriff-signature'] as string;
    const payload = JSON.stringify(req.body || {});

    if (!signature) {
      return next(createAuthError('Missing webhook signature'));
    }

    if (!verificationService.verifyWebhookSignature(payload, signature)) {
      return next(createAuthError('Invalid webhook signature'));
    }
    
    next();
  } catch (error) {
    return next(createAuthError('Error verifying webhook signature'));
  }
};

// Routes

// 🚀 START VERIFICATION - Main endpoint to initiate verification
router.post(
  "/sessions/:customerId/start",
  validateBody(userDataSchema),
  asyncHandler(async (req: Request, res: Response) => {
    const { customerId } = req.params;
    
    // Validate customerId
    if (!customerId || customerId.trim().length === 0) {
      throw createValidationError('Customer ID is required and cannot be empty');
    }

    // Ensure req.body exists
    if (!req.body) {
      req.body = {};
    }
    
    const userData = { 
      firstName: req.body.firstName || '',
      lastName: req.body.lastName || '',
      email: req.body.email || undefined,
      documentNumber: req.body.documentNumber || undefined,
      lang: req.body.lang || 'en',
      features: req.body.features || ['selfid'],
      userId: customerId,
      vendorData: req.body.vendorData || ``
    };

    console.log(`🚀 Starting verification for customer: ${customerId}`);
    console.log('User data:', JSON.stringify(userData, null, 2));

    const session = await verificationService.createVerificationSession(userData);

    sendSuccessResponse(
      res,
      {
        success: true,
        customerId,
        session: {
          id: session.id,
          url: session.url,
          host: session.host,
          status: session.status
        },
        instructions: {
          message: "Redirect user to the provided URL to complete verification",
          url: session.url
        }
      },
      "Verification session created successfully",
      201
    );
  })
);

// Alternative endpoint - Create verification session with auto-generated customer ID
router.post(
  "/sessions/start",
  validateBody(userDataSchema),
  asyncHandler(async (req: Request, res: Response) => {
    // Ensure req.body exists
    if (!req.body) {
      req.body = {};
    }

    const customerId = `customer-${Date.now()}-${Math.random().toString(36).substring(7)}`;
    
    const userData = { 
      firstName: req.body.firstName || 'Test',
      lastName: req.body.lastName || 'User',
      email: req.body.email || undefined,
      documentNumber: req.body.documentNumber || undefined,
      lang: req.body.lang || 'en',
      features: req.body.features || ['selfid'],
      userId: customerId,
      vendorData: req.body.vendorData || `auto-${customerId}`
    };

    console.log(`🚀 Starting verification with auto-generated ID: ${customerId}`);
    console.log('User data:', JSON.stringify(userData, null, 2));

    const session = await verificationService.createVerificationSession(userData);

    sendSuccessResponse(
      res,
      {
        success: true,
        customerId,
        session: {
          id: session.id,
          url: session.url,
          host: session.host,
          status: session.status
        },
        instructions: {
          message: "Redirect user to the provided URL to complete verification",
          url: session.url
        }
      },
      "Verification session created successfully",
      201
    );
  })
);

// Webhook endpoint for Veriff
router.post(
  '/webhook',
  verifyWebhookSignature,
  asyncHandler(async (req: Request, res: Response) => {
    const payload = req.body || {};

    console.log('Received Veriff webhook:', {
      id: payload?.id,
      status: payload?.status,
      code: payload?.code,
      fullPayload: JSON.stringify(payload, null, 2)
    });

    const validation = verificationService.validateVerificationResult(payload);
    if (!validation.valid) {
      throw createValidationError(validation.error || 'Invalid verification result');
    }

    // Handle different verification statuses
    switch (payload.status) {
      case 'approved':
        console.log('✅ Verification approved:', payload.id);
        // Add your business logic here
        break;
      case 'declined':
        console.log('❌ Verification declined:', payload.id);
        // Add your business logic here
        break;
      case 'resubmission_requested':
        console.log('🔄 Resubmission requested:', payload.id);
        // Add your business logic here
        break;
      case 'expired':
        console.log('⏰ Session expired:', payload.id);
        // Add your business logic here
        break;
      default:
        console.log('🔍 Unknown status:', payload.status, 'for session:', payload.id);
    }

    sendSuccessResponse(res, { success: true, message: 'Webhook processed successfully' });
  })
);

// Get verification status/result
router.get(
  '/sessions/:sessionId',
  asyncHandler(async (req: Request, res: Response) => {
    const { sessionId } = req.params;
    
    if (!sessionId || sessionId.trim().length === 0) {
      throw createValidationError('Session ID is required and cannot be empty');
    }
    
    if (sessionId.length < 10) {
      throw createValidationError('Valid session ID is required (minimum 10 characters)');
    }

    console.log(`📋 Fetching verification result for session: ${sessionId}`);

    const result = await verificationService.getVerificationResult(sessionId);
    
    sendSuccessResponse(res, {
      success: true,
      verification: result
    });
  })
);

// Generate session token for frontend
router.post(
  '/token',
  validateBody(userDataSchema),
  asyncHandler(async (req: Request, res: Response) => {
    if (!req.body) {
      req.body = {};
    }

    const userData = {
      firstName: req.body.firstName || 'Test',
      lastName: req.body.lastName || 'User',
      email: req.body.email || undefined,
      userId: req.body.userId || `user-${Date.now()}`
    };
    
    console.log('🎫 Generating session token for user:', userData.firstName, userData.lastName);
    
    const token = verificationService.generateSessionToken(userData);

    sendSuccessResponse(res, { 
      token, 
      expiresIn: '1h' 
    }, 'Session token generated successfully');
  })
);

// Verify token
router.post(
  '/verify-token',
  validateBody(tokenSchema),
  asyncHandler(async (req: Request, res: Response) => {
    if (!req.body) {
      req.body = {};
    }

    const { token } = req.body;
    
    if (!token || typeof token !== 'string' || token.trim().length === 0) {
      throw createValidationError('Valid token is required');
    }
    
    console.log('🔐 Verifying session token');
    
    const verification = verificationService.verifySessionToken(token);
    if (!verification.valid) {
      throw createAuthError(`Invalid or expired token: ${verification.error || 'Unknown error'}`);
    }

    sendSuccessResponse(res, { 
      valid: true, 
      data: verification.data 
    }, 'Token is valid');
  })
);

// Health check
router.get('/health', asyncHandler(async (req: Request, res: Response) => {
  const healthStatus = await verificationService.healthCheck();
  
  res.status(healthStatus.healthy ? 200 : 503).json({
    status: healthStatus.healthy ? 'healthy' : 'unhealthy',
    service: 'veriff-verification',
    timestamp: new Date().toISOString(),
    version: '1.0.0',
    environment: config.NODE_ENV || 'development',
    uptime: process.uptime(),
    ...healthStatus
  });
}));

// Configuration status
router.get('/config', asyncHandler(async (req: Request, res: Response) => {
  const configStatus = verificationService.getConfigStatus();
  
  sendSuccessResponse(res, {
    configured: configStatus.configured,
    missing: configStatus.missing,
    environment: config.IS_PRODUCTION ? 'production' : 'sandbox'
  });
}));

// Test endpoint - for debugging purposes
router.get('/test', asyncHandler(async (req: Request, res: Response) => {
  sendSuccessResponse(res, {
    message: 'Veriff routes are working',
    timestamp: new Date().toISOString(),
    environment: config.NODE_ENV || 'development'
  });
}));

export default router;