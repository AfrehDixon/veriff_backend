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

// Validation Schemas
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
  token: Joi.string().optional()
});

const validateBody = (schema: Joi.ObjectSchema) => {
  return (req: Request, res: Response, next: NextFunction) => {
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
    
    req.body = value || {};
    next();
  };
};

// CORRECTED webhook signature verification middleware
const verifyWebhookSignature = (req: Request, res: Response, next: NextFunction) => {
  try {
    console.log('=== WEBHOOK SIGNATURE MIDDLEWARE ===');
    
    // Get signature from headers (try multiple possible header names)
    const signature = (req.headers['x-veriff-signature'] || 
                     req.headers['x-signature'] || 
                     req.headers['x-webhook-signature']) as string;
    
    console.log('All headers:', Object.keys(req.headers));
    console.log('Signature header value:', signature);
    
    if (!signature) {
      console.error('❌ Missing webhook signature in headers');
      return next(createAuthError('Missing webhook signature'));
    }

    // For webhook routes, req.body should be a Buffer (raw body)
    const rawBody = req.body;
    console.log('Raw body type:', typeof rawBody);
    console.log('Raw body is Buffer:', Buffer.isBuffer(rawBody));
    
    if (!rawBody) {
      console.error('❌ Missing request body for signature verification');
      return next(createAuthError('Missing request body'));
    }

    // Verify the signature using the raw body
    const isValid = verificationService.verifyWebhookSignature(rawBody, signature);
    
    if (!isValid) {
      console.error('❌ Invalid webhook signature');
      return next(createAuthError('Invalid webhook signature'));
    }
    
    console.log('✅ Webhook signature verified successfully');
    
    // Parse the JSON body for further processing
    try {
      const jsonBody = Buffer.isBuffer(rawBody) ? JSON.parse(rawBody.toString()) : rawBody;
      req.body = jsonBody;
      console.log('✅ JSON body parsed successfully');
    } catch (parseError) {
      console.error('❌ Failed to parse JSON body:', parseError);
      return next(createAuthError('Invalid JSON in request body'));
    }
    
    next();
  } catch (error) {
    console.error('❌ Error in webhook signature verification:', error);
    return next(createAuthError('Error verifying webhook signature'));
  }
};

// Test endpoints (for debugging)
router.get('/webhook/test', asyncHandler(async (req: Request, res: Response) => {
  sendSuccessResponse(res, {
    message: 'Webhook endpoint is reachable',
    timestamp: new Date().toISOString(),
    server: 'running',
    environment: config.NODE_ENV || 'development'
  });
}));

router.post('/webhook/test', asyncHandler(async (req: Request, res: Response) => {
  console.log('Test webhook received:', req.body);
  sendSuccessResponse(res, {
    message: 'Test webhook received successfully',
    body: req.body,
    timestamp: new Date().toISOString()
  });
}));

// Routes

// 🚀 START VERIFICATION - Main endpoint to initiate verification
router.post(
  "/sessions/:customerId/start",
  validateBody(userDataSchema),
  asyncHandler(async (req: Request, res: Response) => {
    const { customerId } = req.params;
    
    if (!customerId || customerId.trim().length === 0) {
      throw createValidationError('Customer ID is required and cannot be empty');
    }

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
      vendorData: req.body.vendorData || customerId // Use customerId as vendorData
    };

    console.log(`🚀 Starting verification for customer: ${customerId}`);
    console.log('User data:', JSON.stringify(userData, null, 2));
    console.log('VendorData will be:', userData.vendorData);

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
    if (!req.body) {
      req.body = {};
    }

    const customerId = `customer-${Date.now()}-${Math.random().toString(36).substring(7)}`;
    
    const userData = { 
      firstName: req.body.firstName || '',
      lastName: req.body.lastName || '',
      email: req.body.email || undefined,
      documentNumber: req.body.documentNumber || undefined,
      lang: req.body.lang || 'en',
      features: req.body.features || ['selfid'],
      userId: customerId,
      vendorData: req.body.vendorData || customerId
    };

    console.log(`🚀 Starting verification with auto-generated ID: ${customerId}`);
    console.log('User data:', JSON.stringify(userData, null, 2));
    console.log('VendorData will be:', userData.vendorData);

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

// 🔐 WEBHOOK ENDPOINT WITH SIGNATURE VERIFICATION
router.post(
  '/webhook',
  verifyWebhookSignature, // This middleware will handle signature verification
  asyncHandler(async (req: Request, res: Response) => {
    try {
      console.log('=== VERIFIED WEBHOOK RECEIVED ===');
      const payload = req.body || {};

      console.log('Webhook data:', {
        id: payload?.verification?.id,
        status: payload?.verification?.status,
        code: payload?.verification?.code,
        vendorData: payload?.verification?.vendorData,
      });

      const validation = verificationService.validateVerificationResult(payload);
      if (!validation.valid) {
        throw createValidationError(validation.error || 'Invalid verification result');
      }

      // Extract customerId from vendorData
      const customerId = payload?.verification?.vendorData;
      const sessionId = payload?.verification?.id;
      const status = payload?.verification?.status;

      console.log(`Processing webhook for customer: ${customerId}, session: ${sessionId}, status: ${status}`);

      // Handle different verification statuses
      switch (status) {
        case 'approved':
          console.log(`✅ Verification approved for customer: ${customerId}`);
          // TODO: Add your database update logic here
          break;
        case 'declined':
          console.log(`❌ Verification declined for customer: ${customerId}`);
          // TODO: Add your database update logic here
          break;
        case 'resubmission_requested':
          console.log(`🔄 Resubmission requested for customer: ${customerId}`);
          // TODO: Add your database update logic here
          break;
        case 'expired':
          console.log(`⏰ Session expired for customer: ${customerId}`);
          // TODO: Add your database update logic here
          break;
        default:
          console.log(`🔍 Status: ${status} for customer: ${customerId}`);
      }

      sendSuccessResponse(res, { 
        success: true, 
        message: 'Webhook processed successfully',
        customerId: customerId,
        sessionId: sessionId,
        status: status 
      });

    } catch (error) {
      console.error('Webhook processing error:', error);
      throw error; // Re-throw to be handled by error middleware
    }
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