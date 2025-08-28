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

interface VerificationStatusResponse {
  customerId: string;
  status: 'pending' | 'processing' | 'completed' | 'failed' | 'expired' | 'abandoned' | 'unknown';
  sessionId?: string;
  result?: any;
  lastUpdated: string;
  canRedirect: boolean;
  redirectTo?: string;
}

const verificationStatusStore = new Map<string, VerificationStatusResponse>();

const userDataSchema = Joi.object({
  firstName: Joi.string().min(1).max(100).optional(),
  lastName: Joi.string().min(1).max(100).optional(),
  email: Joi.string().email().optional(),
  phone: Joi.string().optional(),
  documentNumber: Joi.string().optional(),
  country: Joi.string().optional(),
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

const verifyWebhookSignature = (req: Request, res: Response, next: NextFunction) => {
  try {
    const signature = (req.headers['x-veriff-signature'] || 
                     req.headers['x-signature'] || 
                     req.headers['x-webhook-signature']) as string;
    
    if (!signature) {
      return next(createAuthError('Missing webhook signature'));
    }

    const rawBody = req.body;
    
    if (!rawBody) {
      return next(createAuthError('Missing request body'));
    }

    const isValid = verificationService.verifyWebhookSignature(rawBody, signature);
    
    if (!isValid) {
      return next(createAuthError('Invalid webhook signature'));
    }
    
    try {
      const jsonBody = Buffer.isBuffer(rawBody) ? JSON.parse(rawBody.toString()) : rawBody;
      req.body = jsonBody;
    } catch (parseError) {
      return next(createAuthError('Invalid JSON in request body'));
    }
    
    next();
  } catch (error) {
    return next(createAuthError('Error verifying webhook signature'));
  }
};

function mapWebhookStatusToPollingStatus(webhookStatus: string): VerificationStatusResponse['status'] {
  switch (webhookStatus) {
    case 'approved':
      return 'completed';
    case 'declined':
      return 'failed';
    case 'expired':
      return 'expired';
    case 'abandoned':
      return 'abandoned';
    case 'resubmission_requested':
      return 'processing';
    case 'submitted':
      return 'processing';
    default:
      return 'unknown';
  }
}

router.get('/webhook/test', asyncHandler(async (req: Request, res: Response) => {
  sendSuccessResponse(res, {
    message: 'Webhook endpoint is reachable',
    timestamp: new Date().toISOString(),
    server: 'running',
    environment: config.NODE_ENV || 'development'
  });
}));

router.post('/webhook/test', asyncHandler(async (req: Request, res: Response) => {
  sendSuccessResponse(res, {
    message: 'Test webhook received successfully',
    body: req.body,
    timestamp: new Date().toISOString()
  });
}));



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
      email: req.body.email || undefined,
      phone: req.body.phone || undefined,
      documentNumber: req.body.documentNumber || undefined,
      country: req.body.country || undefined,
      lang: req.body.lang || 'en',
      features: req.body.features || ['selfid'],
      vendorData: req.body.vendorData || customerId
    };

    const initialStatus: VerificationStatusResponse = {
      customerId,
      status: 'pending',
      lastUpdated: new Date().toISOString(),
      canRedirect: false
    };
    verificationStatusStore.set(customerId, initialStatus);

    // Ensure token is a string or undefined
    const tokenHeader = req.headers['authorization'] || req.headers['Authorization'];
    const token = Array.isArray(tokenHeader) ? tokenHeader[0] : tokenHeader;

    const session = await verificationService.createVerificationSession(customerId, userData, token);

    const processingStatus: VerificationStatusResponse = {
      customerId,
      status: 'processing',
      sessionId: session.id,
      lastUpdated: new Date().toISOString(),
      canRedirect: false
    };
    verificationStatusStore.set(customerId, processingStatus);

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



router.get(
  '/status/:customerId',
  asyncHandler(async (req: Request, res: Response) => {
    const { customerId } = req.params;
    
    if (!customerId || customerId.trim().length === 0) {
      throw createValidationError('Customer ID is required and cannot be empty');
    }

    try {
      let statusResponse = verificationStatusStore.get(customerId);
      
      if (!statusResponse) {
        statusResponse = {
          customerId,
          status: 'pending',
          lastUpdated: new Date().toISOString(),
          canRedirect: false
        };
      }

      const finalStatuses = ['completed', 'failed', 'expired', 'abandoned'];
      statusResponse.canRedirect = finalStatuses.includes(statusResponse.status);
      
      if (statusResponse.canRedirect) {
        switch (statusResponse.status) {
          case 'completed':
            statusResponse.redirectTo = '/verification/success';
            break;
          case 'failed':
            statusResponse.redirectTo = '/verification/failed';
            break;
          case 'expired':
            statusResponse.redirectTo = '/verification/expired';
            break;
          case 'abandoned':
            statusResponse.redirectTo = '/verification/abandoned';
            break;
        }
      }

      sendSuccessResponse(res, statusResponse);
    } catch (error) {
      const defaultResponse: VerificationStatusResponse = {
        customerId,
        status: 'unknown',
        lastUpdated: new Date().toISOString(),
        canRedirect: false
      };
      
      sendSuccessResponse(res, defaultResponse);
    }
  })
);

router.delete(
  '/status/:customerId',
  asyncHandler(async (req: Request, res: Response) => {
    const { customerId } = req.params;
    
    if (!customerId || customerId.trim().length === 0) {
      throw createValidationError('Customer ID is required and cannot be empty');
    }
    
    verificationStatusStore.delete(customerId);
    
    sendSuccessResponse(res, {
      message: 'Verification status reset successfully',
      customerId
    });
  })
);

router.post(
  '/webhook',
  verifyWebhookSignature,
  asyncHandler(async (req: Request, res: Response) => {
    try {
      const payload = req.body || {};

      const validation = verificationService.validateVerificationResult(payload);
      if (!validation.valid) {
        throw createValidationError(validation.error || 'Invalid verification result');
      }

      const customerId = payload?.verification?.vendorData;
      const sessionId = payload?.verification?.id;
      const status = payload?.verification?.status;
      const verification = payload?.verification;

      const statusResponse: VerificationStatusResponse = {
        customerId,
        status: mapWebhookStatusToPollingStatus(status),
        sessionId,
        result: verification,
        lastUpdated: new Date().toISOString(),
        canRedirect: false
      };

      verificationStatusStore.set(customerId, statusResponse);

      sendSuccessResponse(res, { 
        success: true, 
        message: 'Webhook processed successfully',
        customerId: customerId,
        sessionId: sessionId,
        status: status,
        mappedStatus: statusResponse.status
      });
    } catch (error) {
      throw error;
    }
  })
);

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

    // Ensure token is a string or undefined
    const tokenHeader = req.headers['authorization'] || req.headers['Authorization'];
    const token = Array.isArray(tokenHeader) ? tokenHeader[0] : tokenHeader;

    const result = await verificationService.getVerificationResult(sessionId, token);
    
    sendSuccessResponse(res, {
      success: true,
      verification: result
    });
  })
);

router.post(
  '/token',
  validateBody(userDataSchema),
  asyncHandler(async (req: Request, res: Response) => {
    if (!req.body) {
      req.body = {};
    }

    const userData = {
      firstName: req.body.firstName || '',
      lastName: req.body.lastName || '',
      email: req.body.email || undefined,
      userId: req.body.userId || `user-${Date.now()}`
    };
    
    const token = verificationService.generateSessionToken(userData);

    sendSuccessResponse(res, { 
      token, 
      expiresIn: '1h' 
    }, 'Session token generated successfully');
  })
);

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

router.get('/config', asyncHandler(async (req: Request, res: Response) => {
  const configStatus = verificationService.getConfigStatus();
  
  sendSuccessResponse(res, {
    configured: configStatus.configured,
    missing: configStatus.missing,
    environment: config.IS_PRODUCTION ? 'production' : 'sandbox'
  });
}));

router.get('/test', asyncHandler(async (req: Request, res: Response) => {
  sendSuccessResponse(res, {
    message: 'Veriff routes are working',
    timestamp: new Date().toISOString(),
    environment: config.NODE_ENV || 'development'
  });
}));

export default router;