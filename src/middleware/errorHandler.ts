import { Request, Response, NextFunction } from 'express';
import { config } from '../config/config.js';
// import { ApiError, VerificationError } from '../types/index.js';

// Custom error classes
export class ValidationError extends Error {
  constructor(message: string, public field?: string) {
    super(message);
    this.name = 'ValidationError';
  }
}

export class AuthenticationError extends Error {
  constructor(message: string = 'Authentication failed') {
    super(message);
    this.name = 'AuthenticationError';
  }
}

export class RateLimitError extends Error {
  constructor(message: string = 'Rate limit exceeded') {
    super(message);
    this.name = 'RateLimitError';
  }
}

export class ConfigurationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ConfigurationError';
  }
}

export class ExternalServiceError extends Error {
  constructor(message: string, public service?: string, public statusCode?: number) {
    super(message);
    this.name = 'ExternalServiceError';
  }
}

// Error status code mapping
const getStatusCode = (error: Error): number => {
  switch (error.name) {
    case 'ValidationError':
      return 400;
    case 'AuthenticationError':
      return 401;
    case 'RateLimitError':
      return 429;
    case 'ConfigurationError':
      return 503;
    case 'ExternalServiceError':
      return (error as ExternalServiceError).statusCode || 502;
    default:
      if (error.message.includes('not found')) return 404;
      if (error.message.includes('unauthorized')) return 401;
      if (error.message.includes('forbidden')) return 403;
      return 500;
  }
};

// Get error type for logging and monitoring
const getErrorType = (error: Error): string => {
  if (error.name) return error.name;
  if (error.message.includes('ECONNREFUSED')) return 'ConnectionError';
  if (error.message.includes('timeout')) return 'TimeoutError';
  if (error.message.includes('ENOTFOUND')) return 'DNSError';
  return 'UnknownError';
};

// Sanitize error message for production
const sanitizeErrorMessage = (error: Error, isDevelopment: boolean): string => {
  if (isDevelopment) {
    return error.message;
  }

  // In production, don't expose internal error details
  switch (error.name) {
    case 'ValidationError':
      return error.message; // Validation errors are safe to expose
    case 'AuthenticationError':
      return 'Authentication failed';
    case 'RateLimitError':
      return 'Too many requests. Please try again later.';
    case 'ConfigurationError':
      return 'Service temporarily unavailable';
    case 'ExternalServiceError':
      return 'External service error. Please try again later.';
    default:
      return 'An internal error occurred';
  }
};

// Log error details
const logError = (error: Error, req: Request, additionalContext?: any) => {
  const errorInfo = {
    name: error.name,
    message: error.message,
    stack: error.stack,
    type: getErrorType(error),
    statusCode: getStatusCode(error),
    request: {
      method: req.method,
      url: req.url,
      ip: req.ip,
      userAgent: req.get('User-Agent'),
      timestamp: new Date().toISOString()
    },
    ...additionalContext
  };

  // Log based on error severity
  if (getStatusCode(error) >= 500) {
    console.error('❌ Server Error:', JSON.stringify(errorInfo, null, 2));
  } else if (getStatusCode(error) >= 400) {
    console.warn('⚠️  Client Error:', JSON.stringify(errorInfo, null, 2));
  } else {
    console.info('ℹ️  Info:', JSON.stringify(errorInfo, null, 2));
  }
};

// Main error handler middleware
export const errorHandler = (
  error: Error ,
  req: Request,
  res: Response,
  next: NextFunction
): void => {
  // Log the error
  // Ensure error has 'name' and 'message' properties for logging
  const normalizedError: Error = {
    name: (error as any).name || 'Error',
    message: (error as any).message || 'Unknown error',
    stack: (error as any).stack
  };
  logError(normalizedError, req);

  const isDevelopment = config.NODE_ENV === 'development';
  const statusCode = getStatusCode(normalizedError);
  const errorType = getErrorType(normalizedError);
  const sanitizedMessage = sanitizeErrorMessage(normalizedError, isDevelopment);

  // Prepare error response
  const errorResponse: any = {
    error: true,
    message: sanitizedMessage,
    type: errorType,
    timestamp: new Date().toISOString()
  };

  // Add request ID if available
  if (req.headers['x-request-id']) {
    errorResponse.requestId = req.headers['x-request-id'];
  }

  // Add development-specific details
  if (isDevelopment) {
    errorResponse.details = {
      originalMessage: error.message,
      stack: 'stack' in error ? (error as Error).stack : undefined,
      name: 'name' in error ? (error as any).name : undefined
    };
  }

  // Add specific error fields
  if (error instanceof ValidationError && error.field) {
    errorResponse.field = error.field;
  }

  if (error instanceof ExternalServiceError && error.service) {
    errorResponse.service = error.service;
  }

  // Add rate limiting headers
  if (error instanceof RateLimitError) {
    res.set({
      'Retry-After': '60',
      'X-RateLimit-Limit': config.RATE_LIMIT_MAX_REQUESTS.toString(),
      'X-RateLimit-Remaining': '0',
      'X-RateLimit-Reset': (Date.now() + config.RATE_LIMIT_WINDOW_MS).toString()
    });
  }

  // Send error response
  res.status(statusCode).json(errorResponse);
};

// 404 Not Found handler
export const notFoundHandler = (req: Request, res: Response, next: NextFunction): void => {
  const error = new Error(`Route ${req.method} ${req.path} not found`);
  error.name = 'NotFoundError';
  
  const errorResponse = {
    error: true,
    message: 'Route not found',
    type: 'NotFoundError',
    timestamp: new Date().toISOString(),
    path: req.path,
    method: req.method
  };

  console.warn('⚠️  Route not found:', {
    method: req.method,
    url: req.url,
    ip: req.ip,
    userAgent: req.get('User-Agent')
  });

  res.status(404).json(errorResponse);
};

// Async error wrapper
export const asyncHandler = (fn: (req: Request, res: Response, next: NextFunction) => Promise<any>) => {
  return (req: Request, res: Response, next: NextFunction) => {
    Promise.resolve(fn(req, res, next)).catch(next);
  };
};

// Validation error helper
export const createValidationError = (message: string, field?: string): ValidationError => {
  return new ValidationError(message, field);
};

// Authentication error helper
export const createAuthError = (message?: string): AuthenticationError => {
  return new AuthenticationError(message);
};

// Rate limit error helper
export const createRateLimitError = (message?: string): RateLimitError => {
  return new RateLimitError(message);
};

// Configuration error helper
export const createConfigError = (message: string): ConfigurationError => {
  return new ConfigurationError(message);
};

// External service error helper
export const createServiceError = (message: string, service?: string, statusCode?: number): ExternalServiceError => {
  return new ExternalServiceError(message, service, statusCode);
};

// Error response helpers
export const sendErrorResponse = (
  res: Response,
  statusCode: number,
  message: string,
  type?: string,
  additionalData?: any
) => {
  const errorResponse = {
    error: true,
    message,
    type: type || 'Error',
    timestamp: new Date().toISOString(),
    ...additionalData
  };

  res.status(statusCode).json(errorResponse);
};

export const sendSuccessResponse = (
  res: Response,
  data?: any,
  message?: string,
  statusCode: number = 200
) => {
  const successResponse = {
    success: true,
    message: message || 'Operation completed successfully',
    timestamp: new Date().toISOString(),
    ...(data && { data })
  };

  res.status(statusCode).json(successResponse);
};

// Unhandled promise rejection handler
export const setupGlobalErrorHandlers = () => {
  process.on('unhandledRejection', (reason: any, promise: Promise<any>) => {
    console.error('❌ Unhandled Promise Rejection:', {
      reason: reason?.message || reason,
      stack: reason?.stack,
      promise: promise.toString()
    });
    
    // In production, you might want to exit the process
    if (config.NODE_ENV === 'production') {
      console.error('🚨 Shutting down due to unhandled promise rejection');
      process.exit(1);
    }
  });

  process.on('uncaughtException', (error: Error) => {
    console.error('❌ Uncaught Exception:', {
      name: error.name,
      message: error.message,
      stack: error.stack
    });
    
    // Always exit on uncaught exceptions
    console.error('🚨 Shutting down due to uncaught exception');
    process.exit(1);
  });
};

// Request timeout handler
export const timeoutHandler = (timeoutMs: number = 30000) => {
  return (req: Request, res: Response, next: NextFunction) => {
    const timeout = setTimeout(() => {
      const error = new Error(`Request timeout after ${timeoutMs}ms`);
      error.name = 'TimeoutError';
      next(error);
    }, timeoutMs);

    // Clear timeout when response finishes
    res.on('finish', () => {
      clearTimeout(timeout);
    });

    next();
  };
};

// Health check error handler
export const healthCheckErrorHandler = (error: any) => {
  return {
    healthy: false,
    message: 'Health check failed',
    error: config.NODE_ENV === 'development' ? error.message : 'Internal error',
    timestamp: new Date().toISOString()
  };
};