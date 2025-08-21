import { Request, Response, NextFunction } from 'express';

// Custom error classes
export class ValidationError extends Error {
  public field?: string;

  constructor(message: string, field?: string) {
    super(message);
    this.name = 'ValidationError';
    this.field = field;
  }
}

export class AuthenticationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'AuthenticationError';
  }
}

export class AuthorizationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'AuthorizationError';
  }
}

export class NotFoundError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'NotFoundError';
  }
}

export class ConflictError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ConflictError';
  }
}

export class ExternalServiceError extends Error {
  public service?: string;
  public statusCode?: number;

  constructor(message: string, service?: string, statusCode?: number) {
    super(message);
    this.name = 'ExternalServiceError';
    this.service = service;
    this.statusCode = statusCode;
  }
}

// Error handling middleware
export const errorHandler = (err: Error, req: Request, res: Response, next: NextFunction) => {
  console.error(err.stack);

  if (err instanceof ValidationError) {
    return res.status(400).json({ 
      error: err.message, 
      field: err.field 
    });
  }

  if (err instanceof AuthenticationError) {
    return res.status(401).json({ 
      error: err.message 
    });
  }

  if (err instanceof AuthorizationError) {
    return res.status(403).json({ 
      error: err.message 
    });
  }

  if (err instanceof NotFoundError) {
    return res.status(404).json({ 
      error: err.message 
    });
  }

  if (err instanceof ConflictError) {
    return res.status(409).json({ 
      error: err.message 
    });
  }

  if (err instanceof ExternalServiceError) {
    return res.status(err.statusCode || 502).json({ 
      error: `External service error: ${err.message}`, 
      service: err.service 
    });
  }

  // Generic server error
  return res.status(500).json({ 
    error: 'Internal server error' 
  });
};

// 404 Not Found handler
export const notFoundHandler = (req: Request, res: Response, next: NextFunction) => {
  res.status(404).json({ 
    error: 'Not found' 
  });
};