import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import morgan from 'morgan';
import dotenv from 'dotenv';
import { config } from './config/config';
import verificationRoutes from './routes/verificationRoutes';
import { errorHandler, notFoundHandler } from './middleware/errorHandler';

// Load environment variables
dotenv.config();

const app = express();
const PORT = config.PORT;


// IMPORTANT: Handle raw body for webhook signature verification
app.use('/api/verification/webhook', express.raw({ type: 'application/json' }));

// Security middleware
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      scriptSrc: ["'self'"],
      imgSrc: ["'self'", "data:", "https:"],
    },
  },
  crossOriginEmbedderPolicy: false
}));

// CORS configuration
app.use(cors({
  origin: '*',
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Checkin-Signature']
}));

// Logging middleware
app.use(morgan(config.NODE_ENV === 'production' ? 'combined' : 'dev'));

// Body parsing middleware
app.use(express.json({ 
  limit: config.MAX_FILE_SIZE,
  verify: (req: any, res, buf) => {
    req.rawBody = buf;
  }
}));
app.use(express.urlencoded({ 
  extended: true, 
  limit: config.MAX_FILE_SIZE 
}));



// Rate limiting middleware (simple implementation)
const rateLimitMap = new Map();

app.use((req:any, res:any, next) => {
  const ip = req.ip || req.connection.remoteAddress || 'unknown';
  const now = Date.now();
  const windowStart = now - config.RATE_LIMIT_WINDOW_MS;
  
  if (!rateLimitMap.has(ip)) {
    rateLimitMap.set(ip, []);
  }
  
  const requests = rateLimitMap.get(ip).filter((time: number) => time > windowStart);
  
  if (requests.length >= config.RATE_LIMIT_MAX_REQUESTS) {
    return res.status(429).json({
      error: 'Too many requests',
      retryAfter: Math.ceil(config.RATE_LIMIT_WINDOW_MS / 1000)
    });
  }
  
  requests.push(now);
  rateLimitMap.set(ip, requests);
  next();
});

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({
    status: 'healthy',
    service: 'checkin-verification-backend',
    version: '1.0.0',
    timestamp: new Date().toISOString(),
    environment: config.NODE_ENV,
    uptime: process.uptime()
  });
});

// API routes
app.use('/api/verification', verificationRoutes);

// Root endpoint
app.get('/', (req, res) => {
  res.json({
    message: 'Checkin.com Verification API',
    version: '1.0.0',
    status: 'running',
    documentation: '/api/verification/health',
    endpoints: {
      health: '/health',
      verification: '/api/verification',
      webhook: '/api/verification/webhook'
    }
  });
});

// Error handling middleware (must be last)
app.use(notFoundHandler);
app.use(errorHandler);

// Graceful shutdown handling
process.on('SIGTERM', () => {
  console.log('🛑 SIGTERM received. Shutting down gracefully...');
  process.exit(0);
});

process.on('SIGINT', () => {
  console.log('🛑 SIGINT received. Shutting down gracefully...');
  process.exit(0);
});

const host = config.HOST || "0.0.0.0";

// Start server
app.listen(PORT, host,() => {
  console.log(`🚀 Server running on port ${PORT}`);
  console.log(`📝 Environment: ${config.NODE_ENV}`);
  console.log(`🔗 API available at: http://0.0.0.0:${PORT}/api/verification`);
  console.log(`💚 Health check: http://localhost:${PORT}/health`);
  

});

export default app;