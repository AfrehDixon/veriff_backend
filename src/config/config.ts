import dotenv from 'dotenv';

dotenv.config();

interface Config {
  NODE_ENV: string;
  PORT: number;
  HOST: string

  // Veriff Configuration
  VERIFF_API_KEY: string;
  VERIFF_WEBHOOK_SECRET: string;
  VERIFF_CALLBACK_URL: string;

  // Security Configuration
  JWT_SECRET: string;

  // Rate Limiting Configuration
  RATE_LIMIT_WINDOW_MS: number;
  RATE_LIMIT_MAX_REQUESTS: number;

  // File Upload Configuration
  MAX_FILE_SIZE: string;
  ALLOWED_FILE_TYPES: string[];

  // CORS Configuration
  CORS_ORIGINS: string[];

  // Logging Configuration
  LOG_LEVEL: string;
  LOG_FILE: string;

  // Database Configuration (optional)
  DATABASE_URL?: string;
  REDIS_URL?: string;

  // Computed properties
  IS_PRODUCTION: boolean;
}

const parseArray = (value: string | undefined, defaultValue: string[] = []): string[] => {
  if (!value) return defaultValue;
  return value.split(',').map(item => item.trim()).filter(Boolean);
};

const parseNumber = (value: string | undefined, defaultValue: number): number => {
  const parsed = parseInt(value || '', 10);
  return isNaN(parsed) ? defaultValue : parsed;
};

export const config: Config = {
  NODE_ENV: process.env.NODE_ENV || "development",
  PORT: parseNumber(process.env.PORT, 3000),
  HOST: process.env.HOST || "0.0.0.0",

  VERIFF_API_KEY: process.env.VERIFF_API_KEY || "",
  VERIFF_WEBHOOK_SECRET: process.env.VERIFF_WEBHOOK_SECRET || "",
  VERIFF_CALLBACK_URL:
    process.env.VERIFF_CALLBACK_URL ||
    "https://your-domain.com/api/verification/webhook",

  JWT_SECRET:
    process.env.JWT_SECRET ||
    "your-super-secret-jwt-key-change-this-in-production",

  RATE_LIMIT_WINDOW_MS: parseNumber(
    process.env.RATE_LIMIT_WINDOW_MS,
    15 * 60 * 1000
  ),
  RATE_LIMIT_MAX_REQUESTS: parseNumber(
    process.env.RATE_LIMIT_MAX_REQUESTS,
    100
  ),

  MAX_FILE_SIZE: process.env.MAX_FILE_SIZE || "10mb",
  ALLOWED_FILE_TYPES: parseArray(process.env.ALLOWED_FILE_TYPES, [
    "image/jpeg",
    "image/png",
    "image/webp",
    "image/tiff",
  ]),

  CORS_ORIGINS: parseArray(process.env.CORS_ORIGINS, [
    "http://localhost:3000",
    "http://localhost:3001",
  ]),

  LOG_LEVEL: process.env.LOG_LEVEL || "info",
  LOG_FILE: process.env.LOG_FILE || "logs/app.log",

  DATABASE_URL: process.env.DATABASE_URL,
  REDIS_URL: process.env.REDIS_URL,

  get IS_PRODUCTION() {
    return this.NODE_ENV === "production";
  },
};

export const validateConfig = (): { valid: boolean; errors: string[] } => {
  const errors: string[] = [];

  const requiredVars = ['VERIFF_API_KEY', 'VERIFF_WEBHOOK_SECRET'];
  
  for (const varName of requiredVars) {
    const key = varName as keyof Config;
    if (!config[key]) errors.push(`Missing required environment variable: ${varName}`);
  }

  if (config.IS_PRODUCTION && config.JWT_SECRET === 'your-super-secret-jwt-key-change-this-in-production') {
    errors.push('JWT_SECRET must be changed in production');
  }

  return { valid: errors.length === 0, errors };
};

export default config;