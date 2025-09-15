import express from "express"
import authRoutes from "./auth.route.js"
import { apiLimiter } from "../config/security.js";

const router = express.Router();

router.use(apiLimiter)

const VERSION = process.env.APP_VERSION ?? process.env.npm_package_version ?? '1.0.0';
const ENV = process.env.NODE_ENV ?? 'development';

// Health check endpoint
router.get('/health', (req, res) => {
  res.status(200).json({
    success: true,
    message: 'API is running',
    timestamp: new Date().toISOString(),
    environment: ENV,
    version: VERSION
  });
});

// API info endpoint
router.get('/info', (req, res) => {
  res.status(200).json({
    success: true,
    data: {
      name: 'node-auth',
      version:VERSION,
      description: 'Secure Node.js Backend API',
      environment: ENV,
      timestamp: new Date().toISOString(),
      endpoints: {
        auth: '/api/auth',
        health: '/api/health',
        info: '/api/info'
      }
    }
  });
});

// Route mounting
router.use('/auth', authRoutes);
router.use((req, res) => {
  res.status(404).json({
    success: false,
    error: `${req.originalUrl} endpoint not found`
  });
});

export default router;