import express from "express"
const router = express.Router();

// Health check endpoint
router.get('/health', (req, res) => {
  res.status(200).json({
    success: true,
    message: 'API is running',
    timestamp: new Date().toISOString(),
    environment: process.env.NODE_ENV,
    version: '1.0.0'
  });
});

// API info endpoint
router.get('/info', (req, res) => {
  res.status(200).json({
    success: true,
    data: {
      name: 'Secure Node.js Backend API',
      version: '1.0.0',
      description: 'Güvenli Node.js Backend API',
      environment: process.env.NODE_ENV,
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
//router.use('/auth', authRoutes);

 
export default router;