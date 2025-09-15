import express from "express"
import {
  register,
  login,
  getMe,
  logout,
  forgotPassword,
  resetPassword,
  verifyEmail
} from '../controllers/auth.controller.js';
import { authenticate } from "../middlewares/auth.middleware.js";
import { authLimiter } from "../config/security.js";

// Disable rate limiting in test environment


const authRoutes = express.Router();

authRoutes.use(authLimiter)

// Public routes
authRoutes.post('/register',
  register
);

authRoutes.post('/login',
  login
);

authRoutes.post('/forgot-password',
  forgotPassword
);

authRoutes.put('/reset-password/:token',
  resetPassword
);

authRoutes.get('/verify-email/:token',
  verifyEmail
);

// Protected routes
authRoutes.use(authenticate);

authRoutes.get('/me', getMe);
authRoutes.post('/logout', logout);


export default authRoutes