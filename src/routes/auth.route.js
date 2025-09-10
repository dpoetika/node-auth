import express from "express"
import {
  register,
  login,
  getMe,
  logout
} from '../controllers/auth.controller.js';
import { authenticate } from "../middlewares/auth.middleware.js";

const authRoutes = express.Router();

// Public routes
authRoutes.post('/register',
    register
);

authRoutes.post('/login',
    login
);

// Protected routes
authRoutes.use(authenticate);

authRoutes.get('/me', getMe);
authRoutes.post('/logout', logout);


export default authRoutes