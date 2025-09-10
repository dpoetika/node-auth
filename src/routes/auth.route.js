import express from "express"
import {
  register,
  login
} from '../controllers/auth.controller.js';


const authRoutes = express.Router();

// Public routes
authRoutes.post('/register',
    register
);

authRoutes.post('/login',
    login
);

export default authRoutes