import express from "express"
const {
  register,
  login
} = require('../controllers/authController');


const router = express.Router();

// Public routes
router.post('/register',
    conditionalAuthLimiter,
    sanitizeInput,
    validateUserRegistration,
    register
);

router.post('/login',
    conditionalAuthLimiter,
    conditionalBruteForce,
    sanitizeInput,
    validateUserLogin,
    login
);

export default router