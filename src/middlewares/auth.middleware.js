import jwt from "jsonwebtoken"
import User from "../models/User.js";

export const authenticate = async (req, res, next) => {
  try {
    let token;

    // Get token from header
    if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
      token = req.headers.authorization.split(' ')[1];
    }
    // from cookies
    else if (req.cookies && req.cookies.token) {
      token = req.cookies.token;
    }

    if (!token) {
      return res.status(401).json({
        success: false,
        error: 'You need to login first'
      });
    }

    try {
      // verify token
      const decoded = jwt.verify(token, process.env.JWT_SECRET);
      
      // Get user by id
      const user = await User.findById(decoded.id).select('-password');
      
      if (!user) {
        return res.status(401).json({
          success: false,
          error: 'User not found'
        });
      }

      // Check user if active
      if (!user.isActive) {
        return res.status(401).json({
          success: false,
          error: 'Hesabınız deaktif edilmiştir'
        });
      }

      // Check if token created after password change
      if (user.passwordChangedAt && decoded.iat < user.passwordChangedAt.getTime() / 1000) {
        return res.status(401).json({
          success: false,
          error: 'Password changed. Please login'
        });
      }

      req.user = user;
      next();
    } catch (error) {
      console.log('JWT verification error:', error);
      return res.status(401).json({
        success: false,
        error: 'Invalid token'
      });
    }
  } catch (error) {
    console.log('Authentication error:', error);
    return res.status(500).json({
      success: false,
      error: 'Server Error'
    });
  }
};
