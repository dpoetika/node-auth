import jwt from "jsonwebtoken"
import User from "../models/User.js";

if (!process.env.JWT_SECRET) {
  console.warn('JWT_SECRET is not set; tokens cannot be verified.');
}

export const authenticate = async (req, res, next) => {
  try {
    let token;

    // Get token from header
    const authHeader = req.headers.authorization || '';
    const [scheme, value] = authHeader.split(' ');
    if (scheme && /^bearer$/i.test(scheme) && value) {
      token = value;
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
          error: 'Account is deactivated'
        });
      }

      // Check if token created after password change
      if (
        user.passwordChangedAt &&
        decoded.iat &&
        decoded.iat < Math.floor(user.passwordChangedAt.getTime() / 1000)
      ) {
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

