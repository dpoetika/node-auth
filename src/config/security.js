import rateLimit from "express-rate-limit";

export const createRateLimit = (windowMs = 15 * 60 * 1000, max = 100, message = 'Too many requests have been sent, please try again later.') => {
  return rateLimit({
    windowMs,
    max,
    message: {
      error: message,
      retryAfter: Math.ceil(windowMs / 1000)
    },
    standardHeaders: true,
    legacyHeaders: false,
    handler: (req, res) => {
      res.status(429).json({
        success: false,
        error: message,
        retryAfter: Math.ceil(windowMs / 1000)
      });
    }
  });
};

// general rate limiting
export const generalLimiter = createRateLimit(
  parseInt(process.env.RATE_LIMIT_WINDOW_MS) || 15 * 60 * 1000, // 15 minutes
  parseInt(process.env.RATE_LIMIT_MAX_REQUESTS) || 100 // 100 request
);

// rate limit for Auth endpoint
export const authLimiter = createRateLimit(
  15 * 60 * 1000, // 15 minutes
  5, // 5 request
);

// rate limit for API endpoint
export const apiLimiter = createRateLimit(
  15 * 60 * 1000, // 15 minutes
  1000, // 1000 request
);
