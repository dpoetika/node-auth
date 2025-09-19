import rateLimit from "express-rate-limit";

export const createRateLimit = (windowMs = 15 * 60 * 1000, max = 100, message = 'Too many requests have been sent, please try again later.') => {
  return rateLimit({
    windowMs,
    max,
    standardHeaders: true,
    legacyHeaders: false,
    handler: (req, res) => {
      const reset = req.rateLimit?.resetTime;
      const msLeft = reset instanceof Date ? (reset.getTime() - Date.now()) : (typeof reset === 'number' ? (reset - Date.now()) : windowMs);
      const retryAfter = Math.max(1, Math.ceil(msLeft / 1000));
      res.set('Retry-After', String(retryAfter));
      res.status(429).json({ success: false, error: message, retryAfter });
    }

  });
};

// general rate limiting
export const generalLimiter = createRateLimit(
  Number(process.env.RATE_LIMIT_WINDOW_MS) || 15 * 60 * 1000, // 15 minutes
  Number(process.env.RATE_LIMIT_MAX_REQUESTS) || 100 // 100 request
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
