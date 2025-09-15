

import helmet from 'helmet';
import cors from "cors"
//import ExpressMongoSanitize from 'express-mongo-sanitize';
import xss from 'xss';
import hpp from 'hpp';
import compression from 'compression';

// XSS preventing middleware
const xssClean = (req, res, next) => {
    if (req.body) {
        Object.keys(req.body).forEach(key => {
            if (typeof req.body[key] === 'string') {
                req.body[key] = xss(req.body[key]);
            }
        });
    }

    if (req.query) {
        Object.keys(req.query).forEach(key => {
            if (typeof req.query[key] === 'string') {
                req.query[key] = xss(req.query[key]);
            }
        });
    }

    if (req.params) {
        Object.keys(req.params).forEach(key => {
            if (typeof req.params[key] === 'string') {
                req.params[key] = xss(req.params[key]);
            }
        });
    }

    next();
};

// CORS config
const corsOptions = {
    origin: function (origin, callback) {
        // allow all origins in development env
        if (process.env.NODE_ENV === 'development') {
            return callback(null, true);
        }

        // allow specified origins in production env
        const allowedOrigins = process.env.CORS_ORIGIN ? process.env.CORS_ORIGIN.split(',') : [];

        if (!origin || allowedOrigins.includes(origin) || allowedOrigins.includes('*')) {
            callback(null, true);
        } else {
            callback(new Error('Blocked by CORS Policy'));
        }
    },
    credentials: process.env.CORS_CREDENTIALS === 'true',
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With', 'Accept', 'Origin'],
    exposedHeaders: ['X-Total-Count', 'X-Page-Count'],
    maxAge: 86400 // 24 hours
};

// Helmet security config
const helmetOptions = {
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            styleSrc: ["'self'", "'unsafe-inline'"],
            scriptSrc: ["'self'"],
            imgSrc: ["'self'", "data:", "https:"],
            connectSrc: ["'self'"],
            fontSrc: ["'self'"],
            objectSrc: ["'none'"],
            mediaSrc: ["'self'"],
            frameSrc: ["'none'"],
        },
    },
    crossOriginEmbedderPolicy: false,
    hsts: {
        maxAge: 31536000,
        includeSubDomains: true,
        preload: true
    }
};

// get ip address middleware
const getClientIP = (req, res, next) => {
    req.clientIP = req.headers['x-forwarded-for'] ||
        req.headers['x-real-ip'] ||
        req.connection.remoteAddress ||
        req.socket.remoteAddress ||
        (req.connection.socket ? req.connection.socket.remoteAddress : null) ||
        req.ip;
    next();
};

// Request size limitation
const requestSizeLimit = (limit = '10mb') => {
    return (req, res, next) => {
        const contentLength = parseInt(req.headers['content-length']);
        const maxSize = parseInt(limit.replace(/[^\d]/g, '')) * (limit.includes('mb') ? 1024 * 1024 : 1024);

        if (contentLength && contentLength > maxSize) {
            return res.status(413).json({
                success: false,
                error: 'Request size is too large'
            });
        }

        next();
    };
};


// MongoDB injection 
const sanitizeMongo = (req, res, next) => {
    const sanitize = (obj) => {
        for (const key in obj) {
            if (/^\$/.test(key) || key.includes('.')) {
                delete obj[key]; // delete MongoDB operators 
            } else if (typeof obj[key] === 'object') {
                sanitize(obj[key]);
            }
        }
    };

    if (req.body) sanitize(req.body);
    if (req.query) sanitize(req.query);
    if (req.params) sanitize(req.params);

    next();
};


// Apply security middlewares
export const applySecurity = (app) => {

    // Compression
    app.use(compression());

    // Trust proxy
    app.set('trust proxy', 1);


    // Client IP
    app.use(getClientIP);

    // Request size limit
    app.use(requestSizeLimit('10mb'));

    // Helmet security headers
    app.use(helmet(helmetOptions));

    // CORS
    app.use(cors(corsOptions));

    // MongoDB injection prevention
    app.use(sanitizeMongo);

    // XSS protection
    app.use(xssClean);

    // HTTP Parameter Pollution prevention
    app.use(hpp({
        whitelist: ['sort', 'fields', 'page', 'limit', 'filter']
    }));

    // Disable X-Powered-By header
    app.disable('x-powered-by');
};

