import { config } from "dotenv";
config()
import express from "express"
import connectDB from "./config/database.js";
import router from "./routes/index.route.js";

import cookieParser from "cookie-parser";
import session from "express-session";
import MongoStore from "connect-mongo";


import { applySecurity } from "./middlewares/security.middleware.js";
import { generalLimiter } from "./config/security.js";
//Express app

const app = express(); 

// Apply security middleware
applySecurity(app);

// Rate limiting (run early)
app.use(generalLimiter);

// Body parsing middleware
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Cookie parser
app.use(cookieParser());

// Session configuration
app.use(session({
  secret: process.env.SESSION_SECRET || "your-session-secret",
  resave: false,
  saveUninitialized: false,
  store: MongoStore.create({
    mongoUrl: process.env.MONGODB_URI,
    touchAfter: 24 * 3600 // lazy session update
  }),
  cookie: {
    secure: process.env.NODE_ENV === 'production',
    httpOnly: true,
    maxAge: 24 * 60 * 60 * 1000, // 24 hours
    sameSite: 'strict'
  },
  name: 'sessionId' // Change default session name
}));



//Routes
 
// Root endpoint
app.get('/', (req, res) => {
  res.status(200).json({
    success: true,
    message: 'Secure Node.js Backend API',
    version: '1.0.0',
    environment: process.env.NODE_ENV ?? 'development',
    timestamp: new Date().toISOString(),
    documentation: '/api/info'
  });
});

app.use('/api', router);


//server listening
const PORT = process.env.PORT || 12000;
const HOST = process.env.HOST || 'localhost';

(async () => {
  try {
    await connectDB();
    const server = app.listen(PORT, HOST, () => {
      console.log(`🚀 Server running on http://${HOST}:${PORT}`);
    });
  } catch (err) {
    console.error('Failed to start server:', err);
    process.exit(1);
  }
})();

export default app 