import { config } from "dotenv";
config()
import express from "express"
import connectDB from "./config/database.js";
import router from "./routes/index.route.js";

//Express app
const app = express();

//Database connection 
//connectDB();
 
//middlewares 
app.disable('x-powered-by');
app.use(express.json({ limit: '10mb' }));


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