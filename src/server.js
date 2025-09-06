import { config } from "dotenv";
config()
import express from "express"
import connectDB from "./config/database.js";
import router from "./routes/index.route.js";

//Express app
const app = express();

//Database connection 
connectDB();
 
//middlewares 
app.use(express.json({ limit: '10mb' }));


//Routes
app.get('/health', (req, res) => {
  res.status(200).json({
    status: 'OK',
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    memory: process.memoryUsage(),
    version: '1.0.0'
  });
});

// Root endpoint
app.get('/', (req, res) => {
  res.status(200).json({
    success: true,
    message: 'Secure Node.js Backend API',
    version: '1.0.0',
    environment: process.env.NODE_ENV,
    timestamp: new Date().toISOString(),
    documentation: '/api/info'
  });
});

app.use('/api', router);


//server listening
const PORT = process.env.PORT || 12000;
const HOST = process.env.HOST || 'localhost';

const server = app.listen(PORT, () => {
  console.log(`🚀 Server running on http://${HOST}:${PORT}`);
});

export default app 