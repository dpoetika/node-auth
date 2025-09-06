import mongoose from 'mongoose';
const clientOptions = {
    serverApi: { version: '1', strict: true, deprecationErrors: true },
    serverSelectionTimeoutMS: 5000,
    connectTimeoutMS: 10000,
    maxPoolSize: 10,
};

const connectDB = async () => {
    try {
        const uri = process.env.MONGODB_URI;
        if (!uri) throw new Error('MONGODB_URI is not defined');
        const conn = await mongoose.connect(uri, clientOptions);

        console.log(`MongoDB Connected: ${conn.connection.host}`);

        mongoose.connection.on('error', (err) => {
            console.error('MongoDB connection error:', err);
        });

        mongoose.connection.on('disconnected', () => {
            console.warn('MongoDB disconnected');
        });
        // Graceful shutdown
        process.on('SIGINT', async () => { await mongoose.connection.close(); process.exit(0); });
        process.on('SIGTERM', async () => { await mongoose.connection.close(); process.exit(0); });


    } catch (error) {
        console.error('Database connection failed:', error);
        throw error;
    }
};

export default connectDB