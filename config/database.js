/**
 * MongoDB Database Connection
 * Connects to MongoDB using the MONGODB_URI from environment variables
 */

import mongoose from 'mongoose';

const connectDB = async () => {
  try {
    const mongoURI = process.env.MONGODB_URI;

    if (!mongoURI) {
      console.warn('⚠️  MONGODB_URI is not defined in environment variables');
      console.warn('   Database features will be unavailable.');
      return false;
    }

    await mongoose.connect(mongoURI);

    const { host, name: dbName } = mongoose.connection;
    console.log('✅ MongoDB connected successfully');
    console.log(`   Host: ${host}`);
    console.log(`   Database: ${dbName}`);

    if (dbName !== 'phishnet') {
      console.warn(
        `⚠️  WARNING: Connected to database "${dbName}" instead of expected "phishnet". ` +
        'Ensure MONGODB_URI points to the correct database.'
      );
    }

    return true;
  } catch (error) {
    console.error('❌ MongoDB connection error:', error.message);
    return false;
  }
};

// Handle connection events
mongoose.connection.on('disconnected', () => {
  console.log('⚠️  MongoDB disconnected');
});

mongoose.connection.on('error', (error) => {
  console.error('❌ MongoDB error:', error.message);
});

export default connectDB;
