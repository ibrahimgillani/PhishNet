const mongoose = require('mongoose');

const connectDB = async () => {
  try {
    const mongoURI = process.env.MONGODB_URI;

    if (!mongoURI) {
      throw new Error('MONGODB_URI is not defined in environment variables');
    }

    await mongoose.connect(mongoURI, {
      useNewUrlParser: true,
      useUnifiedTopology: true
    });

    const { host, name: dbName } = mongoose.connection;
    console.log('MongoDB connected successfully');
    console.log(`Connected to host: ${host}`);
    console.log(`Connected to database: ${dbName}`);

    if (dbName !== 'phishnet') {
      console.warn(
        `WARNING: Connected to database "${dbName}" instead of expected "phishnet". ` +
        'Ensure MONGODB_URI points to the shared website database.'
      );
    }
  } catch (error) {
    console.error('MongoDB connection error:', error.message);
    process.exit(1);
  }
};

// Handle connection events
mongoose.connection.on('disconnected', () => {
  console.log('MongoDB disconnected');
});

mongoose.connection.on('error', (error) => {
  console.error('MongoDB error:', error.message);
  // Don't exit on error, just log it
});

module.exports = connectDB;
