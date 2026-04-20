const mongoose = require('mongoose');
require('dotenv').config();

const MONGO_URI = (process.env.MONGO_URI || '').trim();

if (!MONGO_URI) {
  console.error('MONGO_URI is missing. Set it in .env before running this script.');
  process.exit(1);
}

const run = async () => {
  try {
    await mongoose.connect(MONGO_URI, { serverSelectionTimeoutMS: 5000 });
    const result = await mongoose.connection.db.collection('polls').updateMany(
      { votedBy: { $exists: false } },
      { $set: { votedBy: [] } }
    );

    console.log(`Updated ${result.modifiedCount} poll documents.`);
  } catch (error) {
    console.error('Failed to update polls:', error.message);
    process.exitCode = 1;
  } finally {
    await mongoose.connection.close();
  }
};

run();
