import { MongoClient } from 'mongodb';
import { MONGODB_URI } from '../config';
import createHttpError from 'http-errors';

let cachedDb = null;

async function connectToDatabase() {
  if (cachedDb) {
    return Promise.resolve(cachedDb);
  }
  // Connect to our MongoDB database hosted on MongoDB Atlas
  const client = await MongoClient.connect(MONGODB_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true
  });

  cachedDb = client.db();
  return cachedDb;
}

export default function withDbConnection() {
  return {
    before: async ({ event, context }) => {
      let db = null;

      try {
        db = await connectToDatabase();
      } catch (error) {
        console.error(error);
        throw new createHttpError.InternalServerError('Error while connecting to db!');
      }

      context.db = db;
    }
  };
};