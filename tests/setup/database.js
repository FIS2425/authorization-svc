import mongoose from 'mongoose';
import { MongoMemoryServer } from 'mongodb-memory-server';
import { vi } from 'vitest';

let mongoServer;

export const connect = async () => {
  mongoServer = await MongoMemoryServer.create();
  await mongoose.connect(mongoServer.getUri());
  console.log('MongoDB en memoria conectado');
  // Mock Redis
  vi.mock('redis', () => {
    return import('redis-mock'); // Dynamically import 'redis-mock' for mocking
  });
  console.log('Redis mocked');
};

export const closeDatabase = async () => {
  if (mongoose.connection.readyState) {
    await mongoose.connection.dropDatabase();
    await mongoose.connection.close();
    await mongoServer?.stop();
    console.log('MongoDB en memoria desconectado');
  }
};

export const clearDatabase = async () => {
  const collections = mongoose.connection.collections;

  await Promise.all(
    Object.values(collections).map(async (collection) => {
      await collection.deleteMany();
    }),
  );

  console.log('MongoDB en memoria limpiado');
};
