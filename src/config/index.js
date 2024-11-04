import mongoose from 'mongoose';
import api from '../api.js';
import redis from 'redis';

const MONGO_URI = process.env.MONGOURL;
const PORT = process.env.PORT || 3001;

const redisClient = redis.createClient({
  host: process.env.DRAGONFLY_HOST,
  port: process.env.DRAGONFLY_PORT,
});

mongoose
  .connect(MONGO_URI)
  .then(() => {
    console.log('Conexión con MongoDB OK');

    redisClient.connect();

    redisClient.on('connect', () => {
      console.log('Connected to Redis...');
    });

    redisClient.on('error', (err) => {
      console.error('Redis error:', err);
    });

    // Listen for end and close events
    redisClient.on('end', () => {
      console.log('Redis client disconnected');
    });

    // Optionally, handle reconnection logic
    redisClient.on('reconnecting', () => {
      console.log('Attempting to reconnect to Redis...');
    });

    const app = api();

    app.listen(PORT, () => {
      console.log(`Servidor escuchando en http://localhost:${PORT}`);
    });
  })
  .catch((error) => {
    console.error('Error de conexión con MongoDB:', error.message);
  });

export default redisClient;
