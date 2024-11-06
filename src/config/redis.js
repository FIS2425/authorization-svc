import redis from 'redis';

export const redisClient = redis.createClient({
  host: process.env.DRAGONFLY_HOST,
  port: process.env.DRAGONFLY_PORT,
});

export default function () {
  try {
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

    redisClient.connect();
  } catch (error) {
    console.error('Error de conexión con Redis:', error.message);
  }
};
