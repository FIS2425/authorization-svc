import redis from 'redis';

export const redisClient = redis.createClient({
  host: process.env.DRAGONFLY_HOST,
  port: process.env.DRAGONFLY_PORT,
});

export async function deleteTokensByUserId(userId, excludeToken) {
  const tokens = (await redisClient
    .sMembers(`user_tokens:${userId}`))
    .filter((token) => token !== excludeToken);
  for (const token of tokens) {
    await deleteToken(userId, token);
  }
};

export async function deleteToken(userId, token) {
  await redisClient.del(token);
  await redisClient.sRem(`user_tokens:${userId}`, token);
};

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
