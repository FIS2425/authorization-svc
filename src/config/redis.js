import Redis from 'ioredis';
import logger from './logger.js';

export const redisClient = new Redis({
  host: process.env.DRAGONFLY_HOST,
  port: process.env.DRAGONFLY_PORT,
});

export async function deleteTokensByUserId(userId, excludeToken) {
  try {
    const tokens = (await redisClient.smembers(`user_tokens:${userId}`)).filter(
      (token) => token !== excludeToken
    );
    if (tokens.length > 0) {
      await redisClient.del(tokens);
      await redisClient.srem(`user_tokens:${userId}`, tokens);
    }
  } catch (error) {
    logger.error('Error deleting tokens for user', {
      method: 'DELETE',
      userId,
      error: error.message,
      stack: error.stack,
    });
    throw new Error('Error deleting tokens from Redis');
  }
}

export async function deleteToken(userId, token) {
  try {
    if (token) {
      await redisClient.del(token);
      await redisClient.srem(`user_tokens:${userId}`, token);
    }
  } catch (error) {
    logger.error('Error deleting token for user', {
      method: 'DELETE',
      userId,
      error: error.message,
      stack: error.stack,
    });
    throw new Error('Error deleting token from Redis');
  }
}
