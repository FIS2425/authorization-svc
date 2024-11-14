import Redis from 'ioredis';

export const redisClient = new Redis({
  host: process.env.DRAGONFLY_HOST,
  port: process.env.DRAGONFLY_PORT,
});

export async function deleteTokensByUserId(userId, excludeToken) {
  const tokens = (await redisClient
    .smembers(`user_tokens:${userId}`))
    .filter((token) => token !== excludeToken);
  await redisClient.del(tokens);
  await redisClient.srem(`user_tokens:${userId}`, tokens);
};

export async function deleteToken(userId, token) {
  await redisClient.del(token);
  await redisClient.srem(`user_tokens:${userId}`, token);
};
