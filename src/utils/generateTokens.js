import jwt from 'jsonwebtoken';
import { redisClient } from '../config/redis.js';

export const generateTokens = async (user, res) => {
  const token_expiration = parseInt(process.env.JWT_EXPIRATION) || 3600;
  const refreshToken_expiration = parseInt(process.env.JWT_REFRESH_EXPIRATION) || 3600;

  const authToken = await jwt.sign(
    {
      userId: user._id.toString(),
      roles: user.roles,
    },
    process.env.JWT_SECRET || process.env.VITE_JWT_SECRET,
    {
      expiresIn: token_expiration,
    }
  );

  const refreshToken = await jwt.sign(
    {
      userId: user._id.toString(),
    },
    process.env.JWT_SECRET || process.env.VITE_JWT_SECRET,
    {
      expiresIn: refreshToken_expiration,
    }
  );

  redisClient.set(
    authToken,
    user._id.toString(),
    'EX',
    parseInt(process.env.JWT_EXPIRATION) || 3600
  );
  redisClient.set(
    refreshToken,
    user._id.toString(),
    'EX',
    parseInt(process.env.JWT_REFRESH_EXPIRATION) || 3600
  );

  redisClient.sadd(`user_tokens:${user._id.toString()}`, authToken);
  redisClient.sadd(`user_tokens:${user._id.toString()}`, refreshToken);

  res.cookie('token', authToken, { httpOnly: true, maxAge: token_expiration * 1000, sameSite: 'none', secure: true });
  res.cookie('refreshToken', refreshToken, { httpOnly: true, maxAge: refreshToken_expiration * 1000, sameSite: 'none', secure: true });
};
