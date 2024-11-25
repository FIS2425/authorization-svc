import { describe, beforeAll, afterAll, it, expect } from 'vitest';
import { request } from '../../setup/setup'; // Assuming this is your request setup, like Supertest
import { redisClient } from '../../../src/config/redis.js';
import { v4 as uuidv4 } from 'uuid';
import * as db from '../../setup/database';
import User from '../../../src/schemas/User.js';
import jwt from 'jsonwebtoken';

const sampleUser = new User({
  _id: uuidv4(),
  email: 'testuser@mail.com',
  password: 'pAssw0rd!',
  roles: ['patient'],
});

beforeAll(async () => {
  await db.clearDatabase();
  await sampleUser.save();

  const token = jwt.sign(
    { userId: sampleUser._id, roles: sampleUser.roles },
    process.env.VITE_JWT_SECRET
  );

  redisClient.set(token, sampleUser._id.toString(), async () => {
    console.log('Token set');
  });
});

afterAll(async () => {
  await db.clearDatabase();
});

describe('Token Controller', () => {
  let token;
  
  describe('validate', () => {
    beforeAll(async () => {
      token = jwt.sign(
        { userId: sampleUser._id, roles: sampleUser.roles },
        process.env.VITE_JWT_SECRET
      );
      redisClient.set(token, sampleUser._id.toString());
    });

    it('should validate the token successfully', async () => {
      const res = await request.get('/token/validate').set('Cookie', `token=${token}`);

      expect(res.status).toBe(200);
    });

    it('should return 401 with no token provided', async () => {
      const res = await request.get('/token/validate').set('Cookie', '');

      expect(res.status).toBe(401);
      expect(res.body.message).toBe('No token provided');
    });

    it('should return 401 with token expired', async () => {
      const expiredToken = jwt.sign(
        { userId: sampleUser._id, roles: sampleUser.roles },
        process.env.VITE_JWT_SECRET,
        { expiresIn: 0 }
      );

      const res = await request
        .get('/token/validate')
        .set('Cookie', `token=${expiredToken}`);

      expect(res.status).toBe(401);
      expect(res.body.message).toBe('Token expired');
    });

    it('should return 401 with token expired in dragonfly', async () => {
    // From here on out redis will not need to be accessed, so we can safely delete the token
      await redisClient.del(token);

      const expiredToken = jwt.sign(
        { userId: sampleUser._id, roles: sampleUser.roles },
        process.env.VITE_JWT_SECRET,
        { expiresIn: 0 }
      );

      const res = await request
        .get('/token/validate')
        .set('Cookie', `token=${expiredToken}`);

      expect(res.status).toBe(401);
      expect(res.body.message).toBe('Token expired');
    });

    it('should return 401 if user is not found', async () => {
      const nonExistentUserId = uuidv4();
      const invalidToken = jwt.sign(
        { userId: nonExistentUserId, roles: sampleUser.roles },
        process.env.VITE_JWT_SECRET
      );

      const res = await request
        .get('/token/validate')
        .set('Cookie', `token=${invalidToken}`);

      expect(res.status).toBe(401);
      expect(res.body.message).toBe('User not found');
    });

    it('should return 401 with invalid token (badly signed)', async () => {
      const invalidToken = 'invalid.token.value';

      const res = await request
        .get('/token/validate')
        .set('Cookie', `token=${invalidToken}`);

      expect(res.status).toBe(401);
      expect(res.body.message).toBe('Invalid token');
    });
  });

  describe('refresh', () => {
    let validToken, validRefreshToken;
  
    beforeAll(async () => {
      validToken = jwt.sign(
        { userId: sampleUser._id, roles: sampleUser.roles },
        process.env.VITE_JWT_SECRET
      );
      validRefreshToken = jwt.sign(
        { userId: sampleUser._id, roles: sampleUser.roles },
        process.env.VITE_JWT_SECRET
      );
  
      redisClient.set(validToken, sampleUser._id.toString());
      redisClient.set(validRefreshToken, sampleUser._id.toString());
      redisClient.sadd(`user_tokens:${sampleUser._id}`, validToken);
      redisClient.sadd(`user_tokens:${sampleUser._id}`, validRefreshToken);
    });
  
    afterAll(async () => {
      await redisClient.del(validToken);
      await redisClient.del(validRefreshToken);
      await redisClient.srem(`user_tokens:${sampleUser._id}`, validToken);
      await redisClient.srem(`user_tokens:${sampleUser._id}`, validRefreshToken);
    });
  
    it('should refresh tokens successfully', async () => {
      const res = await request
        .get('/token/refresh')
        .set('Cookie', `token=${validToken}; refreshToken=${validRefreshToken}`);
  
      expect(res.status).toBe(200);
      expect(res.body.message).toBe('Tokens refreshed');
  
      const newToken = res.headers['set-cookie'].find((cookie) =>
        cookie.startsWith('token=')
      );
      const newRefreshToken = res.headers['set-cookie'].find((cookie) =>
        cookie.startsWith('refreshToken=')
      );
  
      expect(newToken).toBeDefined();
      expect(newRefreshToken).toBeDefined();
    });
  
    it('should return 401 if no refreshToken is provided', async () => {
      const res = await request
        .get('/token/refresh')
        .set('Cookie', `token=${validToken}`);
  
      expect(res.status).toBe(401);
      expect(res.body.message).toBe('No token provided');
    });
  
    it('should return 401 if refreshToken is expired', async () => {
      const expiredRefreshToken = jwt.sign(
        { userId: sampleUser._id, roles: sampleUser.roles },
        process.env.VITE_JWT_SECRET,
        { expiresIn: 0 }
      );
  
      const res = await request
        .get('/token/refresh')
        .set('Cookie', `token=${validToken}; refreshToken=${expiredRefreshToken}`);
  
      expect(res.status).toBe(401);
      expect(res.body.message).toBe('Token expired');
    });
  
    it('should return 401 if refreshToken is invalid', async () => {
      const invalidRefreshToken = 'invalid.token.value';
  
      const res = await request
        .get('/token/refresh')
        .set('Cookie', `token=${validToken}; refreshToken=${invalidRefreshToken}`);
  
      expect(res.status).toBe(401);
      expect(res.body.message).toBe('Invalid token');
    });
  
    it('should return 401 if user does not exist', async () => {
      const nonExistentUserId = uuidv4();
      const invalidRefreshToken = jwt.sign(
        { userId: nonExistentUserId, roles: sampleUser.roles },
        process.env.VITE_JWT_SECRET
      );
  
      const res = await request
        .get('/token/refresh')
        .set('Cookie', `token=${validToken}; refreshToken=${invalidRefreshToken}`);
  
      expect(res.status).toBe(401);
      expect(res.body.message).toBe('User not found');
    });

    it('should return 401 if user does not have a token', async () => {
      const res = await request
        .get('/token/refresh')
        .set('Cookie', 'token=invalidToken; refreshToken=invalidRefreshToken');
  
      expect(res.status).toBe(401);
      expect(res.body.message).toBe('Invalid token');
    });

    it('should return 401 if user does not have a refresh token', async () => {
      const res = await request
        .get('/token/refresh')
        .set('Cookie', `token=${validToken}; refreshToken=invalidRefreshToken`);
  
      expect(res.status).toBe(401);
      expect(res.body.message).toBe('Invalid token');
    });
  });  
});
