import { describe, afterEach, it, vi, expect } from 'vitest';
import { request } from '../../setup/setup';
import jwt from 'jsonwebtoken';
import User from '../../../src/schemas/User.js';
import { redisClient } from '../../../src/config/redis.js';

afterEach(() => {
  vi.resetAllMocks();
});

describe('Token Controller', () => {
  describe('validate token', () => {
    it('should return 200', async () => {
    // We test happy path as the middleware is already tested
      const mockUser = {
        _id: 'userId',
        email: 'testuser@mail.com',
        password: 'password',
        roles: ['user'],
        comparePassword: vi.fn().mockResolvedValue(true),
      };
      const mockToken = 'validToken';
      const mockDecoded = { userId: 'user123', roles: ['user'] };

      vi.spyOn(jwt, 'verify').mockReturnValueOnce(mockDecoded);
      vi.spyOn(User, 'findById').mockResolvedValue(mockUser);
      vi.spyOn(redisClient, 'exists').mockResolvedValue(true);

      const res = await request
        .get('/token/validate')
        .set('Cookie', `token=${mockToken}`);

      expect(res.status).toBe(200);
      expect(res.body.message).toBe('Token is valid');
    });
  });

  describe('refresh token', () => {
    it('should return 200', async () => {
      const mockUser = {
        _id: 'userId',
        email: 'testuser@mail.com',
        password: 'password',
        roles: ['user'],
        comparePassword: vi.fn().mockResolvedValue(true),
      };
      const mockToken = 'validToken';
      const mockRefresh = 'validRefreshToken';
      const mockDecoded = { userId: 'user123', roles: ['user'] };

      vi.spyOn(jwt, 'verify').mockReturnValueOnce(mockDecoded);
      vi.spyOn(User, 'findById').mockResolvedValue(mockUser);
      vi.spyOn(redisClient, 'exists').mockResolvedValue(true);
      vi.spyOn(redisClient, 'del').mockResolvedValue(true);
      vi.spyOn(redisClient, 'sismember').mockResolvedValue(true);
      vi.spyOn(redisClient, 'srem').mockResolvedValue(true);

      const res = await request
        .get('/token/refresh')
        .set('Cookie', `token=${mockToken}; refreshToken=${mockRefresh}`);

      expect(res.status).toBe(200);
      expect(res.body.message).toBe('Tokens refreshed');
    });
    it('should return 500', async () => {
      const mockUser = {
        _id: 'userId',
        email: 'testuser@mail.com',
        password: 'password',
        roles: ['user'],
        comparePassword: vi.fn().mockResolvedValue(true),
      };
      const mockToken = 'validToken';
      const mockRefresh = 'validRefreshToken';
      const mockDecoded = { userId: 'user123', roles: ['user'] };

      vi.spyOn(jwt, 'verify').mockReturnValueOnce(mockDecoded);
      vi.spyOn(User, 'findById').mockResolvedValue(mockUser);
      vi.spyOn(redisClient, 'exists').mockResolvedValue(true);
      vi.spyOn(redisClient, 'del').mockResolvedValue(true);
      vi.spyOn(redisClient, 'sismember').mockResolvedValue(true);
      vi.spyOn(redisClient, 'srem').mockResolvedValue(true);

      vi.spyOn(jwt, 'sign').mockImplementationOnce(() => {
        throw new Error('JWT signing error');
      });

      const res = await request
        .get('/token/refresh')
        .set('Cookie', `token=${mockToken}; refreshToken=${mockRefresh}`);

      expect(res.status).toBe(500);
      expect(res.body.message).toBe('Internal server error');
    });
  });
});
