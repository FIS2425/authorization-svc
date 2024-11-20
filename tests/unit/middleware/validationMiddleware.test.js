import { describe, afterEach, it, vi, expect } from 'vitest';
import jwt from 'jsonwebtoken';
import { validateAuthToken } from '../../../src/middleware/validationMiddleware.js';
import User from '../../../src/schemas/User.js';
import { redisClient } from '../../../src/config/redis.js';

afterEach(() => {
  vi.resetAllMocks();
});

describe('Validation Middleware', () => {
  describe('validate token', () => {
    it('should validate the token successfully', async () => {
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

      const req = { cookies: { token: mockToken } };
      const res = { status: vi.fn().mockReturnThis(), json: vi.fn() };
      const next = vi.fn();

      await validateAuthToken(req, res, next);

      expect(jwt.verify).toHaveBeenCalledWith(mockToken, process.env.JWT_SECRET || process.env.VITE_JWT_SECRET);
      expect(User.findById).toHaveBeenCalledWith(mockDecoded.userId);
      expect(redisClient.exists).toHaveBeenCalledWith(mockToken);
      expect(next).toHaveBeenCalled();
    });

    it('should return 401 with no token provided', async () => {
      const req = { cookies: {} };
      const res = { status: vi.fn().mockReturnThis(), json: vi.fn() };
      const next = vi.fn();

      await validateAuthToken(req, res, next);

      expect(res.status).toHaveBeenCalledWith(401);
      expect(res.json).toHaveBeenCalledWith({ message: 'No token provided' });
      expect(next).not.toHaveBeenCalled();
    });

    it('should return 401 with token expired', async () => {
      const mockToken = 'expiredToken';

      const req = { cookies: { token: mockToken } };
      const res = { status: vi.fn().mockReturnThis(), json: vi.fn() };
      const next = vi.fn();

      vi.spyOn(jwt, 'verify').mockImplementation(() => {
        throw new jwt.TokenExpiredError('jwt expired', new Date());
      });

      await validateAuthToken(req, res, next);

      expect(res.status).toHaveBeenCalledWith(401);
      expect(res.json).toHaveBeenCalledWith({ message: 'Token expired' });
      expect(next).not.toHaveBeenCalled();
    });


    it('should return 401 with token expired in dragonfly', async () => {
      const mockUser = {
        _id: 'userId',
        email: 'testuser@mail.com',
        password: 'password',
        roles: ['user'],
        comparePassword: vi.fn().mockResolvedValue(true),
      };
      const mockToken = 'expiredToken';
      const mockDecoded = { userId: 'user123', roles: ['user'] };

      const req = { cookies: { token: mockToken } };
      const res = { status: vi.fn().mockReturnThis(), json: vi.fn() };
      const next = vi.fn();

      vi.spyOn(jwt, 'verify').mockReturnValueOnce(mockDecoded);
      vi.spyOn(User, 'findById').mockResolvedValue(mockUser);
      vi.spyOn(redisClient, 'exists').mockResolvedValue(false);

      await validateAuthToken(req, res, next);

      expect(res.status).toHaveBeenCalledWith(401);
      expect(res.json).toHaveBeenCalledWith({ message: 'Token expired' });
      expect(next).not.toHaveBeenCalled();
    });

    it('should return 401 if user is not found', async () => {
      const mockToken = 'validToken';
      const mockDecoded = { userId: 'user123' };

      const req = { cookies: { token: mockToken } };
      const res = { status: vi.fn().mockReturnThis(), json: vi.fn() };
      const next = vi.fn();

      vi.spyOn(jwt, 'verify').mockReturnValueOnce(mockDecoded);
      vi.spyOn(User, 'findById').mockResolvedValue(null);
      vi.spyOn(redisClient, 'exists').mockResolvedValue(false);

      await validateAuthToken(req, res, next);

      expect(res.status).toHaveBeenCalledWith(401);
      expect(res.json).toHaveBeenCalledWith({ message: 'User not found' });
      expect(next).not.toHaveBeenCalled();
    });

    it('should return 401 with invalid token (badly signed)', async () => {
      const mockToken = 'badToken';

      const req = { cookies: { token: mockToken } };
      const res = { status: vi.fn().mockReturnThis(), json: vi.fn() };
      const next = vi.fn();

      jwt.verify.mockImplementation(() => {
        throw new jwt.JsonWebTokenError('invalid signature');
      });

      await validateAuthToken(req, res, next);

      expect(res.status).toHaveBeenCalledWith(401);
      expect(res.json).toHaveBeenCalledWith({ message: 'Invalid token' });
      expect(next).not.toHaveBeenCalled();
    });
  });
});
