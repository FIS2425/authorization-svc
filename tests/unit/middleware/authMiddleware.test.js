import { afterEach, describe, expect, it, vi } from 'vitest';
import User from '../../../src/schemas/User.js';
import { userExists } from '../../../src/middleware/authMiddleware.js';

afterEach(() => {
  vi.resetAllMocks();
});

describe('Auth Middleware', () => {
  describe('userExists', () => {
    it('should find user and attach to request', async () => {
      vi.spyOn(User, 'findById').mockResolvedValue({
        _id: 'someId',
        roles: ['patient'],
      });

      const req = { params: { id: 'someId' } };
      const res = { status: vi.fn().mockReturnThis(), json: vi.fn() };
      const next = vi.fn();

      await userExists(req, res, next);

      expect(User.findById).toHaveBeenCalledWith('someId');
      expect(req.onUser).toEqual({ _id: 'someId', roles: ['patient'] });
      expect(next).toHaveBeenCalled();
    });

    it('should return 404 if user does not exist', async () => {
      vi.spyOn(User, 'findById').mockResolvedValue(null);

      const req = { params: { id: 'nonExistentId' } };
      const res = { status: vi.fn().mockReturnThis(), json: vi.fn() };
      const next = vi.fn();

      await userExists(req, res, next);

      expect(User.findById).toHaveBeenCalledWith('nonExistentId');
      expect(res.status).toHaveBeenCalledWith(404);
      expect(res.json).toHaveBeenCalledWith({ message: 'User not found' });
      expect(next).not.toHaveBeenCalled();
    });
  });
});
