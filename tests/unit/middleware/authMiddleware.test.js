import { afterEach, describe, expect, it, vi } from 'vitest';
import User from '../../../src/schemas/User.js';
import { checkRoles } from '../../../src/middleware/authMiddleware.js';

afterEach(() => {
  vi.resetAllMocks();
});

describe('Auth Middleware', () => {
  describe('validate role', () => {
    it('should confirm one role', async () => {
      vi.spyOn(User, 'findById').mockResolvedValue({
        roles: ['clinicadmin']
      });

      const req = { userId: 'someId' };
      const res = { status: vi.fn().mockReturnThis(), json: vi.fn() };
      const next = vi.fn();

      await checkRoles('clinicadmin')(req, res, next);

      expect(User.findById).toHaveBeenCalledWith('someId');
      expect(next).toHaveBeenCalled();
    });

    it('should reject one role', async () => {
      vi.spyOn(User, 'findById').mockResolvedValue({
        roles: ['clinicadmin']
      });

      const req = { userId: 'someId' };
      const res = { status: vi.fn().mockReturnThis(), json: vi.fn() };
      const next = vi.fn();

      await checkRoles('admin')(req, res, next);

      expect(User.findById).toHaveBeenCalledWith('someId');
      expect(res.json).toHaveBeenCalledWith({ message: 'Unauthorized' });
      expect(next).not.toHaveBeenCalled();
    });

    it('should confirm many roles', async () => {
      vi.spyOn(User, 'findById').mockResolvedValue({
        roles: ['clinicadmin', 'doctor', 'admin']
      });

      const req = { userId: 'someId' };
      const res = { status: vi.fn().mockReturnThis(), json: vi.fn() };
      const next = vi.fn();

      await checkRoles('clinicadmin', 'doctor', 'admin')(req, res, next);

      expect(User.findById).toHaveBeenCalledWith('someId');
      expect(next).toHaveBeenCalled();
    });

    it('should reject one in many role', async () => {
      vi.spyOn(User, 'findById').mockResolvedValue({
        roles: ['clinicadmin', 'doctor']
      });

      const req = { userId: 'someId' };
      const res = { status: vi.fn().mockReturnThis(), json: vi.fn() };
      const next = vi.fn();

      await checkRoles('clinicadmin', 'doctor', 'admin')(req, res, next);

      expect(User.findById).toHaveBeenCalledWith('someId');
      expect(res.json).toHaveBeenCalledWith({ message: 'Unauthorized' });
      expect(next).not.toHaveBeenCalled();
    });

    it('should reject some in many role', async () => {
      vi.spyOn(User, 'findById').mockResolvedValue({
        roles: ['doctor']
      });

      const req = { userId: 'someId' };
      const res = { status: vi.fn().mockReturnThis(), json: vi.fn() };
      const next = vi.fn();

      await checkRoles('clinicadmin', 'doctor', 'admin')(req, res, next);

      expect(User.findById).toHaveBeenCalledWith('someId');
      expect(res.json).toHaveBeenCalledWith({ message: 'Unauthorized' });
      expect(next).not.toHaveBeenCalled();
    });

    it('should reject all roles', async () => {
      vi.spyOn(User, 'findById').mockResolvedValue({
        roles: ['patient']
      });

      const req = { userId: 'someId' };
      const res = { status: vi.fn().mockReturnThis(), json: vi.fn() };
      const next = vi.fn();

      await checkRoles('clinicadmin', 'doctor', 'admin')(req, res, next);

      expect(User.findById).toHaveBeenCalledWith('someId');
      expect(res.json).toHaveBeenCalledWith({ message: 'Unauthorized' });
      expect(next).not.toHaveBeenCalled();
    });
  });
});
