import { afterEach, describe, expect, it, vi } from 'vitest';
import User from '../../../src/schemas/User.js';
import { checkRoles, userExists, hasAccessToUser } from '../../../src/middleware/authMiddleware.js';

afterEach(() => {
  vi.resetAllMocks();
});

describe('Auth Middleware', () => {
  describe('validate role', () => {
    it('should confirm one role', async () => {
      const req = { userId: 'someId', roles: ['clinicadmin'] };
      const res = { status: vi.fn().mockReturnThis(), json: vi.fn() };
      const next = vi.fn();

      await checkRoles('clinicadmin')(req, res, next);

      expect(next).toHaveBeenCalled();
    });

    it('should reject one role', async () => {
      const req = { userId: 'someId', roles: ['clinicadmin'] };
      const res = { status: vi.fn().mockReturnThis(), json: vi.fn() };
      const next = vi.fn();

      await checkRoles('admin')(req, res, next);

      expect(res.json).toHaveBeenCalledWith({ message: 'Unauthorized' });
      expect(next).not.toHaveBeenCalled();
    });

    it('should confirm many roles', async () => {
      const req = { userId: 'someId', roles: ['clinicadmin', 'doctor', 'admin'] };
      const res = { status: vi.fn().mockReturnThis(), json: vi.fn() };
      const next = vi.fn();

      await checkRoles('clinicadmin', 'doctor', 'admin')(req, res, next);

      expect(next).toHaveBeenCalled();
    });

    it('should reject one in many role', async () => {
      const req = { userId: 'someId', roles: ['clinicadmin', 'doctor'] };
      const res = { status: vi.fn().mockReturnThis(), json: vi.fn() };
      const next = vi.fn();

      await checkRoles('clinicadmin', 'doctor', 'admin')(req, res, next);

      expect(res.json).toHaveBeenCalledWith({ message: 'Unauthorized' });
      expect(next).not.toHaveBeenCalled();
    });

    it('should reject some in many role', async () => {
      const req = { userId: 'someId', roles: ['doctor'] };
      const res = { status: vi.fn().mockReturnThis(), json: vi.fn() };
      const next = vi.fn();

      await checkRoles('clinicadmin', 'doctor', 'admin')(req, res, next);

      expect(res.json).toHaveBeenCalledWith({ message: 'Unauthorized' });
      expect(next).not.toHaveBeenCalled();
    });

    it('should reject all roles', async () => {
      const req = { userId: 'someId', roles: ['patient'] };
      const res = { status: vi.fn().mockReturnThis(), json: vi.fn() };
      const next = vi.fn();

      await checkRoles('clinicadmin', 'doctor', 'admin')(req, res, next);

      expect(res.json).toHaveBeenCalledWith({ message: 'Unauthorized' });
      expect(next).not.toHaveBeenCalled();
    });
  });

  describe('userExists', () => {
    it('should find user and attach to request', async () => {
      vi.spyOn(User, 'findById').mockResolvedValue({
        _id: 'someId',
        roles: ['patient']
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

  describe('hasAccessToUser', () => {
    it('should allow access for admin role', async () => {
      const req = { userId: 'adminId', roles: ['admin'], params: { id: 'someUserId' } };
      const res = { status: vi.fn().mockReturnThis(), json: vi.fn() };
      const next = vi.fn();

      await hasAccessToUser(req, res, next);

      expect(next).toHaveBeenCalled();
    });

    it('should allow access for clinicadmin role', async () => {
      const req = { userId: 'clinicAdminId', roles: ['clinicadmin'], params: { id: 'someUserId' } };
      const res = { status: vi.fn().mockReturnThis(), json: vi.fn() };
      const next = vi.fn();

      await hasAccessToUser(req, res, next);

      expect(next).toHaveBeenCalled();
    });

    it('should allow access for doctor role', async () => {
      const req = { userId: 'doctorId', roles: ['doctor'], params: { id: 'someUserId' } };
      const res = { status: vi.fn().mockReturnThis(), json: vi.fn() };
      const next = vi.fn();

      await hasAccessToUser(req, res, next);

      expect(next).toHaveBeenCalled();
    });

    it('should allow access for same user', async () => {
      const req = { userId: 'someUserId', roles: ['patient'], params: { id: 'someUserId' } };
      const res = { status: vi.fn().mockReturnThis(), json: vi.fn() };
      const next = vi.fn();

      await hasAccessToUser(req, res, next);

      expect(next).toHaveBeenCalled();
    });

    it('should deny access for different user without appropriate role', async () => {
      const req = { userId: 'userId', roles: ['patient'], params: { id: 'otherUserId' } };
      const res = { status: vi.fn().mockReturnThis(), json: vi.fn() };
      const next = vi.fn();

      await hasAccessToUser(req, res, next);

      expect(res.status).toHaveBeenCalledWith(403);
      expect(res.json).toHaveBeenCalledWith({ message: 'Unauthorized' });
      expect(next).not.toHaveBeenCalled();
    });

    it('should deny access for user without appropriate role', async () => {
      const req = { userId: 'userId', roles: ['patient'], params: { id: 'someOtherUserId' } };
      const res = { status: vi.fn().mockReturnThis(), json: vi.fn() };
      const next = vi.fn();

      await hasAccessToUser(req, res, next);

      expect(res.status).toHaveBeenCalledWith(403);
      expect(res.json).toHaveBeenCalledWith({ message: 'Unauthorized' });
      expect(next).not.toHaveBeenCalled();
    });
  });
});
