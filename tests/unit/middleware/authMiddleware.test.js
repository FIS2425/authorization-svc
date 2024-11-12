import { afterEach, describe, expect, it, vi } from 'vitest';
import User from '../../../src/schemas/User.js';
import Role from '../../../src/schemas/Role.js';
import { userExists } from '../../../src/middleware/authMiddleware.js';
import { authorizeRequest } from '../../../src/middleware/authMiddleware.js';

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

  describe('authorizeRequest', () => {
    it('should call next if user has permission', async () => {
      const req = { method: 'get', originalUrl: '/users', userId: 'userId', ip: 'ip', roles: ['patient'], params: { id: 'userId' } };
      const res = { status: vi.fn().mockReturnThis(), json: vi.fn() };
      const next = vi.fn();

      vi.spyOn(User, 'findById').mockResolvedValue({ userId: 'userId', roles: ['patient'] });
      vi.spyOn(Role, 'find').mockResolvedValue([
        {
          role: 'patient',
          permissions: [{ method: 'get', onRoles: ['himself'] }],
        },
      ]);
      await authorizeRequest('get')(req, res, next);

      expect(next).toHaveBeenCalled();
    });

    it('should call next if can assign roles on create', async () => {
      const req = {
        method: 'create',
        originalUrl: '/users',
        userId: 'userId',
        ip: 'ip',
        roles: ['admin'],
        body: {
          email: 'email@test.com',
          password: 'password',
          roles: ['clinicadmin'],
        }
      };
      const res = { status: vi.fn().mockReturnThis(), json: vi.fn() };
      const next = vi.fn();

      vi.spyOn(User, 'findById').mockResolvedValue({ userId: 'userId', roles: ['clinicadmin'] });
      vi.spyOn(Role, 'find').mockResolvedValue([
        {
          role: 'admin',
          permissions: [{ method: 'create', onRoles: ['clinicadmin'] }],
        },
      ]);
      await authorizeRequest('create')(req, res, next);

      expect(next).toHaveBeenCalled();
    });

    it('should call next if can assign roles on edit', async () => {
      const req = {
        method: 'edit',
        originalUrl: '/users',
        userId: 'userId',
        ip: 'ip',
        roles: ['admin'],
        params: { id: 'clinicId' },
        body: {
          roles: ['clinicadmin'],
        }
      };
      const res = { status: vi.fn().mockReturnThis(), json: vi.fn() };
      const next = vi.fn();

      vi.spyOn(User, 'findById').mockResolvedValue({ userId: 'userId', roles: ['clinicadmin'] });
      vi.spyOn(Role, 'find').mockResolvedValue([
        {
          role: 'admin',
          permissions: [
            { method: 'edit', onRoles: ['clinicadmin'] },
          ],
        },
      ]);
      await authorizeRequest('edit')(req, res, next);

      expect(next).toHaveBeenCalled();
    });

    it('should return 400 if method is invalid', async () => {
      const req = { method: 'invalidMethod', originalUrl: '/users' };
      const res = { status: vi.fn().mockReturnThis(), json: vi.fn() };
      const next = vi.fn();

      await authorizeRequest('invalidMethod')(req, res, next);

      expect(res.status).toHaveBeenCalledWith(400);
      expect(res.json).toHaveBeenCalledWith({ message: 'Invalid method' });
      expect(next).not.toHaveBeenCalled();
    });

    it('should return 403 if user has no roles', async () => {
      const req = { method: 'get', originalUrl: '/users', userId: 'userId', ip: 'ip' };
      const res = { status: vi.fn().mockReturnThis(), json: vi.fn() };
      const next = vi.fn();

      await authorizeRequest('get')(req, res, next);

      expect(res.status).toHaveBeenCalledWith(403);
      expect(res.json).toHaveBeenCalledWith({ message: 'Forbidden' });
      expect(next).not.toHaveBeenCalled();
    });

    it('should return 403 if user has no permission on method', async () => {
      const req = { method: 'get', originalUrl: '/users', userId: 'userId', ip: 'ip', roles: ['patient'], params: { id: 'doctorId' } };
      const res = { status: vi.fn().mockReturnThis(), json: vi.fn() };
      const next = vi.fn();

      vi.spyOn(User, 'findById').mockResolvedValue({ userId: 'doctorId', roles: ['doctor'] });
      vi.spyOn(Role, 'find').mockResolvedValue([
        {
          role: 'patient',
          permissions: [{ method: 'get', onRoles: ['himself'] }],
        },
      ]);

      await authorizeRequest('get')(req, res, next);

      expect(res.status).toHaveBeenCalledWith(403);
      expect(res.json).toHaveBeenCalledWith({ message: 'Forbidden' });
      expect(next).not.toHaveBeenCalled();
    });

    it('should return 403 if user has no permission on roles on create', async () => {
      const req = {
        method: 'create',
        originalUrl: '/users',
        userId: 'userId',
        ip: 'ip',
        roles: ['admin'],
        body: {
          email: 'email@test.com',
          password: 'password',
          roles: ['clinicadmin'],
        }
      };

      const res = { status: vi.fn().mockReturnThis(), json: vi.fn() };
      const next = vi.fn();

      vi.spyOn(User, 'findById').mockResolvedValue({ userId: 'userId', roles: ['clinicadmin'] });
      vi.spyOn(Role, 'find').mockResolvedValue([
        {
          role: 'admin',
          permissions: [{ method: 'create', onRoles: ['patient'] }],
        },
      ]);
      await authorizeRequest('create')(req, res, next);

      expect(res.status).toHaveBeenCalledWith(403);
      expect(res.json).toHaveBeenCalledWith({ message: 'Forbidden' });
      expect(next).not.toHaveBeenCalled();
    });

    it('should return 403 if user has no permission on roles on edit', async () => {
      const req = {
        method: 'edit',
        originalUrl: '/users',
        userId: 'userId',
        ip: 'ip',
        roles: ['admin'],
        params: { id: 'clinicId' },
        body: {
          roles: ['clinicadmin'],
        }
      };
      const res = { status: vi.fn().mockReturnThis(), json: vi.fn() };
      const next = vi.fn();

      vi.spyOn(User, 'findById').mockResolvedValue({ userId: 'userId', roles: ['clinicadmin'] });
      vi.spyOn(Role, 'find').mockResolvedValue([
        {
          role: 'admin',
          permissions: [
            { method: 'edit', onRoles: ['patient'] },
          ],
        },
      ]);
      await authorizeRequest('edit')(req, res, next);

      expect(res.status).toHaveBeenCalledWith(403);
      expect(res.json).toHaveBeenCalledWith({ message: 'Forbidden' });
      expect(next).not.toHaveBeenCalled();
    });

    it('should return 403 if user has no permission target user', async () => {
      const req = {
        method: 'edit',
        originalUrl: '/users',
        userId: 'userId',
        ip: 'ip',
        roles: ['doctor'],
        params: { id: 'clinicId' },
        body: {
          roles: ['clinicadmin'],
        }
      };
      const res = { status: vi.fn().mockReturnThis(), json: vi.fn() };
      const next = vi.fn();

      vi.spyOn(User, 'findById').mockResolvedValue({ userId: 'userId', roles: ['clinicadmin'] });
      vi.spyOn(Role, 'find').mockResolvedValue([
        {
          role: 'admin',
          permissions: [
            { method: 'edit', onRoles: ['patient'] },
          ],
        },
      ]);
      await authorizeRequest('edit')(req, res, next);

      expect(res.status).toHaveBeenCalledWith(403);
      expect(res.json).toHaveBeenCalledWith({ message: 'Forbidden' });
      expect(next).not.toHaveBeenCalled();
    });

    it('should return 500 on server error', async () => {
      const req = { method: 'get', originalUrl: '/users', userId: 'userId', ip: 'ip', roles: ['patient'], params: { id: 'userId' } };
      const res = { status: vi.fn().mockReturnThis(), json: vi.fn() };
      const next = vi.fn();

      vi.spyOn(User, 'findById').mockResolvedValue(new Error('Database error'));

      await authorizeRequest('get')(req, res, next);

      expect(res.status).toHaveBeenCalledWith(500);
      expect(res.json).toHaveBeenCalledWith({ message: 'Internal server error' });
      expect(next).not.toHaveBeenCalled();
    });
  });
});
