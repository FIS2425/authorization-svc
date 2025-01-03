import { describe, beforeEach, afterEach, expect, it, vi } from 'vitest';
import speakeasy from 'speakeasy';
import jwt from 'jsonwebtoken';
import { request } from '../../setup/setup';
import User from '../../../src/schemas/User.js';
import Role from '../../../src/schemas/Role.js';
import { redisClient } from '../../../src/config/redis.js';

afterEach(() => {
  vi.resetAllMocks();
});

describe('User Controller', () => {
  describe('login', () => {
    it('should login successfully with valid credentials', async () => {
      const user = {
        _id: 'userId',
        email: 'testuser@test.com',
        password: 'password',
        roles: ['user'],
        comparePassword: vi.fn().mockResolvedValue(true),
        toObject: vi.fn().mockReturnValue({
          _id: 'userId',
          email: 'testuser@test.com',
          password: 'password',
          roles: ['user'],
        }),
      };

      vi.spyOn(User, 'findOne').mockResolvedValue(user);
      vi.spyOn(jwt, 'sign')
        .mockReturnValueOnce('authToken')
        .mockReturnValueOnce('refreshToken');
      vi.spyOn(redisClient, 'set').mockResolvedValue(true);

      const response = await request
        .post('/login')
        .send({ email: 'testuser@test.com', password: 'password' });

      expect(response.status).toBe(200);
      expect(response.body.message).toBe('Login successful');
      expect(response.headers['set-cookie']).toEqual(
        expect.arrayContaining([
          expect.stringContaining('token=authToken'),
          expect.stringContaining('refreshToken=refreshToken'),
        ])
      );
    });

    it('should not login with valid credentials and 2fa', async () => {
      const user = {
        _id: 'userId',
        email: 'testuser@test.com',
        password: 'password',
        roles: ['user'],
        totpSecret: 'secret',
        comparePassword: vi.fn().mockResolvedValue(true),
      };

      vi.spyOn(User, 'findOne').mockResolvedValue(user);

      const response = await request
        .post('/login')
        .send({ email: 'testuser@test.com', password: 'password' });

      expect(response.status).toBe(200);
      expect(response.body.message).toBe(
        'Credentials validated, please verify 2FA token'
      );
      expect(response.headers).not.toHaveProperty('set-cookie');
    });

    it('should return 400 with invalid credentials', async () => {
      const user = {
        _id: 'userId',
        email: 'testuser@test.com',
        password: 'password',
        comparePassword: vi.fn().mockResolvedValue(false),
      };

      vi.spyOn(User, 'findOne').mockResolvedValue(user);

      const response = await request
        .post('/login')
        .send({ email: 'testuser@test.com', password: 'wrongpassword' });

      expect(response.status).toBe(400);
      expect(response.body.message).toBe('Invalid credentials');
    });

    it('should return 400 if user is not found', async () => {
      vi.spyOn(User, 'findOne').mockResolvedValue(null);

      const response = await request
        .post('/login')
        .send({ email: 'nonexistentuser@test.com', password: 'password' });

      expect(response.status).toBe(400);
      expect(response.body.message).toBe('Invalid credentials');
    });
  });

  describe('logout', () => {
    it('should logout successfully', async () => {
      vi.spyOn(jwt, 'verify').mockReturnValueOnce({ userId: 'userId' });
      vi.spyOn(redisClient, 'del').mockResolvedValue(true);

      const response = await request
        .post('/logout')
        .set('Cookie', ['token=authToken&refreshToken=refreshToken']);

      expect(response.status).toBe(200);
      expect(response.body.message).toBe('Logout successful');
    });

    it('should return 401 if not logged in', async () => {
      const response = await request.post('/logout');

      expect(response.status).toBe(401);
      expect(response.body.message).toBe('Not logged in');
    });

    it('should handle errors during logout', async () => {
      vi.spyOn(jwt, 'verify').mockReturnValueOnce({ userId: 'userId' });
      vi.spyOn(redisClient, 'del').mockResolvedValue(false);

      const response = await request
        .post('/logout')
        .set('Cookie', ['token=authToken&refreshToken=refreshToken']);

      expect(response.status).toBe(200);
      expect(response.body.message).toBe('Logout successful');
    });
  });

  describe('createUser', () => {
    // Mock middlewares
    beforeEach(() => {
      const user = {
        email: 'email@test.com',
        password: 'password',
        roles: ['clinicadmin'],
      };
      vi.spyOn(jwt, 'verify').mockReturnValueOnce({
        userId: 'userId',
        roles: ['clinicadmin'],
      });
      vi.spyOn(User, 'findById').mockResolvedValue(user);
      vi.spyOn(redisClient, 'exists').mockResolvedValue(true);
    });

    it('should create a user successfully', async () => {
      const user = {
        email: 'email@test.com',
        password: 'password',
        roles: ['patient'],
      };

      vi.spyOn(User, 'create').mockResolvedValue(user);
      vi.spyOn(Role, 'find').mockResolvedValue([
        {
          role: 'clinicadmin',
          permissions: [
            { method: 'create', onRoles: ['doctor', 'patient', 'himself'] },
          ],
        },
      ]);

      const response = await request
        .post('/users')
        .set('Cookie', ['token=authToken&refreshToken=refreshToken'])
        .send({
          email: 'email@test.com',
          password: 'pAssw0rd!',
          roles: ['patient'],
        });

      expect(response.status).toBe(201);
      expect(response.body.email).toBe(user.email);
      expect(response.body.roles).toEqual(user.roles);
      expect(response.body).not.toHaveProperty('password');
    });

    it('should return 400 when required email and password not sent', async () => {
      vi.spyOn(Role, 'find').mockResolvedValue([
        {
          role: 'clinicadmin',
          permissions: [
            { method: 'create', onRoles: ['doctor', 'patient', 'himself'] },
          ],
        },
      ]);

      const response = await request
        .post('/users')
        .set('Cookie', ['token=authToken&refreshToken=refreshToken'])
        .send({});

      expect(response.status).toBe(400);
      expect(response.body).toEqual({
        message: 'Validation error',
        errors: {
          email: 'Email is required',
          password: 'Password is required',
        },
      });
    });

    it('should return 400 when required email and password empty', async () => {
      vi.spyOn(Role, 'find').mockResolvedValue([
        {
          role: 'clinicadmin',
          permissions: [
            { method: 'create', onRoles: ['doctor', 'patient', 'himself'] },
          ],
        },
      ]);

      const response = await request
        .post('/users')
        .set('Cookie', ['token=authToken&refreshToken=refreshToken'])
        .send({ email: '', password: '' });

      expect(response.status).toBe(400);
    });

    it('should return 400 if user already exists', async () => {
      vi.spyOn(User, 'findOne').mockResolvedValue({
        _id: 'userId',
        email: 'email@test.com',
        password: 'pAssw0rd!',
        roles: ['patient'],
      });
      vi.spyOn(Role, 'find').mockResolvedValue([
        {
          role: 'clinicadmin',
          permissions: [
            { method: 'create', onRoles: ['doctor', 'patient', 'himself'] },
          ],
        },
      ]);

      const response = await request
        .post('/users')
        .set('Cookie', ['token=authToken&refreshToken=refreshToken'])
        .send({
          email: 'email@test.com',
          password: 'pAssw0rd!',
          roles: ['patient'],
        });

      expect(response.status).toBe(400);
      expect(response.body.message).toBe(
        'A user with that email already exists.'
      );
    });

    it('should return 400 on failed user attr validation', async () => {
      const user = {
        email: 'email2@email.com',
        password: 'pAssw0rd!',
        roles: ['patient'],
      };

      vi.spyOn(User, 'create').mockResolvedValue(user);
      vi.spyOn(Role, 'find').mockResolvedValue([
        {
          role: 'clinicadmin',
          permissions: [
            { method: 'create', onRoles: ['doctor', 'patient', 'himself'] },
          ],
        },
      ]);

      const response = await request
        .post('/users')
        .set('Cookie', ['token=authToken&refreshToken=refreshToken'])
        .send({
          email: 'email2.com',
          password: 'password!',
          roles: ['patient'],
        });

      expect(response.status).toBe(400);
      expect(response.body).toEqual({
        message: 'Validation error',
        errors: {
          email: 'Invalid email address',
          password:
                        'Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character',
        },
      });
    });
  });

  describe('editUser', () => {
    // Mock middlewares
    beforeEach(() => {
      const user = {
        email: 'email@test.com',
        password: 'password',
        roles: ['clinicadmin'],
      };
      vi.spyOn(jwt, 'verify').mockReturnValueOnce({
        userId: 'userId',
        roles: ['clinicadmin'],
      });
      vi.spyOn(User, 'findById').mockResolvedValue(user);
      vi.spyOn(redisClient, 'exists').mockResolvedValue(true);
    });

    it('should edit a user successfully same email', async () => {
      const user = {
        _id: 'userId',
        email: 'email@test.com',
        password: 'password',
        roles: ['patient'],
      };
      user.toObject = vi.fn().mockReturnValue(user);
      user.save = vi.fn().mockReturnThis();

      vi.spyOn(User, 'findById').mockResolvedValue(user);
      vi.spyOn(User, 'findOne').mockResolvedValue(user);
      vi.spyOn(Role, 'find').mockResolvedValue([
        {
          role: 'clinicadmin',
          permissions: [
            { method: 'edit', onRoles: ['doctor', 'patient', 'himself'] },
          ],
        },
      ]);

      const response = await request
        .put('/users/userId')
        .set('Cookie', ['token=authToken&refreshToken=refreshToken'])
        .send({
          email: 'email@test.com',
          password: 'pAssw0rd!',
          roles: ['patient'],
        });

      expect(response.status).toBe(200);
      expect(response.body.email).toBe(user.email);
      expect(response.body.roles).toEqual(user.roles);
      expect(response.body).not.toHaveProperty('password');
    });

    it('should edit a user successfully diff email', async () => {
      const user = {
        _id: 'userId',
        email: 'email@test.com',
        password: 'password',
        roles: ['patient'],
      };
      user.toObject = vi.fn().mockReturnValue(user);
      user.save = vi.fn().mockReturnThis();

      vi.spyOn(User, 'findById').mockResolvedValue(user);
      vi.spyOn(User, 'findOne').mockResolvedValue(null);
      vi.spyOn(Role, 'find').mockResolvedValue([
        {
          role: 'clinicadmin',
          permissions: [
            { method: 'edit', onRoles: ['doctor', 'patient', 'himself'] },
          ],
        },
      ]);

      const response = await request
        .put('/users/userId')
        .set('Cookie', ['token=authToken&refreshToken=refreshToken'])
        .send({
          email: 'email@test2.com',
          password: 'pAssw0rd!',
          roles: ['patient'],
        });

      expect(response.status).toBe(200);
      expect(response.body.email).toBe(user.email);
      expect(response.body.roles).toEqual(user.roles);
      expect(response.body).not.toHaveProperty('password');
    });

    it('should return 400 when email in use', async () => {
      const user = {
        _id: 'userId',
        email: 'email@test.com',
        password: 'password',
        roles: ['patient'],
      };
      user.toObject = vi.fn().mockReturnValue(user);
      user.save = vi.fn().mockReturnThis();

      vi.spyOn(User, 'findById').mockResolvedValue(user);
      vi.spyOn(User, 'findOne').mockResolvedValue({
        _id: 'userId2',
      });
      vi.spyOn(Role, 'find').mockResolvedValue([
        {
          role: 'clinicadmin',
          permissions: [
            { method: 'edit', onRoles: ['doctor', 'patient', 'himself'] },
          ],
        },
      ]);

      const response = await request
        .put('/users/userId')
        .set('Cookie', ['token=authToken&refreshToken=refreshToken'])
        .send({
          email: 'email@test2.com',
          password: 'pAssw0rd!',
          roles: ['patient'],
        });

      expect(response.status).toBe(400);
      expect(response.body.message).toBe(
        'A user with that email already exists.'
      );
    });

    it('should return 400 on failed user attr validation', async () => {
      const user = {
        _id: 'userId',
        email: 'email@test.com',
        password: 'password',
        roles: ['patient'],
      };
      user.toObject = vi.fn().mockReturnValue(user);
      user.save = vi.fn().mockReturnThis();

      vi.spyOn(User, 'findById').mockResolvedValue(user);
      vi.spyOn(Role, 'find').mockResolvedValue([
        {
          role: 'clinicadmin',
          permissions: [
            { method: 'edit', onRoles: ['doctor', 'patient', 'himself'] },
          ],
        },
      ]);

      const response = await request
        .put('/users/userId')
        .set('Cookie', ['token=authToken&refreshToken=refreshToken'])
        .send({
          email: 'email',
          password: 'password!',
          roles: [],
        });

      expect(response.status).toBe(400);
      expect(response.body).toEqual({
        message: 'Validation error',
        errors: {
          email: 'Invalid email address',
          password:
                        'Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character',
          roles: 'At least one role is required.',
        },
      });
    });
  });

  describe('getUser', () => {
    // Mock middlewares
    beforeEach(() => {
      vi.spyOn(jwt, 'verify').mockReturnValueOnce({
        userId: 'userId',
        roles: ['clinicadmin'],
      });
      vi.spyOn(redisClient, 'exists').mockResolvedValue(true);
    });

    it('should return user successfully', async () => {
      const user = new User({
        _id: 'userId',
        email: 'email@email.com',
        password: 'password',
        roles: ['doctor'],
      });

      vi.spyOn(User, 'findById').mockResolvedValue(user);
      vi.spyOn(Role, 'find').mockResolvedValue([
        {
          role: 'clinicadmin',
          permissions: [
            { method: 'get', onRoles: ['doctor', 'patient', 'himself'] },
          ],
        },
      ]);

      const response = await request
        .get('/users/userId')
        .set('Cookie', ['token=authToken&refreshToken=refreshToken']);

      expect(response.status).toBe(200);
      expect(response.body.email).toBe(user.email);
      expect(response.body.roles).toEqual(user.roles);
      expect(response.body).not.toHaveProperty('password');
    });

    it('should return 404 if user is not found', async () => {
      // the first call to `User.findById` is on the middleware
      vi.spyOn(User, 'findById')
        .mockReturnValueOnce({})
        .mockResolvedValue(null);

      const response = await request
        .get('/users/userId')
        .set('Cookie', ['token=authToken&refreshToken=refreshToken']);

      expect(response.status).toBe(404);
      expect(response.body).toEqual({ message: 'User not found' });
    });

    it('should return 500 if there is an error retrieving user', async () => {
      const errorMessage = 'Database error';
      vi.spyOn(User, 'findById')
        .mockReturnValueOnce({})
        .mockResolvedValue(new Error(errorMessage));
      vi.spyOn(Role, 'find').mockResolvedValue([
        {
          role: 'clinicadmin',
          permissions: [
            { method: 'get', onRoles: ['doctor', 'patient', 'himself'] },
          ],
        },
      ]);

      const response = await request
        .get('/users/userId')
        .set('Cookie', ['token=authToken&refreshToken=refreshToken']);

      expect(response.status).toBe(500);
      expect(response.body).toEqual({ message: 'Internal server error' });
    });
  });

  describe('deleteUser', () => {
    beforeEach(() => {
      const user = {
        email: 'email@test.com',
        password: 'password',
        roles: ['clinicadmin'],
      };
      vi.spyOn(jwt, 'verify').mockReturnValueOnce({
        userId: 'userId',
        roles: ['clinicadmin'],
      });
      vi.spyOn(User, 'findById').mockResolvedValue(user);
      vi.spyOn(redisClient, 'exists').mockResolvedValue(true);
    });

    it('should delete user successfully', async () => {
      const user = {
        _id: 'userId',
        email: 'email@email.com',
        password: 'password',
        roles: ['doctor'],
      };

      vi.spyOn(User, 'findById').mockResolvedValue(user);
      vi.spyOn(User, 'findOne').mockResolvedValue(user);
      vi.spyOn(Role, 'find').mockResolvedValue([
        {
          role: 'clinicadmin',
          permissions: [
            { method: 'delete', onRoles: ['doctor', 'patient', 'himself'] },
          ],
        },
      ]);
      vi.spyOn(User, 'findByIdAndDelete').mockResolvedValue(user);
      vi.spyOn(redisClient, 'del').mockResolvedValue(true);

      const response = await request
        .delete('/users/userId')
        .set('Cookie', ['token=authToken&refreshToken=refreshToken']);

      expect(response.status).toBe(204);
    });

    it('should return 404 if user is not found', async () => {
      const user = {
        _id: 'userId',
        email: 'email@email.com',
        password: 'password',
        roles: ['doctor'],
      };

      vi.spyOn(User, 'findById')
        .mockReturnValueOnce(user)
        .mockResolvedValue(null);
      vi.spyOn(User, 'findOne').mockResolvedValue(user);
      vi.spyOn(Role, 'find').mockResolvedValue([
        {
          role: 'clinicadmin',
          permissions: [
            { method: 'delete', onRoles: ['doctor', 'patient', 'himself'] },
          ],
        },
      ]);

      const response = await request
        .delete('/users/userId')
        .set('Cookie', ['token=authToken&refreshToken=refreshToken']);

      expect(response.status).toBe(404);
      expect(response.body).toEqual({ message: 'User not found' });
    });

    it('should return 500 if there is an error deleting user', async () => {
      const user = {
        _id: 'userId',
        email: 'email@email.com',
        password: 'password',
        roles: ['doctor'],
      };

      vi.spyOn(User, 'findById').mockResolvedValue(user);
      vi.spyOn(User, 'findOne').mockResolvedValue(user);
      vi.spyOn(Role, 'find').mockResolvedValue([
        {
          role: 'clinicadmin',
          permissions: [
            { method: 'delete', onRoles: ['doctor', 'patient', 'himself'] },
          ],
        },
      ]);
      const errorMessage = 'Database error';
      vi.spyOn(User, 'findByIdAndDelete').mockRejectedValue(
        new Error(errorMessage)
      );

      const response = await request
        .delete('/users/userId')
        .set('Cookie', ['token=authToken&refreshToken=refreshToken']);

      expect(response.status).toBe(500);
      expect(response.body).toEqual({ message: 'Internal server error' });
    });
  });

  describe('changePassword', () => {
    beforeEach(() => {
      vi.spyOn(jwt, 'verify').mockReturnValueOnce({
        userId: 'userId',
        roles: ['clinicadmin'],
      });
      vi.spyOn(redisClient, 'exists').mockResolvedValue(true);
    });

    it('should change password successfully', async () => {
      const user = new User({
        _id: 'userId',
        email: 'email@email.com',
        password: 'password',
        roles: ['doctor'],
      });
      user.comparePassword = vi.fn().mockResolvedValue(true);
      user.save = vi.fn().mockReturnThis();

      vi.spyOn(User, 'findById').mockResolvedValue(user);
      vi.spyOn(Role, 'find').mockResolvedValue([
        {
          role: 'clinicadmin',
          permissions: [
            {
              method: 'changePassword',
              onRoles: ['doctor', 'patient', 'himself'],
            },
          ],
        },
      ]);

      const response = await request
        .post('/users/change-password')
        .set('Cookie', ['token=authToken&refreshToken=refreshToken'])
        .send({
          currentPassword: 'password',
          newPassword: 'newPassword!123',
        });

      expect(response.status).toBe(200);
      expect(response.body.message).toBe('Password changed successfully');
    });

    it('should return 400 if old password is incorrect', async () => {
      const user = new User({
        _id: 'userId',
        email: 'email@email.com',
        password: 'password',
        roles: ['doctor'],
      });
      user.comparePassword = vi.fn().mockResolvedValue(false);

      vi.spyOn(User, 'findById').mockResolvedValue(user);
      vi.spyOn(Role, 'find').mockResolvedValue([
        {
          role: 'clinicadmin',
          permissions: [
            {
              method: 'changePassword',
              onRoles: ['doctor', 'patient', 'himself'],
            },
          ],
        },
      ]);

      const response = await request
        .post('/users/change-password')
        .set('Cookie', ['token=authToken&refreshToken=refreshToken'])
        .send({
          currentPassword: 'wrongPassword',
          newPassword: 'newPassword!123',
        });

      expect(response.status).toBe(400);
      expect(response.body.message).toBe('Invalid credentials');
    });

    it('should return 500 on error changing password', async () => {
      const user = new User({
        _id: 'userId',
        email: 'email@email.com',
        password: 'password',
        roles: ['doctor'],
      });
      user.comparePassword = vi
        .fn()
        .mockRejectedValue(new Error('Database error'));

      vi.spyOn(User, 'findById').mockResolvedValue(user);
      vi.spyOn(Role, 'find').mockResolvedValue([
        {
          role: 'clinicadmin',
          permissions: [
            {
              method: 'changePassword',
              onRoles: ['doctor', 'patient', 'himself'],
            },
          ],
        },
      ]);

      const response = await request
        .post('/users/change-password')
        .set('Cookie', ['token=authToken&refreshToken=refreshToken'])
        .send({
          currentPassword: 'password',
          newPassword: 'newPassword!123',
        });

      expect(response.status).toBe(500);
      expect(response.body.message).toBe('Error when authenticating');
    });
  });

  describe('enable2FA', () => {
    beforeEach(() => {
      vi.spyOn(jwt, 'verify').mockReturnValueOnce({
        userId: 'userId',
        roles: ['clinicadmin'],
      });
      vi.spyOn(redisClient, 'exists').mockResolvedValue(true);
    });

    it('should return 200', async () => {
      vi.spyOn(User, 'findById').mockResolvedValue({
        _id: 'userId',
        email: 'email@email.com',
        password: 'Password.1',
        roles: ['clinicadmin'],
        totpSecret: null,
        save: vi.fn().mockReturnThis(),
      });

      const response = await request
        .post('/users/enable-2fa')
        .set('Cookie', ['token=authToken&refreshToken=refreshToken']);

      expect(response.status).toBe(200);
      expect(response.body.message).toBe('2FA enabled successfully');
      expect(response.body).toHaveProperty('qrCodeUrl');
    });

    it('should return 500 on qrcode error', async () => {
      vi.spyOn(User, 'findById').mockResolvedValue({
        _id: 'userId',
        email: 'email@email.com',
        password: 'Password.1',
        roles: ['clinicadmin'],
        totpSecret: null,
        save: vi.fn().mockReturnThis(),
      });

      vi.spyOn(speakeasy, 'generateSecret').mockImplementation(() => {
        throw new Error('QR code error');
      });

      const response = await request
        .post('/users/enable-2fa')
        .set('Cookie', ['token=authToken&refreshToken=refreshToken']);

      expect(response.status).toBe(500);
      expect(response.body.message).toBe('Internal server error');
    });

    it('should return 500 on server error', async () => {
      vi.spyOn(User, 'findById').mockResolvedValue({
        _id: 'userId',
        email: 'email@email.com',
        password: 'Password.1',
        roles: ['clinicadmin'],
        totpSecret: null,
        save: vi.fn().mockImplementation(() => {
          throw new Error('User save error');
        }),
      });

      const response = await request
        .post('/users/enable-2fa')
        .set('Cookie', ['token=authToken&refreshToken=refreshToken']);

      expect(response.status).toBe(500);
      expect(response.body.message).toBe('Internal server error');
    });
  });

  describe('verify2FA', () => {
    beforeEach(() => {
      vi.spyOn(jwt, 'verify').mockReturnValueOnce({
        userId: 'userId',
        roles: ['clinicadmin'],
      });
      vi.spyOn(redisClient, 'exists').mockResolvedValue(true);
    });

    it('should return 200', async () => {
      vi.spyOn(User, 'findById').mockResolvedValue({
        _id: 'userId',
        email: 'email@email.com',
        password: 'Password.1',
        roles: ['clinicadmin'],
        totpSecret: 'secret',
      });

      vi.spyOn(speakeasy.totp, 'verify').mockReturnValueOnce(true);

      vi.spyOn(jwt, 'sign')
        .mockReturnValueOnce('authToken')
        .mockReturnValueOnce('refreshToken');

      vi.spyOn(redisClient, 'del').mockResolvedValue(true);
      vi.spyOn(redisClient, 'set').mockResolvedValue(true);
      vi.spyOn(redisClient, 'sadd').mockResolvedValue(true);

      const response = await request.post('/users/verify-2fa').send({
        userId: 'userId',
        totpToken: '123456',
      });

      expect(response.status).toBe(200);
      expect(response.body.message).toBe('Login successful');
      expect(response.headers['set-cookie']).toEqual(
        expect.arrayContaining([
          expect.stringContaining('token=authToken'),
          expect.stringContaining('refreshToken=refreshToken'),
        ])
      );
    });

    it('should return 400 if no session exists', async () => {
      vi.spyOn(User, 'findById').mockResolvedValue({
        _id: 'userId',
        email: 'email@email.com',
        password: 'Password.1',
        roles: ['clinicadmin'],
        totpSecret: 'secret',
      });

      vi.spyOn(redisClient, 'exists').mockResolvedValueOnce(false);

      const response = await request.post('/users/verify-2fa').send({
        userId: 'userId',
        totpToken: '123456',
      });

      expect(response.status).toBe(403);
      expect(response.body.message).toBe('2FA session expired or invalid');
    });

    it('should return 400 if token is invalid', async () => {
      vi.spyOn(User, 'findById').mockResolvedValue({
        _id: 'userId',
        email: 'email@email.com',
        password: 'Password.1',
        roles: ['clinicadmin'],
        totpSecret: 'secret',
      });

      const response = await request.post('/users/verify-2fa').send({
        userId: 'userId',
        totpToken: '123456',
      });

      expect(response.status).toBe(400);
      expect(response.body.message).toBe('Invalid 2FA token');
    });

    it('should return 403 if 2FA not enabled', async () => {
      vi.spyOn(User, 'findById').mockResolvedValue({
        _id: 'userId',
        email: 'email@email.com',
        password: 'Password.1',
        roles: ['clinicadmin'],
        totpSecret: null,
      });

      const response = await request.post('/users/verify-2fa').send({
        userId: 'userId',
        totpToken: '123456',
      });

      expect(response.status).toBe(403);
      expect(response.body.message).toBe('2FA not enabled for this user');
    });

    it('should return 404 if no user exists', async () => {
      vi.spyOn(User, 'findById').mockResolvedValue(null);

      const response = await request.post('/users/verify-2fa').send({
        userId: 'userId',
        totpToken: '123456',
      });

      expect(response.status).toBe(404);
      expect(response.body.message).toBe('User not found');
    });
      });
});
