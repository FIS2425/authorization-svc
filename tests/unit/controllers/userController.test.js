import { describe, beforeEach, afterEach, expect, it, vi } from 'vitest';
import jwt from 'jsonwebtoken';
import { request } from '../../setup/setup';
import User from '../../../src/schemas/User.js';
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

    it('should return 401 with invalid credentials', async () => {
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

      expect(response.status).toBe(401);
      expect(response.body.message).toBe('Invalid credentials');
    });

    it('should return 401 if user is not found', async () => {
      vi.spyOn(User, 'findOne').mockResolvedValue(null);

      const response = await request
        .post('/login')
        .send({ email: 'nonexistentuser@test.com', password: 'password' });

      expect(response.status).toBe(401);
      expect(response.body.message).toBe('User not found');
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
      vi.spyOn(jwt, 'verify').mockReturnValueOnce({ userId: 'userId', roles: ['clinicadmin'] });
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

      const response = await request
        .post('/users')
        .set('Cookie', ['token=authToken&refreshToken=refreshToken'])
        .send({
          email: 'email@test.com',
          password: 'password',
          roles: ['patient'],
        });

      expect(response.status).toBe(201);
      expect(response.body.email).toBe(user.email);
      expect(response.body.roles).toEqual(user.roles);
      expect(response.body).not.toHaveProperty('password');
    });

    it('should return 400 when required email and password not sent', async () => {
      const response = await request
        .post('/users')
        .set('Cookie', ['token=authToken&refreshToken=refreshToken'])
        .send({});

      expect(response.status).toBe(400);
      expect(response.body).toEqual({
        email: 'Email is required',
        password: 'Password is required',
      });
    });

    it('should return 400 when required email and password empty', async () => {
      const response = await request
        .post('/users')
        .set('Cookie', ['token=authToken&refreshToken=refreshToken'])
        .send({ email: '', password: '' });

      expect(response.status).toBe(400);
      expect(response.body).toEqual({
        email: 'Email is required',
        password: 'Password is required',
      });
    });

    it('should return 400 if user already exists', async () => {
      vi.spyOn(User, 'findOne').mockResolvedValue({
        _id: 'userId',
        email: 'email@test.com',
        password: 'password',
        roles: ['patient'],
      });
      const response = await request
        .post('/users')
        .set('Cookie', ['token=authToken&refreshToken=refreshToken'])
        .send({ email: 'email@test.com', password: 'password' });

      expect(response.status).toBe(400);
      expect(response.body.message).toBe('A user with that email already exists.');
    });

    it('should return 400 on failed user attr validation', async () => {
      const user = {
        email: 'email2.com',
        password: 'password',
        roles: ['user'],
      };

      vi.spyOn(User, 'create').mockResolvedValue(user);

      const response = await request
        .post('/users')
        .set('Cookie', ['token=authToken&refreshToken=refreshToken'])
        .send({
          email: 'email2.com',
          password: 'password',
          roles: ['user'],
        });

      expect(response.status).toBe(400);
      expect(response.body.messages).toEqual([
        'Invalid email address',
        '`user` is not a valid enum value for path `roles.0`.'
      ]);
    });

  });
});
