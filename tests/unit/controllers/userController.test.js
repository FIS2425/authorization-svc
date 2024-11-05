import { describe, it, expect, vi } from 'vitest';
import request from 'supertest';
import express from 'express';
import * as userController from '../../../src/controllers/userController.js';
import User from '../../../src/schemas/User.js';
import jwt from 'jsonwebtoken';
import redisClient from '../../../src/config/redis.js';

vi.mock('../../../src/schemas/User.js');
vi.mock('jsonwebtoken');
vi.mock('../../../src/config/index.js');

const app = express();
app.use(express.json());
app.post('/login', userController.login);
app.post('/logout', userController.logout);

describe('User Controller', () => {
  describe('login', () => {
    it('should login successfully with valid credentials', async () => {
      const user = {
        _id: 'userId',
        username: 'testuser',
        password: 'password',
        roles: ['user'],
        comparePassword: vi.fn().mockResolvedValue(true),
      };

      User.findOne.mockResolvedValue(user);
      jwt.sign
        .mockReturnValueOnce('authToken')
        .mockReturnValueOnce('refreshToken');
      redisClient.set.mockResolvedValue(true);

      const response = await request(app)
        .post('/login')
        .send({ username: 'testuser', password: 'password' });

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
        username: 'testuser',
        password: 'password',
        comparePassword: vi.fn().mockResolvedValue(false),
      };

      User.findOne.mockResolvedValue(user);

      const response = await request(app)
        .post('/login')
        .send({ username: 'testuser', password: 'wrongpassword' });

      expect(response.status).toBe(401);
      expect(response.body.message).toBe('Invalid credentials');
    });

    it('should return 401 if user is not found', async () => {
      User.findOne.mockResolvedValue(null);

      const response = await request(app)
        .post('/login')
        .send({ username: 'nonexistentuser', password: 'password' });

      expect(response.status).toBe(401);
      expect(response.body.message).toBe('Invalid credentials');
    });
  });

  describe('logout', () => {
    it('should logout successfully', async () => {
      redisClient.del.mockResolvedValue(true);

      const response = await request(app)
        .post('/logout')
        .set('Cookie', ['token=authToken']);

      expect(response.status).toBe(200);
      expect(response.body.message).toBe('Logout successful');
    });

    it('should return 401 if not logged in', async () => {
      const response = await request(app).post('/logout');

      expect(response.status).toBe(401);
      expect(response.body.message).toBe('Not logged in');
    });

    it('should handle errors during logout', async () => {
      redisClient.del.mockRejectedValue(new Error('Redis error'));

      const response = await request(app)
        .post('/logout')
        .set('Cookie', ['token=authToken']);

      expect(response.status).toBe(200);
      expect(response.body.message).toBe('Logout successful');
    });
  });
});
