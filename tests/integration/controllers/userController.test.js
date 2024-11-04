import { describe, it, expect, vi } from 'vitest';
import request from 'supertest';
import express from 'express';
import cookieParser from 'cookie-parser';
import redisClient from '../../../src/config/index.js';
import * as userController from '../../../src/controllers/userController.js';
import User from '../../../src/schemas/User.js';

const app = express();
app.use(express.json());
app.use(cookieParser());
app.post('/login', userController.login);
app.post('/logout', userController.logout);

describe('User Controller Integration Tests', () => {
  describe('login', () => {
    it('should login successfully with valid credentials', async () => {
      const user = new User({
        username: 'testuser',
        password: 'password',
        roles: ['patient'],
      });
      await user.save();

      const response = await request(app)
        .post('/login')
        .send({ username: 'testuser', password: 'password' });

      expect(response.status).toBe(200);
      expect(response.body.message).toBe('Login successful');
      expect(response.headers['set-cookie']).toEqual(
        expect.arrayContaining([
          expect.stringContaining('token='),
          expect.stringContaining('refreshToken='),
        ])
      );

      await User.deleteOne({ username: 'testuser' });
    });

    it('should return 401 with invalid credentials', async () => {
      const user = new User({
        username: 'testuser',
        password: 'password',
        roles: ['patient'],
      });
      await user.save();

      const response = await request(app)
        .post('/login')
        .send({ username: 'testuser', password: 'wrongpassword' });

      expect(response.status).toBe(401);
      expect(response.body.message).toBe('Invalid credentials');

      await User.deleteOne({ username: 'testuser' });
    });

    it('should return 401 if user is not found', async () => {
      const response = await request(app)
        .post('/login')
        .send({ username: 'nonexistentuser', password: 'password' });

      expect(response.status).toBe(401);
      expect(response.body.message).toBe('Invalid credentials');
    });
  });

  describe('logout', () => {
    it('should logout successfully', async () => {
      const user = new User({
        username: 'testuser',
        password: 'password',
        roles: ['patient'],
      });
      await user.save();

      const loginResponse = await request(app)
        .post('/login')
        .send({ username: 'testuser', password: 'password' });

      const cookies = loginResponse.headers['set-cookie'];

      const response = await request(app)
        .post('/logout')
        .set('Cookie', cookies);

      expect(response.status).toBe(200);
      expect(response.body.message).toBe('Logout successful');

      await User.deleteOne({ username: 'testuser' });
    });

    it('should return 401 if not logged in', async () => {
      const response = await request(app).post('/logout');

      expect(response.status).toBe(401);
      expect(response.body.message).toBe('Not logged in');
    });

    it('should handle errors during logout', async () => {
      const user = new User({
        username: 'testuser',
        password: 'password',
        roles: ['patient'],
      });
      await user.save();

      const loginResponse = await request(app)
        .post('/login')
        .send({ username: 'testuser', password: 'password' });

      const cookies = loginResponse.headers['set-cookie'];

      vi.spyOn(redisClient, 'del').mockRejectedValue(new Error('Redis error'));

      const response = await request(app)
        .post('/logout')
        .set('Cookie', cookies);

      expect(response.status).toBe(200);
      expect(response.body.message).toBe('Logout successful');

      await User.deleteOne({ username: 'testuser' });
    });
  });
});
