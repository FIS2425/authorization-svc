import { beforeAll, afterAll, describe, expect, it, vi } from 'vitest';
import { v4 as uuidv4 } from 'uuid';
import * as db from '../../setup/database';
import { request } from '../../setup/setup';
import User from '../../../src/schemas/User.js';
import { redisClient } from '../../../src/config/redis.js';

const sampleUser = new User({
  _id: uuidv4(),
  username: 'testuser',
  password: 'password',
  roles: ['patient'],
});

beforeAll(async () => {
  await db.clearDatabase();
  await sampleUser.save();
});


afterAll(async () => {
  await db.clearDatabase();
});

describe('User Controller Integration Tests', () => {
  describe('login', () => {
    it('should login successfully with valid credentials', async () => {
      const response = await request
        .post('/login')
        .send({ username: 'testuser', password: 'password' }
        );

      expect(response.status).toBe(200);
      expect(response.body.message).toBe('Login successful');
      expect(response.headers['set-cookie']).toEqual(
        expect.arrayContaining([
          expect.stringContaining('token='),
          expect.stringContaining('refreshToken='),
        ])
      );
    });

    it('should return 401 with invalid credentials', async () => {
      const response = await request
        .post('/login')
        .send({ username: 'testuser', password: 'wrongpassword' });

      expect(response.status).toBe(401);
      expect(response.body.message).toBe('Invalid credentials');
    });

    it('should return 401 if user is not found', async () => {
      const response = await request
        .post('/login')
        .send({ username: 'nonexistentuser', password: 'password' });

      expect(response.status).toBe(401);
      expect(response.body.message).toBe('User not found');
    });
  });

  describe('logout', () => {
    it('should logout successfully', async () => {
      const loginResponse = await request
        .post('/login')
        .send({ username: 'testuser', password: 'password' });

      const cookies = loginResponse.headers['set-cookie'];

      const response = await request
        .post('/logout')
        .set('Cookie', cookies);

      expect(response.status).toBe(200);
      expect(response.body.message).toBe('Logout successful');
    });

    it('should return 401 if not logged in', async () => {
      const response = await request.post('/logout');

      expect(response.status).toBe(401);
      expect(response.body.message).toBe('Not logged in');
    });

    it('should handle errors during logout', async () => {
      const loginResponse = await request
        .post('/login')
        .send({ username: 'testuser', password: 'password' });

      const cookies = loginResponse.headers['set-cookie'];

      vi.spyOn(redisClient, 'del').mockRejectedValue(new Error('Redis error'));

      const response = await request
        .post('/logout')
        .set('Cookie', cookies);

      expect(response.status).toBe(200);
      expect(response.body.message).toBe('Logout successful');
    });
  });
});
