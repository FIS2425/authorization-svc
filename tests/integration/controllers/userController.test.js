import { beforeAll, afterAll, describe, expect, it, vi } from 'vitest';
import { v4 as uuidv4 } from 'uuid';
import * as db from '../../setup/database';
import { request } from '../../setup/setup';
import User from '../../../src/schemas/User.js';
import { redisClient } from '../../../src/config/redis.js';
import jwt from 'jsonwebtoken';

const sampleUser = new User({
  _id: uuidv4(),
  email: 'testuser@test.com',
  password: 'password',
  roles: ['patient'],
});

const clinicAdmin = new User({
  _id: uuidv4(),
  email: 'clinicAdmin@test.com',
  password: 'password',
  roles: ['clinicadmin'],
});

const sampleUserToken = jwt.sign({ userId: sampleUser._id, roles: sampleUser.roles }, process.env.VITE_JWT_SECRET);
const clinicAdminToken = jwt.sign({ userId: clinicAdmin._id, roles: clinicAdmin.roles }, process.env.VITE_JWT_SECRET);

beforeAll(async () => {
  await db.clearDatabase();
  await sampleUser.save();
  await clinicAdmin.save();

  redisClient.set(sampleUserToken, sampleUser._id.toString(), async () => { });
  redisClient.set(clinicAdminToken, clinicAdmin._id.toString(), async () => { });

  // We mock `exists` because `redis-mock` is not compatible with `redis 4`, so we change the behavior of the method
  vi.spyOn(redisClient, 'exists').mockImplementation((key) => {
    return new Promise((resolve, reject) => {
      redisClient.get(key, (err, value) => {
        if (err) {
          reject(false);
        } else {
          console.log('Token exists', value);
          resolve(value ? 1 : 0);
        }
      });
    });
  });
});

afterAll(async () => {
  await db.clearDatabase();
});

describe('User Controller Integration Tests', () => {
  describe('login', () => {
    it('should login successfully with valid credentials', async () => {
      const response = await request
        .post('/login')
        .send({ email: 'testuser@test.com', password: 'password' });

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
        .send({ email: 'testuser@test.com', password: 'wrongpassword' });

      expect(response.status).toBe(401);
      expect(response.body.message).toBe('Invalid credentials');
    });

    it('should return 401 if user is not found', async () => {
      const response = await request
        .post('/login')
        .send({ email: 'nonexistentuser@test.com', password: 'password' });

      expect(response.status).toBe(401);
      expect(response.body.message).toBe('User not found');
    });
  });

  describe('logout', () => {
    it('should logout successfully', async () => {
      const loginResponse = await request
        .post('/login')
        .send({ email: 'testuser@test.com', password: 'password' });

      const cookies = loginResponse.headers['set-cookie'];

      const response = await request.post('/logout').set('Cookie', cookies);

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
        .send({ email: 'testuser@test.com', password: 'password' });

      const cookies = loginResponse.headers['set-cookie'];

      vi.spyOn(redisClient, 'del').mockRejectedValue(new Error('Redis error'));

      const response = await request.post('/logout').set('Cookie', cookies);

      expect(response.status).toBe(200);
      expect(response.body.message).toBe('Logout successful');
    });
  });

  describe('createUser', () => {
    it('should create a user successfully', async () => {
      const mockUser = {
        email: 'email@test.com',
        password: 'password',
        roles: ['patient'],
      };

      const response = await request
        .post('/users')
        .set('Cookie', [`token=${clinicAdminToken}`])
        .send({
          email: 'email@test.com',
          password: 'password',
          roles: ['patient'],
        });

      expect(response.status).toBe(201);
      expect(response.body.email).toBe(mockUser.email);
      expect(response.body.roles).toEqual(mockUser.roles);
      expect(response.body).not.toHaveProperty('password');
    });

    it('should return 400 when required email and password not sent', async () => {
      const response = await request
        .post('/users')
        .set('Cookie', [`token=${clinicAdminToken}`])
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
        .set('Cookie', [`token=${clinicAdminToken}`])
        .send({ email: '', password: '' });

      expect(response.status).toBe(400);
      expect(response.body).toEqual({
        email: 'Email is required',
        password: 'Password is required',
      });
    });

    it('should return 400 if user already exists', async () => {
      const response = await request
        .post('/users')
        .set('Cookie', [`token=${clinicAdminToken}`])
        .send({ email: 'testuser@test.com', password: 'password' });

      expect(response.status).toBe(400);
      expect(response.body.message).toBe('A user with that email already exists.');
    });

    it('should return 400 on failed user attr validation', async () => {
      const response = await request
        .post('/users')
        .set('Cookie', [`token=${clinicAdminToken}`])
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

    it('should return 403 if a non clinicadmin tries to create an user', async () => {
      const response = await request
        .post('/users')
        .set('Cookie', [`token=${sampleUserToken}`])
        .send({
          email: 'email2.com',
          password: 'password',
          roles: ['patient'],
        });

      expect(response.status).toBe(403);
      expect(response.body.message).toEqual('Unauthorized');
    });

  });
});
