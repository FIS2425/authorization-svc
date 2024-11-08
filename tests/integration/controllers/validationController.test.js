import { describe, beforeAll, afterAll, it, vi, expect } from 'vitest';
import { request } from '../../setup/setup'; // Assuming this is your request setup, like Supertest
import { redisClient } from '../../../src/config/redis.js';
import { v4 as uuidv4 } from 'uuid';
import * as db from '../../setup/database';
import User from '../../../src/schemas/User.js';
import jwt from 'jsonwebtoken';

const sampleUser = new User({
  _id: uuidv4(),
  email: 'testuser@mail.com',
  password: 'password',
  roles: ['patient'],
});

beforeAll(async () => {
  await db.clearDatabase();
  await sampleUser.save();

  const token = jwt.sign({ userId: sampleUser._id, roles: sampleUser.roles }, process.env.VITE_JWT_SECRET);

  redisClient.set(token, sampleUser._id.toString(), async () => { console.log('Token set'); });

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

describe('Validation Middleware', () => {
  let token;

  beforeAll(async () => {
    token = jwt.sign({ userId: sampleUser._id, roles: sampleUser.roles }, process.env.VITE_JWT_SECRET);
    redisClient.set(token, sampleUser._id.toString(), async () => { console.log('Token set'); });
  });

  it('should validate the token successfully', async () => {
    const res = await request
      .get('/validate')
      .set('Cookie', `token=${token}`);

    expect(res.status).toBe(200);
  });

  it('should return 401 with no token provided', async () => {
    const res = await request
      .get('/validate')
      .set('Cookie', '');

    expect(res.status).toBe(401);
    expect(res.body.message).toBe('No token provided');
  });

  it('should return 401 with token expired', async () => {
    const expiredToken = jwt.sign({ userId: sampleUser._id, roles: sampleUser.roles }, process.env.VITE_JWT_SECRET, { expiresIn: 0 });

    const res = await request
      .get('/validate')
      .set('Cookie', `token=${expiredToken}`);

    expect(res.status).toBe(401);
    expect(res.body.message).toBe('Token expired');
  });

  it('should return 401 with token expired in dragonfly', async () => {
    // From here on out redis will not need to be accessed, so we can safely delete the token
    redisClient.del(token, () => { });

    const expiredToken = jwt.sign({ userId: sampleUser._id, roles: sampleUser.roles }, process.env.VITE_JWT_SECRET, { expiresIn: 0 });

    const res = await request
      .get('/validate')
      .set('Cookie', `token=${expiredToken}`);

    expect(res.status).toBe(401);
    expect(res.body.message).toBe('Token expired');
  });

  it('should return 401 if user is not found', async () => {
    const nonExistentUserId = uuidv4();
    const invalidToken = jwt.sign({ userId: nonExistentUserId, roles: sampleUser.roles }, process.env.VITE_JWT_SECRET);

    const res = await request
      .get('/validate')
      .set('Cookie', `token=${invalidToken}`);

    expect(res.status).toBe(401);
    expect(res.body.message).toBe('User not found');
  });

  it('should return 401 with invalid token (badly signed)', async () => {
    const invalidToken = 'invalid.token.value';

    const res = await request
      .get('/validate')
      .set('Cookie', `token=${invalidToken}`);

    expect(res.status).toBe(401);
    expect(res.body.message).toBe('Invalid token');
  });
});
