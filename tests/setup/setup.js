import { beforeAll, afterAll, vi } from 'vitest';
import supertest from 'supertest';
import { redisClient } from '../../src/config/redis.js';

import * as db from './database';
import api from '../../src/api.js';
const app = api();

let server;
let request;

beforeAll(async () => {
  await db.connect();
  await mockRedis();
  server = app.listen(0);
  request = supertest(server);
});

afterAll(async () => {
  await db.closeDatabase();
  server.close();
});

async function mockRedis() {
  // Mock Redis
  vi.mock('redis', () => {
    return import('redis-mock'); // Dynamically import 'redis-mock' for mocking
  });
  // We mock `exists` because `redis-mock` is not compatible with `redis 4`, so we change the behavior of the method
  vi.spyOn(redisClient, 'exists').mockImplementation((key) => {
    return new Promise((resolve, reject) => {
      redisClient.get(key, (err, value) => {
        if (err) {
          reject(false);
        } else {
          resolve(value ? 1 : 0);
        }
      });
    });
  });

  // We mock sAdd, sMembers, and sRem becase they do not exist in `redis-mock`. So we need to create them
  // Since `redis-mock` does not support sets, we need to create our own mockImplementation
  // Basically we will store the values as a comma separated string as a pseudo_set in a pseudo_secondaryindex
  redisClient.sMembers = (key) => {
    return new Promise((resolve, reject) => {
      redisClient.get(key, (err, value) => {
        if (err) {
          reject(false);
        } else {
          resolve(value ? value.split(',') : []);
        }
      });
    });
  };
  redisClient.sAdd = (key, value) => {
    return new Promise((resolve, reject) => {
      redisClient.sMembers(key, (err, members) => {
        if (err) {
          reject(false);
        } else {
          if (!members.includes(value)) {
            members.push(value);
          }
          redisClient.set(key, members.join(','), (err) => {
            if (err) {
              reject(false);
            } else {
              resolve(1);
            }
          });
        }
      });
    });
  };
  redisClient.sRem = (key, value) => {
    return new Promise((resolve, reject) => {
      redisClient.sMembers(key, (err, members) => {
        if (err) {
          reject(false);
        } else {
          const index = members.indexOf(value);
          if (index !== -1) {
            members.splice(index, 1);
          }
          redisClient.set(key, members.join(','), (err) => {
            if (err) {
              reject(false);
            } else {
              resolve(1);
            }
          });
        }
      });
    });
  };
  console.log('Redis mocked');
};

export { request };
