import { beforeAll, afterAll } from 'vitest';
import supertest from 'supertest';

import * as db from './database';
import api from '../../src/api.js';
const app = api();

let server;
let request;

beforeAll(async () => {
  await db.connect();
  server = app.listen(0);
  request = supertest(server);
});

afterAll(async () => {
  await db.closeDatabase();
  server.close();
});

export { request };
