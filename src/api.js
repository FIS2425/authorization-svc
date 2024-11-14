import express from 'express';
import cors from 'cors';
import swaggerUI from 'swagger-ui-express';
import YAML from 'yamljs';
import userRoutes from './routes/userRoutes.js';
import validationRoutes from './routes/validationRoutes.js';
import cookieParser from 'cookie-parser';

const swaggerDocument = YAML.load('./openapi.yaml');

export default function () {
  const app = express();

  app.use(cors());
  app.use(express.json());
  app.use(express.urlencoded({ extended: true }));
  app.use(cookieParser());

  // Register routes
  app.use(`${process.env.API_PREFIX || '/'}`, userRoutes);
  app.use(`${process.env.API_PREFIX || '/'}`, validationRoutes);

  app.get(`${process.env.API_PREFIX || '/'}`, (req, res) => {
    res.send('API funcionando correctamente');
  });

  app.use('/docs', swaggerUI.serve, swaggerUI.setup(swaggerDocument));

  return app;
}
