import express from 'express';
import cors from 'cors';
import swaggerUI from 'swagger-ui-express';
import YAML from 'yamljs';
import routes from './routes/userRoutes.js';

const swaggerDocument = YAML.load('./openapi.yaml');

export default function () {
  const app = express();

  app.use(cors());
  app.use(express.json());
  app.use(express.urlencoded({ extended: true }));

  // Register routes
  app.use('/', routes);

  app.get('/', (req, res) => {
    res.send('API funcionando correctamente');
  });

  app.use('/docs', swaggerUI.serve, swaggerUI.setup(swaggerDocument));

  return app;
}
