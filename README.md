# Authorization  Microservice

## ⚙️ Project Setup

### 1. Clone the Repository ⬇️

To begin, clone the repository using SSH, then install all necessary dependencies by running:

```bash
npm install
```

### 2. Environment Variables 🗝️

Create a `.env` file by duplicating the `.env.example` file provided in the repository. Add your MongoDB credentials and update the `URL` as needed.

### 3. Development 🛠️

For development, use the following command:

```bash
npm run dev
```

This command runs the project with `node --watch`, allowing hot-reloading during development, similar to `nodemon`.

### 4. Production 🚀

For production builds, start the application with:

```bash
npm start
```

### 5. Linting 🧹

To check for code quality using linters, run:

```bash
npm run lint
```

For automatic linting fixes, use:

```bash
npm run lint-fix
```

### 6. Testing 🧪

To run tests, use the following command:

```bash
npm test
```

### 7. Populating the Database 📚

To populate the database with sample data, run:

```bash
npm run populate <FileName>
```

### 8. Logging 📝

To add logs to your application, use the `logger` object provided in the `config/logger.js` file. The logger is configured to write logs to the console and a file in the `logs` directory. There are five log levels available:
- `error`
- `warn`
- `info`
- `http`
- `verbose`
- `debug`

#### Example:
You can log messages adding the following code to your methods:

```javascript
logger.error('This is an error message');
logger.http('Incoming HTTP request', {
  method: 'GET',
  url: '/api/appointments',
  userUid: 'a71b0cbd-7edd-4ae1-919b-403a33fba2eb',
  params: { date: '2024-11-04', status: 'confirmed' }
});
```

## Docker Setup 🐳

To run the application in a Docker container:

1. Modify the `/workdir` setting in the `Dockerfile` to match the corresponding microservice directory.
2. Update the `deploy-docker` workflow to deploy the correct microservice.

Once these changes are made, ensure Docker is installed and running on your system, then build and start the container with:

```bash
docker compose up -d
```

This command launches your deployed Docker image in detached mode.

## Kubernetes Setup ☸️

To run the application in Kubernetes (locally):

First, install Docker.

Then install kubernetes, kompose and minikube. You can see how to install them [here](https://kubernetes.io/docs/tasks/tools/).

Once done, run the following commands:

```bash
minikube start
kompose convert -o kubernetes/

alias kubectl='minikube kubectl --'
```

This should create the configuration for all your services from the `docker-compose.yml` file. For ease of setup, make sure all environment variables needed are directly or indirectly defined in your `docker-compose.yaml`.

Then, to create secrets for your environment variables, run:

```bash
kubectl create secret generic auth-secrets --from-env-file=.env -o yaml > kubernetes/secrets.yaml
```

Now go to your "-deployment.yaml" files and add for every secret environment variable add:

```yaml
- name: <env_var_name>
  valueFrom:
    secretKeyRef:
      name: auth-secrets
      key: <env_var_key>
```

Go to you app "-deployment.yaml" file and change the valie of the `image` field to the image you want to deploy. Most likely the lastest tag of your image on ghcr.

Go to any "-service.yaml" which ports you want to expose to the open internet and add:

```yaml
  type: LoadBalancer
  ports:
    - protocol: <svc_protocol> # Example: TCP
      port: <port>
      targetPort: <port>
      nodePort: <port_exposed> # Example: 30001
```

And then go to the other "-service.yaml" (mongodb and others) files and add the following:

```yaml
  type: ClusterIP
  ports:
    - protocol: <svc_protocol> # Example: TCP
      name: "<port>"
      port: <port>
      targetPort: <port>
```

Then finally, to deploy your services, run:

```bash
kubectl apply -f kubernetes/
minikube service <service_to_expose-1> <service_to_expose-2> ... <service_to_expose-n>
```
