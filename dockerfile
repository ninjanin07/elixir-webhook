# Use Node.js 18 as the base image
FROM node:18

# Create and set the working directory
WORKDIR /app

# Copy the package.json and install dependencies
COPY package*.json ./
RUN npm install

# Copy the rest of the source code
COPY . .

# Expose the port (Vercel doesn’t use this, but it's useful locally)
EXPOSE 3000

# Run a basic HTTP server (we'll customize this if needed)
CMD ["node", "api/elixir.js"]
