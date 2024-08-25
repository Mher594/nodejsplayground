CREATE TABLE users (
  id SERIAL PRIMARY KEY,
  email VARCHAR(255) UNIQUE NOT NULL,
  password TEXT NOT NULL,
  verification_token VARCHAR(64),
  verified BOOLEAN DEFAULT FALSE
);