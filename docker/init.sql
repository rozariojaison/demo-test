-- Create application and Konga databases
CREATE DATABASE app_db;
CREATE DATABASE konga_db;

-- Enable pgcrypto for gen_random_uuid() in app_db
\c app_db
CREATE EXTENSION IF NOT EXISTS pgcrypto;
