-- Initial schema for a new installation with the starter PDO schema.
CREATE TABLE `User` (
    `user_id` INTEGER PRIMARY KEY,
    `username` TEXT NOT NULL UNIQUE,
    `password` TEXT,
    `status` INTEGER NOT NULL DEFAULT 0,
    `secret` TEXT,
    `credential` TEXT,
    `password_expires_at` INTEGER
);
