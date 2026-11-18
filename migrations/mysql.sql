-- Initial schema for a new installation with the starter PDO schema.
CREATE TABLE `User` (
    `user_id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `username` VARCHAR(191) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL,
    `password` VARCHAR(255) NULL,
    `status` INT NOT NULL DEFAULT 0,
    `secret` VARCHAR(128) NULL,
    `credential` JSON NULL,
    `password_expires_at` BIGINT NULL,
    PRIMARY KEY (`user_id`),
    UNIQUE KEY `user_username_unique` (`username`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
