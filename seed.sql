-- Seed data for the SQL-injection lab.
-- Creates the `lab` database, a `users` table, sample rows,
-- and a low-privilege lab user used by get_db_connection().

CREATE DATABASE IF NOT EXISTS lab;

CREATE USER IF NOT EXISTS 'labuser'@'localhost' IDENTIFIED BY 'labpass';
GRANT SELECT ON lab.* TO 'labuser'@'localhost';
FLUSH PRIVILEGES;

USE lab;

-- Level 1: login-bypass scenario. Access is granted if the WHERE clause
-- (username AND password) matches any row; an injected OR defeats it.
-- The `iban` column holds obviously-fake "private" data so the injection
-- clearly leaks information that should never be exposed.
DROP TABLE IF EXISTS users;
CREATE TABLE users (
    username VARCHAR(255) PRIMARY KEY,
    password VARCHAR(255) NOT NULL,
    iban     VARCHAR(50),
    is_admin TINYINT(1)   NOT NULL DEFAULT 0
);

-- All IBAN values are deliberately fake (DE00 checksum is invalid).
-- The admin's IBAN is swapped for a breadcrumb: once you bypass the login as
-- admin, the leaked value tells you how many columns the table ha s (6) — the
-- count you need for the UNION SELECT schema-discovery step.
-- A dummy row is inserted first so it gets the lowest id. This way the
-- "OR '1'='1" ordering-luck exploit returns this boring row (row 0), not admin.
INSERT INTO users (username, password, iban, is_admin) VALUES
    ('admin', 's3cr3t_p@ss',  'DE00 2345 6789 0123 4567 89',  1),
    ('alice', 'alicepw',      'DE00 1111 1111 1111 1111 11',  0),
    ('bob',   'password',        'DE00 2222 2222 2222 2222 22',  0),
    ('Max',   'password',     'DE00 3333 3333 3333 3333 33',  0);
