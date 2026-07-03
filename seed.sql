-- Seed data for the SQL-injection lab.
-- Creates the `level1` database, a `products` table, sample rows,
-- and a low-privilege lab user used by get_db_connection().

CREATE DATABASE IF NOT EXISTS level1;

CREATE USER IF NOT EXISTS 'labuser'@'localhost' IDENTIFIED BY 'labpass';
GRANT SELECT ON level1.* TO 'labuser'@'localhost';
FLUSH PRIVILEGES;

USE level1;

-- Level 1: login-bypass scenario. Access is granted if the WHERE clause
-- (username AND password) matches any row; an injected OR defeats it.
-- The extra columns hold obviously-fake "private" data so the injection
-- clearly leaks information that should never be exposed.
DROP TABLE IF EXISTS users;
CREATE TABLE users (
    id            INT PRIMARY KEY AUTO_INCREMENT,
    username      VARCHAR(255) NOT NULL,
    password      VARCHAR(255) NOT NULL,
    role          VARCHAR(50)  NOT NULL DEFAULT 'user',
    email         VARCHAR(255),
    phone         VARCHAR(50),
    date_of_birth DATE,
    ssn           VARCHAR(50),
    credit_card   VARCHAR(50),
    salary        DECIMAL(10, 2),
    home_address  VARCHAR(255),
    api_key       VARCHAR(255),
    is_admin      TINYINT(1) NOT NULL DEFAULT 0
);

-- All values below are deliberately fake examples:
--   * @example.com is the reserved documentation domain (RFC 2606)
--   * 555-01xx phone numbers are the reserved fictional range
--   * 000-00-00xx are invalid SSNs
--   * 4111 1111 1111 1111 is the well-known Visa TEST card number
--   * api keys are prefixed sk_test_EXAMPLE_ and labelled DEMO-ONLY
-- A dummy row is inserted first so it gets the lowest id. This way the
-- "OR '1'='1" ordering-luck exploit returns this boring row (row 0), not admin.
INSERT INTO users (username, password, role, email, phone, date_of_birth, ssn, credit_card, salary, home_address, api_key, is_admin) VALUES
    ('dummy', 'dummy', 'dummy', 'dummy', 'dummy', NULL, 'dummy', 'dummy', 0.00, 'dummy', 'dummy', 0),
    ('admin', 's3cr3t_p@ss', 'admin', 'admin@example.com', '555-0100', '1980-01-01', '000-00-0000', '4111 1111 1111 1111', 250000.00, '123 Example Street, Exampleville, EX 00000', 'sk_test_EXAMPLE_ADMIN_DEMO_ONLY_0000', 1),
    ('alice', 'alicepw',      'user',  'alice@example.com', '555-0101', '1990-02-02', '000-00-0001', '4111 1111 1111 1111', 82000.00,  '456 Example Avenue, Exampleville, EX 00000', 'sk_test_EXAMPLE_ALICE_DEMO_ONLY_0001', 0),
    ('bob',   'bobpw',        'user',  'bob@example.com',   '555-0102', '1985-03-03', '000-00-0002', '4111 1111 1111 1111', 78000.00,  '789 Example Boulevard, Exampleville, EX 00000', 'sk_test_EXAMPLE_BOB_DEMO_ONLY_0002', 0),
    ('Max',   'password',       'user',  'max@example.com',   '555-0103', '1970-04-04', '000-00-0003', '4111 1111 1111 1111', 65000.00,  '321 Example Lane, Exampleville, EX 00000', 'sk_test_EXAMPLE_MAX_DEMO_ONLY_0003', 0);
