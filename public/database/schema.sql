DROP DATABASE IF EXISTS mtaamarket;
CREATE DATABASE mtaamarket;
USE mtaamarket;
DROP TABLE IF EXISTS admins;
CREATE TABLE admins(
    id int AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(100),
    email VARCHAR(150) NOT NULL UNIQUE,
    password_hash VARCHAR(255),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP


);
DROP TABLE IF EXISTS categories;
CREATE TABLE categories(
    id int AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(100) NOT NULL UNIQUE,
    slug VARCHAR(150) NOT NULL UNIQUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP


);
DROP TABLE IF EXISTS products;
CREATE TABLE products(
    id int AUTO_INCREMENT PRIMARY KEY,
    category_id INT NOT NULL,
    name VARCHAR(150),
    description VARCHAR(4096),
    price DECIMAL(10,2),
    image VARCHAR(100),
    stock INT DEFAULT 0,
    is_active BOOLEAN DEFAULT TRUE,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

CONSTRAINT fk_product_category
FOREIGN KEY (category_id)
REFERENCES categories(id)
ON DELETE CASCADE

);

DROP TABLE IF EXISTS orders;
CREATE TABLE orders(
    id int AUTO_INCREMENT PRIMARY KEY,
    customer_name VARCHAR(100),
    phone VARCHAR(150),
    email VARCHAR(150) NOT NULL,
    delivery_area VARCHAR(150),
    notes VARCHAR(100) DEFAULT NULL,
    total_amount DECIMAL(10,2),
    status VARCHAR(150) DEFAULT 'pending',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP


);
DROP TABLE IF EXISTS order_items;
CREATE TABLE order_items(
    id int AUTO_INCREMENT PRIMARY KEY,
    order_id INT NOT NULL,
    product_id INT NOT NULL,
    product_name VARCHAR(4096),
    unit_price DECIMAL(10,2) NOT NULL,
    quantity INT NOT NULL DEFAULT 1,
    line_total DECIMAL(10,2) NOT NULL

CONSTRAINT fk_item_order
FOREIGN KEY (order_id)
REFERENCES orders(id)
ON DELETE CASCADE,

CONSTRAINT fk_item_product
FOREIGN KEY (product_id)
REFERENCES products(id)
ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS users (
  id            INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  name          VARCHAR(100)  NOT NULL,
  email         VARCHAR(190)  NOT NULL UNIQUE,
  password_hash VARCHAR(255)  NOT NULL,
  phone         VARCHAR(30)   NOT NULL DEFAULT '',
  address       VARCHAR(255)  NOT NULL DEFAULT '',
  city          VARCHAR(100)  NOT NULL DEFAULT '',
  postal_code   VARCHAR(20)   NOT NULL DEFAULT '',
  country       VARCHAR(100)  NOT NULL DEFAULT '',
  created_at    TIMESTAMP     NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB;
 