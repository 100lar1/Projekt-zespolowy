CREATE DATABASE IF NOT EXISTS wybory CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE wybory;

CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    imie VARCHAR(100) NOT NULL,
    nazwisko VARCHAR(100) NOT NULL,
    email VARCHAR(255) NOT NULL UNIQUE,
    haslo VARCHAR(255) NOT NULL,
    rola ENUM('uzytkownik', 'admin') DEFAULT 'uzytkownik'
);

CREATE TABLE okregi (
    id INT AUTO_INCREMENT PRIMARY KEY,
    nazwa VARCHAR(100) NOT NULL,
    opis TEXT
);

CREATE TABLE kandydaci (
    id INT AUTO_INCREMENT PRIMARY KEY,
    imie VARCHAR(100) NOT NULL,
    nazwisko VARCHAR(100) NOT NULL,
    partia VARCHAR(100),
    okreg_id INT,
    FOREIGN KEY (okreg_id) REFERENCES okregi(id) ON DELETE SET NULL
);

CREATE TABLE glosy (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT,
    kandydat_id INT,
    czas TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (kandydat_id) REFERENCES kandydaci(id) ON DELETE CASCADE,
    UNIQUE(user_id)
);
