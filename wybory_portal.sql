-- phpMyAdmin SQL Dump
-- version 5.2.1
-- https://www.phpmyadmin.net/
--
-- Host: 127.0.0.1
-- Generation Time: Maj 17, 2025 at 09:27 AM
-- Wersja serwera: 10.4.32-MariaDB
-- Wersja PHP: 8.2.12

SET SQL_MODE = "NO_AUTO_VALUE_ON_ZERO";
START TRANSACTION;
SET time_zone = "+00:00";

/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8mb4 */;

--
-- Database: `wybory_portal`
--

-- --------------------------------------------------------

--
-- Struktura tabeli dla tabeli `candidates`
--

CREATE TABLE `candidates` (
  `id` int(11) NOT NULL,
  `election_id` int(11) DEFAULT NULL,
  `name` varchar(100) DEFAULT NULL,
  `description` text DEFAULT NULL,
  `votes` int(11) DEFAULT 0
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `candidates`
--

INSERT INTO `candidates` (`id`, `election_id`, `name`, `description`, `votes`) VALUES
(5, 2, 'Katarzyna Nowak', NULL, 2),
(6, 2, 'Michał Kowalski', NULL, 1),
(7, 2, 'Anna Zielińska', NULL, 1),
(8, 2, 'Paweł Maj', NULL, 1),
(9, 1, 'Adam Nowak', 'student', 0);

-- --------------------------------------------------------

--
-- Struktura tabeli dla tabeli `elections`
--

CREATE TABLE `elections` (
  `id` int(11) NOT NULL,
  `name` varchar(255) DEFAULT NULL,
  `start_time` datetime DEFAULT NULL,
  `end_time` datetime DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `elections`
--

INSERT INTO `elections` (`id`, `name`, `start_time`, `end_time`) VALUES
(1, 'Wybory do Samorządu Studenckiego', '2025-05-05 08:00:00', '2025-05-15 20:00:00'),
(2, 'Wybory do Samorządu Studenckiego', '2025-05-05 08:00:00', '2025-05-15 20:00:00'),
(3, 'Wybory do samorzadu', '2025-05-07 19:44:00', '2025-05-07 19:44:00');

-- --------------------------------------------------------

--
-- Struktura tabeli dla tabeli `users`
--

CREATE TABLE `users` (
  `id` int(11) NOT NULL,
  `name` varchar(100) DEFAULT NULL,
  `surname` varchar(100) DEFAULT NULL,
  `pesel` char(11) DEFAULT NULL,
  `email` varchar(100) DEFAULT NULL,
  `password_hash` varchar(255) DEFAULT NULL,
  `is_admin` tinyint(1) DEFAULT 0,
  `admin_username` varchar(50) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `users`
--

INSERT INTO `users` (`id`, `name`, `surname`, `pesel`, `email`, `password_hash`, `is_admin`, `admin_username`) VALUES
(1, 'Adam ', 'Nowak', '56080565738', 'adam.nowak2@poczta.pl', '$2y$10$y5QyKnsfHKRq4jZCXTZDWeCBEXKB7HVOeiXOrciWwt6VzlHSzwE/O', 0, NULL),
(2, 'admin', 'admin', '12345678901', 'admin@poczta.pl', '$2y$10$FZ9ilzUqq4NzkdnedL3v1.85CeRYb2JgOWyILdJ1Pagr6MqDTxoNm', 1, 'admin'),
(3, 'Adam ', 'Nowak', '76022517516', 'adam.nowak2@poczta.pl', '$2y$10$AZO3FHii.trpIlMvw/FzXOI2RW7TXnXqbEbegWNjl5RBbQ140GXny', 0, NULL),
(4, 'Adam ', 'Nowak', '76022517512', 'adam.nowak2@poczta.pl', '$2y$10$LeDKAAYtQ54D0DYwAsghEeiwSUzd9isMtu.bK9oHCQhiOzHMpIBmG', 0, NULL),
(5, 'Adam ', 'Nowak', '78021642297', 'adam.nowak2@poczta.pl', '$2y$10$2OFyIjRfMsInJ8BcAoab.uaaBI5890gAnQ3.OEkg/zD0iOlD5L/mu', 0, NULL),
(6, 'Adam ', 'Nowak', '88122727218', 'adam.nowak2@poczta.pl', '$2y$10$aVXw1MXGC/jb1uoZ7V94KuBbkjCpD46Bo9f22sZo.w9g8BlOVnYJi', 0, NULL),
(7, 'Adam ', 'Nowak', '89030744171', 'adam.nowak2@poczta.pl', '$2y$10$..tAoyRsaM6SRmG7iCTuzOH/irhjWJrauiubZ.GpKL9qF17LrlS4O', 0, NULL),
(8, 'Adam ', 'Nowak', '50102681898', 'adam.nowak2@poczta.pl', '$2y$10$CM8GSTZW39vFJA/a/Us/O.u4dhUp2.M6bQAsK.fGpzthozpdECrwa', 0, NULL);

-- --------------------------------------------------------

--
-- Struktura tabeli dla tabeli `vote_tokens`
--

CREATE TABLE `vote_tokens` (
  `id` int(11) NOT NULL,
  `user_id` int(11) DEFAULT NULL,
  `election_id` int(11) DEFAULT NULL,
  `token` varchar(255) DEFAULT NULL,
  `used` tinyint(1) DEFAULT 0,
  `expires_at` datetime DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `vote_tokens`
--

INSERT INTO `vote_tokens` (`id`, `user_id`, `election_id`, `token`, `used`, `expires_at`) VALUES
(1, 1, 1, '49b40d1a780dce1d0711c20d6aed43e7', 0, '2025-05-06 15:02:02'),
(2, 1, 2, '1aa8fcccaa9854e86ae5853094964ea3', 1, '2025-05-06 15:03:57'),
(3, 5, 2, 'f231ea0baac949da41cbedb37fb0d7b2', 1, '2025-05-06 20:22:38'),
(4, 6, 2, 'cdce1f79022e1c85622345472c7dd310', 1, '2025-05-06 20:31:01'),
(5, 7, 2, 'b06eb3d849686c5d556e167523be48ef', 1, '2025-05-06 20:32:06'),
(6, 8, 2, 'c185c022c8f311485e6e6678108c5604', 1, '2025-05-06 20:35:01');

--
-- Indeksy dla zrzutów tabel
--

--
-- Indeksy dla tabeli `candidates`
--
ALTER TABLE `candidates`
  ADD PRIMARY KEY (`id`),
  ADD KEY `election_id` (`election_id`);

--
-- Indeksy dla tabeli `elections`
--
ALTER TABLE `elections`
  ADD PRIMARY KEY (`id`);

--
-- Indeksy dla tabeli `users`
--
ALTER TABLE `users`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `pesel` (`pesel`),
  ADD UNIQUE KEY `admin_username` (`admin_username`);

--
-- Indeksy dla tabeli `vote_tokens`
--
ALTER TABLE `vote_tokens`
  ADD PRIMARY KEY (`id`),
  ADD KEY `user_id` (`user_id`),
  ADD KEY `election_id` (`election_id`);

--
-- AUTO_INCREMENT for dumped tables
--

--
-- AUTO_INCREMENT for table `candidates`
--
ALTER TABLE `candidates`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=10;

--
-- AUTO_INCREMENT for table `elections`
--
ALTER TABLE `elections`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=4;

--
-- AUTO_INCREMENT for table `users`
--
ALTER TABLE `users`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=9;

--
-- AUTO_INCREMENT for table `vote_tokens`
--
ALTER TABLE `vote_tokens`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=7;

--
-- Constraints for dumped tables
--

--
-- Constraints for table `candidates`
--
ALTER TABLE `candidates`
  ADD CONSTRAINT `candidates_ibfk_1` FOREIGN KEY (`election_id`) REFERENCES `elections` (`id`) ON DELETE CASCADE;

--
-- Constraints for table `vote_tokens`
--
ALTER TABLE `vote_tokens`
  ADD CONSTRAINT `vote_tokens_ibfk_1` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`),
  ADD CONSTRAINT `vote_tokens_ibfk_2` FOREIGN KEY (`election_id`) REFERENCES `elections` (`id`);
COMMIT;

/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;