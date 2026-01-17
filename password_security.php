<?php
/**
 * Kompleksowy system walidacji i bezpieczeństwa haseł
 * Implementuje wymuszenie silnych haseł w całym systemie
 */

class PasswordSecurity {
    
    // Minimalne wymagania dla haseł
    const MIN_LENGTH = 8;
    const MAX_LENGTH = 128;
    const REQUIRE_UPPERCASE = true;
    const REQUIRE_LOWERCASE = true;
    const REQUIRE_NUMBERS = true;
    const REQUIRE_SPECIAL_CHARS = true;
    
    // Lista popularnych słabych haseł (można rozszerzyć)
    private static $commonPasswords = [
        'password', '123456', '123456789', 'qwerty', 'abc123', 
        'password123', 'admin', 'user', '12345678', 'welcome',
        'login', 'haslo', 'administrator', 'root', 'test'
    ];
    
    /**
     * Waliduje siłę hasła zgodnie z wymaganiami bezpieczeństwa
     * @param string $password Hasło do sprawdzenia
     * @return array ['valid' => bool, 'errors' => array, 'score' => int]
     */
    public static function validatePassword($password) {
        $errors = [];
        $score = 0;
        
        // Sprawdzenie długości
        if (strlen($password) < self::MIN_LENGTH) {
            $errors[] = "Hasło musi mieć co najmniej " . self::MIN_LENGTH . " znaków";
        } elseif (strlen($password) >= self::MIN_LENGTH) {
            $score += 10;
        }
        
        if (strlen($password) > self::MAX_LENGTH) {
            $errors[] = "Hasło nie może mieć więcej niż " . self::MAX_LENGTH . " znaków";
        }
        
        // Sprawdzenie wielkich liter
        if (self::REQUIRE_UPPERCASE && !preg_match('/[A-Z]/', $password)) {
            $errors[] = "Hasło musi zawierać co najmniej jedną wielką literę";
        } elseif (preg_match('/[A-Z]/', $password)) {
            $score += 10;
        }
        
        // Sprawdzenie małych liter
        if (self::REQUIRE_LOWERCASE && !preg_match('/[a-z]/', $password)) {
            $errors[] = "Hasło musi zawierać co najmniej jedną małą literę";
        } elseif (preg_match('/[a-z]/', $password)) {
            $score += 10;
        }
        
        // Sprawdzenie cyfr
        if (self::REQUIRE_NUMBERS && !preg_match('/[0-9]/', $password)) {
            $errors[] = "Hasło musi zawierać co najmniej jedną cyfrę";
        } elseif (preg_match('/[0-9]/', $password)) {
            $score += 10;
        }
        
        // Sprawdzenie znaków specjalnych
        if (self::REQUIRE_SPECIAL_CHARS && !preg_match('/[^a-zA-Z0-9]/', $password)) {
            $errors[] = "Hasło musi zawierać co najmniej jeden znak specjalny (!@#$%^&*()_+-=[]{}|;:,.<>?)";
        } elseif (preg_match('/[^a-zA-Z0-9]/', $password)) {
            $score += 15;
        }
        
        // Sprawdzenie czy nie jest popularnym hasłem
        if (in_array(strtolower($password), self::$commonPasswords)) {
            $errors[] = "To hasło jest zbyt popularne i łatwe do odgadnięcia";
        }
        
        // Sprawdzenie powtarzających się znaków
        if (preg_match('/(.)\1{2,}/', $password)) {
            $errors[] = "Hasło nie może zawierać więcej niż 2 identycznych znaków pod rząd";
        } else {
            $score += 5;
        }
        
        // Sprawdzenie sekwencji
        if (self::containsSequence($password)) {
            $errors[] = "Hasło nie może zawierać prostych sekwencji (123, abc, qwerty)";
        } else {
            $score += 5;
        }
        
        // Dodatkowe punkty za długość
        if (strlen($password) >= 12) {
            $score += 10;
        }
        if (strlen($password) >= 16) {
            $score += 10;
        }
        
        // Sprawdzenie różnorodności znaków
        $uniqueChars = count(array_unique(str_split($password)));
        if ($uniqueChars >= strlen($password) * 0.6) {
            $score += 10;
        }
        
        return [
            'valid' => empty($errors),
            'errors' => $errors,
            'score' => min($score, 100), // Maksymalny wynik 100
            'strength' => self::getStrengthLevel($score)
        ];
    }
    
    /**
     * Sprawdza czy hasło zawiera popularne sekwencje
     */
    private static function containsSequence($password) {
        $sequences = [
            '123', '234', '345', '456', '567', '678', '789',
            'abc', 'bcd', 'cde', 'def', 'efg', 'fgh', 'ghi',
            'qwe', 'wer', 'ert', 'rty', 'tyu', 'yui', 'uio',
            'asd', 'sdf', 'dfg', 'fgh', 'ghj', 'hjk', 'jkl'
        ];
        
        $lowerPassword = strtolower($password);
        foreach ($sequences as $seq) {
            if (strpos($lowerPassword, $seq) !== false) {
                return true;
            }
        }
        
        return false;
    }
    
    /**
     * Określa poziom siły hasła na podstawie wyniku
     */
    private static function getStrengthLevel($score) {
        if ($score >= 80) return 'bardzo-silne';
        if ($score >= 60) return 'silne';
        if ($score >= 40) return 'srednie';
        if ($score >= 20) return 'slabe';
        return 'bardzo-slabe';
    }
    
    /**
     * Bezpieczne hashowanie hasła
     */
    public static function hashPassword($password) {
        return password_hash($password, PASSWORD_ARGON2ID, [
            'memory_cost' => 65536, // 64 MB
            'time_cost' => 4,       // 4 iteracje
            'threads' => 3          // 3 wątki
        ]);
    }
    
    /**
     * Weryfikacja hasła
     */
    public static function verifyPassword($password, $hash) {
        return password_verify($password, $hash);
    }
    
    /**
     * Sprawdza czy hash hasła wymaga ponownego zahashowania
     */
    public static function needsRehash($hash) {
        return password_needs_rehash($hash, PASSWORD_ARGON2ID, [
            'memory_cost' => 65536,
            'time_cost' => 4,
            'threads' => 3
        ]);
    }
    
    /**
     * Generuje bezpieczne hasło
     */
    public static function generateSecurePassword($length = 12) {
        $chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+-=[]{}|;:,.<>?';
        $password = '';
        
        // Zagwarantuj że hasło spełnia wszystkie wymagania
        $password .= chr(rand(65, 90));  // Wielka litera
        $password .= chr(rand(97, 122)); // Mała litera
        $password .= chr(rand(48, 57));  // Cyfra
        $password .= $chars[rand(62, strlen($chars) - 1)]; // Znak specjalny
        
        // Dodaj resztę znaków
        for ($i = 4; $i < $length; $i++) {
            $password .= $chars[random_int(0, strlen($chars) - 1)];
        }
        
        // Przemieszaj znaki
        return str_shuffle($password);
    }
    
    /**
     * Zwraca JavaScript do walidacji hasła po stronie klienta
     */
    public static function getClientSideValidationJS() {
        return "
        function validatePasswordStrength(password) {
            const errors = [];
            let score = 0;
            
            // Długość
            if (password.length < 8) {
                errors.push('Hasło musi mieć co najmniej 8 znaków');
            } else {
                score += 10;
            }
            
            // Wielkie litery
            if (!/[A-Z]/.test(password)) {
                errors.push('Hasło musi zawierać wielką literę');
            } else {
                score += 10;
            }
            
            // Małe litery
            if (!/[a-z]/.test(password)) {
                errors.push('Hasło musi zawierać małą literę');
            } else {
                score += 10;
            }
            
            // Cyfry
            if (!/[0-9]/.test(password)) {
                errors.push('Hasło musi zawierać cyfrę');
            } else {
                score += 10;
            }
            
            // Znaki specjalne
            if (!/[^a-zA-Z0-9]/.test(password)) {
                errors.push('Hasło musi zawierać znak specjalny');
            } else {
                score += 15;
            }
            
            // Popularne hasła
            const common = ['password', '123456', '123456789', 'qwerty', 'abc123'];
            if (common.includes(password.toLowerCase())) {
                errors.push('To hasło jest zbyt popularne');
            }
            
            // Dodatkowe punkty
            if (password.length >= 12) score += 10;
            if (password.length >= 16) score += 10;
            
            let strength = 'bardzo-slabe';
            if (score >= 80) strength = 'bardzo-silne';
            else if (score >= 60) strength = 'silne';
            else if (score >= 40) strength = 'srednie';
            else if (score >= 20) strength = 'slabe';
            
            return {
                valid: errors.length === 0,
                errors: errors,
                score: Math.min(score, 100),
                strength: strength
            };
        }
        
        function updatePasswordIndicator(password, indicatorId) {
            const result = validatePasswordStrength(password);
            const indicator = document.getElementById(indicatorId);
            
            if (!indicator) return result;
            
            indicator.className = 'password-strength ' + result.strength;
            
            if (result.errors.length > 0) {
                indicator.innerHTML = '<ul><li>' + result.errors.join('</li><li>') + '</li></ul>';
            } else {
                const strengthText = {
                    'bardzo-slabe': 'Bardzo słabe',
                    'slabe': 'Słabe',
                    'srednie': 'Średnie',
                    'silne': 'Silne',
                    'bardzo-silne': 'Bardzo silne'
                };
                indicator.innerHTML = 'Siła hasła: ' + strengthText[result.strength] + ' (' + result.score + '/100)';
            }
            
            return result;
        }
        ";
    }
    
    /**
     * Zwraca CSS dla wskaźnika siły hasła
     */
    public static function getPasswordStrengthCSS() {
        return "
        .password-strength {
            padding: 10px;
            margin: 5px 0;
            border-radius: 4px;
            font-size: 14px;
        }
        
        .password-strength.bardzo-slabe {
            background-color: #ffebee;
            color: #c62828;
            border: 1px solid #ef5350;
        }
        
        .password-strength.slabe {
            background-color: #fff3e0;
            color: #ef6c00;
            border: 1px solid #ff9800;
        }
        
        .password-strength.srednie {
            background-color: #fff8e1;
            color: #f57f17;
            border: 1px solid #ffcc02;
        }
        
        .password-strength.silne {
            background-color: #f3e5f5;
            color: #7b1fa2;
            border: 1px solid #9c27b0;
        }
        
        .password-strength.bardzo-silne {
            background-color: #e8f5e8;
            color: #2e7d32;
            border: 1px solid #4caf50;
        }
        
        .password-strength ul {
            margin: 0;
            padding-left: 20px;
        }
        
        .password-strength li {
            margin: 2px 0;
        }
        ";
    }
}
?>