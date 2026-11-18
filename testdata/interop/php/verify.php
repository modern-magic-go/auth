<?php

declare(strict_types=1);

require __DIR__ . '/vendor/autoload.php';

use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Signer\Hmac\Sha256;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Validation\Constraint\IssuedBy;
use Lcobucci\JWT\Validation\Constraint\PermittedFor;

$tokenString = $argv[1] ?? '';
$secret = $argv[2] ?? '';
if ($tokenString === '' || $secret === '') {
    fwrite(STDERR, "usage: php verify.php <jwt> <secret>\n");
    exit(2);
}

$config = Configuration::forSymmetricSigner(new Sha256(), InMemory::plainText($secret));
$token = $config->parser()->parse($tokenString);

$constraints = $config->validationConstraints();
$constraints[] = new IssuedBy('auth-service');
$constraints[] = new PermittedFor('admin-api');
$config->validator()->assert($token, ...$constraints);

echo "verified\n";
