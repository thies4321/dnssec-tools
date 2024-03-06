<?php

declare(strict_types=1);

namespace DnsSecTools\Entity;

final readonly class DnsKey
{
    public function __construct(
        public int $flags,
        public int $protocol,
        public int $algorithm,
        public string $publicKey,
    ) {
    }
}
