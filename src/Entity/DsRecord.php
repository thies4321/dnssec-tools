<?php

declare(strict_types=1);

namespace DnsSecTools\Entity;

final readonly class DsRecord
{
    public function __construct(
        public int $keyTag,
        public int $algorithm,
        public int $digestType,
        public string $digest,
    ) {
    }
}
