<?php

declare(strict_types=1);

namespace DnsSecTools;

use DnsSecTools\Entity\DnsKey;
use DnsSecTools\Generator\DigestGenerator;

use function sprintf;

class DnsSec
{
    public static function generateDigestFromDnsKey(string $domain, DnsKey $dnsKey): array
    {
        return (new DigestGenerator())->generate(
            $domain,
            sprintf(
                '%d %d %d %s',
                $dnsKey->flags,
                $dnsKey->protocol,
                $dnsKey->algorithm,
                $dnsKey->publicKey
            )
        );
    }
}
