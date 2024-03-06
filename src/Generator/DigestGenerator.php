<?php

declare(strict_types=1);

namespace DnsSecTools\Generator;

use DnsSecTools\Entity\DsRecord;

use function array_map;
use function base64_decode;
use function chr;
use function explode;
use function hash;
use function pack;
use function sha1;
use function str_ends_with;
use function str_replace;
use function strlen;
use function strtolower;
use function unpack;

final readonly class DigestGenerator
{
    public function generate(string $domain, string $dnsKey): array
    {
        $dnsKeyList = explode(' ', $dnsKey, 4);
        list($flags, $protocol, $algorithm, $publicKey) = $dnsKeyList;
        $publicKey = str_replace(' ', '', $publicKey);

        $keyTag = $this->calculateKeyTag((int) $flags, (int) $protocol, (int) $algorithm, $publicKey);
        $digests = $this->calculateDs($domain, (int) $flags, (int) $protocol, (int) $algorithm, $publicKey);

        return array_map(function (array $digest) use ($keyTag, $algorithm) {
            return new DsRecord($keyTag, (int) $algorithm, $digest['algorithm'], $digest['ds']);
        }, $digests);
    }

    private function calculateKeyTag(int $flags, int $protocol, int $algorithm, string $publicKey): int
    {
        $bin = pack('nCC', $flags, $protocol, $algorithm);
        $bin = $bin . base64_decode($publicKey);

        $cnt = 0;
        for ($i = 0; $i < strlen($bin); $i++) {
            $s = unpack('C', $bin[$i])[1];

            if (($i % 2) === 0) {
                $cnt += $s << 8;
            } else {
                $cnt += $s;
            }
        }

        return (($cnt & 0xFFFF) + ($cnt >> 16)) & 0xFFFF;
    }

    private function calculateDs(string $domain, int $flags, int $protocol, int $algorithm, string $publicKey): array
    {
        if (! str_ends_with($domain, '.')) {
            $domain = $domain . '.';
        }

        $signature = '';
        $parts = explode('.', $domain);

        foreach ($parts as $part) {
            $signature .= chr(strlen($part)) . $part;
        }

        $signature .= pack('nCC', $flags, $protocol, $algorithm);
        $signature .= base64_decode($publicKey);

        return [
            [
                'algorithm' => 1,
                'ds' => strtolower(sha1($signature))
            ],
            [
                'algorithm' => 2,
                'ds' => strtolower(hash('sha256', $signature))
            ],
            [
                'algorithm' => 4,
                'ds' => strtolower(hash('sha384', $signature))
            ]
        ];
    }
}
