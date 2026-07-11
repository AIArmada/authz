<?php

declare(strict_types=1);

namespace AIArmada\Authz\Support;

final class BackUrlSanitizer
{
    /**
     * Sanitize a back URL to prevent open redirect attacks.
     *
     * Accepts:
     * - Relative paths starting with / (e.g. /admin/dashboard)
     *
     * Rejects:
     * - Protocol-relative URLs (//evil.com)
     * - Non-http/https schemes (javascript:, data:)
     * - Different hosts
     * - Different effective ports (including implied defaults)
     */
    public static function sanitize(?string $url): string
    {
        if (! is_string($url) || $url === '') {
            return '/';
        }

        if (str_starts_with($url, '//')) {
            return '/';
        }

        if (str_starts_with($url, '/')) {
            return $url;
        }

        $parsed = parse_url($url);

        if (! is_array($parsed) || ! isset($parsed['host'])) {
            return '/';
        }

        $scheme = isset($parsed['scheme']) ? mb_strtolower($parsed['scheme']) : '';

        if ($scheme !== 'http' && $scheme !== 'https') {
            return '/';
        }

        $requestHost = request()->getHost();
        $urlHost = mb_strtolower($parsed['host']);

        if ($urlHost !== mb_strtolower($requestHost)) {
            return '/';
        }

        $urlPort = isset($parsed['port']) ? (int) $parsed['port'] : null;
        $requestPort = request()->getPort();

        if ($urlPort !== null && $urlPort !== $requestPort) {
            return '/';
        }

        return $url;
    }
}
