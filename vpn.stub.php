<?php

/**
 * @generate-class-entries
 * @generate-legacy-arginfo 80000
 */

namespace {
    /**
     * A WireGuard profile (or a pool of profiles) that selected HTTP(S)
     * requests are sent through. Nothing else in PHP uses the tunnel.
     *
     * @strict-properties
     */
    final class VPN
    {
        /** @cvalue PHP_VPN_VERSION */
        public const string VERSION = UNKNOWN;

        private function __construct() {}

        /** Loads a wg-quick style `.conf` profile from a file. */
        public static function wireguard(string $path, array $options = []): VPN {}

        /** Loads a profile from a string (for example from a secret store). */
        public static function wireguardFromString(#[\SensitiveParameter] string $config, array $options = []): VPN {}

        /**
         * Several profiles (each with its own key pair) used in rotation, so
         * several PHP processes can send requests at the same time.
         *
         * @param array<int, VPN|string> $profiles
         */
        public static function pool(array $profiles, array $options = []): VPN {}

        public function request(string $method, string $url, array $options = []): VPN\Response {}

        /** Non-secret details of each profile (endpoint, addresses, session age). */
        public function info(): array {}

        /** Closes this process's tunnel(s) for the profile. */
        public function close(): void {}
    }
}

namespace VPN {
    /** @strict-properties */
    final class Response
    {
        private function __construct() {}

        public function status(): int {}

        /** @return array<string, list<string>> lower-case names */
        public function headers(): array {}

        /** All values of the header joined with ", ", or null. */
        public function header(string $name): ?string {}

        public function body(): string {}

        public function effectiveUrl(): string {}

        public function redirectCount(): int {}

        /** IP address the response came from (inside the tunnel). */
        public function remoteAddress(): string {}
    }

    class Exception extends \RuntimeException {}

    class ConfigException extends Exception {}

    class TunnelException extends Exception {}

    class DnsException extends Exception {}

    class ConnectException extends Exception {}

    class TlsException extends Exception {}

    class TimeoutException extends Exception {}

    class ProtocolException extends Exception {}

    class PolicyException extends Exception {}

    class LimitException extends Exception {}

    class LockTimeoutException extends Exception {}
}
