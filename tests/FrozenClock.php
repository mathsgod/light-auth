<?php
declare(strict_types=1);
namespace Light\Auth\Tests;
use Psr\Clock\ClockInterface;
final class FrozenClock implements ClockInterface
{
    public int $timestamp = 1735689600;
    public function now(): \DateTimeImmutable { return new \DateTimeImmutable('@' . $this->timestamp); }
}
