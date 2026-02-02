<?php
declare(strict_types=1);

require __DIR__ . '/src/AgentApp.php';

$app = new AgentApp(__DIR__ . '/.env');
$app->handle();
