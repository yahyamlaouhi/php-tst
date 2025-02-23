<?php

require 'vendor/autoload.php';

use FastRoute\RouteCollector;
use Illuminate\Validation\Factory as ValidatorFactory;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use Ramsey\Uuid\Uuid;
use Dotenv\Dotenv;
use Symfony\Component\Cache\Adapter\FilesystemAdapter;
use Psr\Http\Message\ServerRequestInterface;
use Laminas\Diactoros\Response\JsonResponse;
use Laminas\Diactoros\ServerRequestFactory;
use Laminas\Diactoros\Response;

$dotenv = Dotenv::createImmutable(__DIR__);
$dotenv->load();

$cache = new FilesystemAdapter();
$validator = new ValidatorFactory(new Illuminate\Translation\Translator(new Illuminate\Translation\ArrayLoader(), 'en'));

$dispatcher = FastRoute\simpleDispatcher(function (RouteCollector $r) {
    $r->addRoute('GET', '/api/uuid', 'generateUuid');
    $r->addRoute('POST', '/api/login', 'login');
    $r->addRoute('GET', '/api/protected', 'protectedEndpoint');
});

$request = ServerRequestFactory::fromGlobals();
$httpMethod = $request->getMethod();
$uri = $request->getUri()->getPath();

$routeInfo = $dispatcher->dispatch($httpMethod, $uri);
switch ($routeInfo[0]) {
    case FastRoute\Dispatcher::NOT_FOUND:
        echo json_encode(['error' => 'Not Found']);
        http_response_code(404);
        break;
    case FastRoute\Dispatcher::METHOD_NOT_ALLOWED:
        echo json_encode(['error' => 'Method Not Allowed']);
        http_response_code(405);
        break;
    case FastRoute\Dispatcher::FOUND:
        $handler = $routeInfo[1];
        $vars = $routeInfo[2];
        echo json_encode($handler($request, $vars));
        break;
}

function generateUuid()
{
    global $cache;
    $cachedUuid = $cache->getItem('uuid');
    if (!$cachedUuid->isHit()) {
        $uuid = Uuid::uuid4()->toString();
        $cachedUuid->set($uuid)->expiresAfter(60);
        $cache->save($cachedUuid);
    }
    return new JsonResponse(['uuid' => $cachedUuid->get()]);
}

function login(ServerRequestInterface $request)
{
    global $validator;
    $body = json_decode($request->getBody()->getContents(), true);
    $validation = $validator->make($body, [
        'username' => 'required|string',
        'password' => 'required|string',
    ]);
    if ($validation->fails()) {
        return new JsonResponse(['error' => 'Invalid input'], 400);
    }
    if ($body['username'] !== 'admin' || $body['password'] !== 'secret') {
        return new JsonResponse(['error' => 'Unauthorized'], 401);
    }
    $payload = [
        'username' => $body['username'],
        'iat' => time(),
    ];
    $jwt = JWT::encode($payload, $_ENV['JWT_SECRET'], 'HS256');
    return new JsonResponse(['token' => $jwt]);
}

function protectedEndpoint(ServerRequestInterface $request)
{
    $authHeader = $request->getHeaderLine('Authorization');
    if (!preg_match('/Bearer\s+(\S+)/', $authHeader, $matches)) {
        return new JsonResponse(['error' => 'Unauthorized'], 401);
    }
    $token = $matches[1];
    try {
        $decoded = JWT::decode($token, new Key($_ENV['JWT_SECRET'], 'HS256'));
        return new JsonResponse(['message' => 'Welcome, ' . $decoded->username]);
    } catch (Exception $e) {
        return new JsonResponse(['error' => 'Invalid token'], 401);
    }
}
