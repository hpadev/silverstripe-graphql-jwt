<?php declare(strict_types=1);

namespace Firesphere\GraphQLJWT\Resolver\Mutation;

use BadMethodCallException;
use Exception;
use Firesphere\GraphQLJWT\Helpers\TokenStatusEnum;
use Firesphere\GraphQLJWT\Helpers\HeaderExtractor;
use Firesphere\GraphQLJWT\Helpers\MemberTokenGenerator;
use Firesphere\GraphQLJWT\Helpers\RequiresAuthenticator;
use Firesphere\GraphQLJWT\Model\JWTRecord;
use Firesphere\GraphQLJWT\Authentication\JWTAuthenticator;
use GraphQL\Type\Definition\ResolveInfo;
use GraphQL\Type\Definition\Type;
use OutOfBoundsException;
use Psr\Container\NotFoundExceptionInterface;
use SilverStripe\Control\Controller;
use SilverStripe\Core\Extensible;
use SilverStripe\GraphQL\MutationCreator;
use SilverStripe\GraphQL\OperationResolver;
use SilverStripe\ORM\ValidationException;

class RefreshToken
{
    use RequiresAuthenticator;
    use HeaderExtractor;
    use MemberTokenGenerator;
    use Extensible;

    /**
     * @param mixed $object
     * @param array $args
     * @param mixed $context
     * @param ResolveInfo $info
     * @return array
     * @throws NotFoundExceptionInterface
     * @throws ValidationException
     * @throws BadMethodCallException
     * @throws OutOfBoundsException
     * @throws Exception
     */
    public static function resolve($object, array $args, $context, ResolveInfo $info): array
    {
        $refreshToken = new self();
        $refreshToken->setJWTAuthenticator(new JWTAuthenticator());
        $authenticator = $refreshToken->getJWTAuthenticator();
        $request = Controller::curr()->getRequest();
        $token = $refreshToken->getAuthorizationHeader($request);

        // Check status of existing token
        /** @var JWTRecord $record */
        list($record, $status) = $authenticator->validateToken($token, $request);
        $member = null;
        switch ($status) {
            case TokenStatusEnum::STATUS_OK:
            case TokenStatusEnum::STATUS_EXPIRED:
                $member = $record->Member();
                $renewable = true;
                break;
            case TokenStatusEnum::STATUS_DEAD:
            case TokenStatusEnum::STATUS_INVALID:
            default:
                $member = null;
                $renewable = false;
                break;
        }

        // Check if renewable
        if (!$renewable) {
            return $refreshToken->generateResponse($status);
        }

        // Create new token for member
        $newToken = $authenticator->generateToken($request, $member);
        return $refreshToken->generateResponse(TokenStatusEnum::STATUS_OK, $member, $newToken->__toString());
    }
}
