"""Various exception classes."""


class BlockChainError(Exception):
    """Base exception for all custom exceptions."""

    pass


class BlockNotFoundError(BlockChainError):
    """Block cannot be found."""

    pass


class BlockValidationError(BlockChainError):
    """Block validation failed."""

    pass


class BlockDifficultyError(BlockChainError):
    """Block hash does not meet required difficulty."""

    pass


class TransactionNotFoundError(BlockChainError):
    """Transaction cannot be found."""

    pass


class TransactionDuplicateInputError(BlockChainError):
    """Duplicate transaction inputs."""

    pass


class TransactionValidationError(BlockChainError):
    """Transaction validation failed."""

    pass


class IndexIntegrityError(BlockChainError):
    """There is a problem with the index."""

    pass


class DBIntegrityError(BlockChainError):
    """There is a problem with the database."""

    pass
