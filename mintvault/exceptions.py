"""
Исключения и ошибки MintVault.
Все сообщения ориентированы на понятность для пользователя Linux Mint и не раскрывают секретные данные.
"""


class MintVaultError(Exception):
    """Базовое исключение для всех ошибок приложения MintVault."""
    pass


class AuthenticationError(MintVaultError):
    """Неверный пароль, неверный ключ восстановления или ошибка проверки подлинности."""
    pass


class IntegrityError(MintVaultError):
    """Нарушение целостности зашифрованных данных, заголовка или индекса хранилища."""
    pass


class VaultFormatError(MintVaultError):
    """Неподдерживаемый или повреждённый формат файла хранилища."""
    pass


class VaultLockedError(MintVaultError):
    """Попытка выполнить операцию над заблокированным хранилищем."""
    pass


class VaultBusyError(MintVaultError):
    """Хранилище уже занято другой операцией или открыто в другом процессе."""
    pass


class UnsafeFileObjectError(MintVaultError):
    """Отказ в обработке потенциально опасного файлового объекта (символическая ссылка, сокет, FIFO, устройство)."""
    pass


class PathTraversalError(MintVaultError):
    """Обнаружена попытка обхода каталогов (Path Traversal) при импорте или извлечении."""
    pass


class FileOverwriteError(MintVaultError):
    """Целевой файл или каталог уже существует (защита от перезаписи при извлечении)."""
    pass


class InsufficientDiskSpaceError(MintVaultError):
    """Недостаточно свободного места на диске для безопасного выполнения операции."""
    pass


class OperationCancelledError(MintVaultError):
    """Операция была безопасно отменена пользователем."""
    pass
